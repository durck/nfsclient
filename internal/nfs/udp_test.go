package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func udpPeer(t *testing.T, handler func(*net.UDPConn, *net.UDPAddr, []byte)) (*net.UDPConn, int) {
	t.Helper()
	s, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65536)
		for {
			n, addr, err := s.ReadFromUDP(b)
			if err != nil {
				return
			}
			handler(s, addr, append([]byte(nil), b[:n]...))
		}
	}()
	t.Cleanup(func() { s.Close(); <-done })
	return s, s.LocalAddr().(*net.UDPAddr).Port
}
func udpReply(xid, value uint32) []byte {
	var b encoder
	for _, n := range []uint32{xid, 1, 0, 0, 0, 0, value} {
		b.u32(n)
	}
	return b
}
func udpClient(t *testing.T, port int) *rpcClient {
	t.Helper()
	c, err := dialRPCTransport(context.Background(), "127.0.0.1", port, 150*time.Millisecond, false, "udp")
	if err != nil {
		t.Fatal(err)
	}
	c.udpRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { c.conn.Close() })
	return c
}

func TestUDPRetrySameDatagram(t *testing.T) {
	packets := make(chan []byte, 3)
	var count atomic.Int32
	_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
		packets <- b
		if count.Add(1) == 1 {
			return
		}
		s.WriteToUDP(udpReply(binary.BigEndian.Uint32(b), 42), a)
	})
	c := udpClient(t, port)
	d, err := c.call(context.Background(), nfsProgram, 3, 1, &Auth{UID: 7}, nil)
	if err != nil || d.u32() != 42 {
		t.Fatalf("reply %v %v", d, err)
	}
	if !bytes.Equal(<-packets, <-packets) || count.Load() != 2 {
		t.Fatal("retry changed XID, credentials, arguments or count")
	}
}

func TestUDPRejectsForeignAndLateReplies(t *testing.T) {
	foreign, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	var count uint32
	var old []byte
	_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
		count++
		xid := binary.BigEndian.Uint32(b)
		foreign.WriteToUDP(udpReply(xid, 999), a)
		s.WriteToUDP([]byte{1, 2}, a)
		s.WriteToUDP(udpReply(xid+99, 888), a)
		if old != nil {
			s.WriteToUDP(old, a)
		}
		old = udpReply(xid, count)
		s.WriteToUDP(old, a)
		s.WriteToUDP(old, a)
	})
	c := udpClient(t, port)
	for want := uint32(1); want <= 2; want++ {
		d, err := c.call(context.Background(), nfsProgram, 2, 6, nil, nil)
		if err != nil || d.u32() != want {
			t.Fatalf("wrong reply %v %v", d, err)
		}
	}
}

func TestUDPTimeoutBoundsAndMutation(t *testing.T) {
	for _, proc := range []uint32{1, 2, 7, 8, 9, 12, 21} {
		t.Run(fmt.Sprint(proc), func(t *testing.T) {
			var count atomic.Int32
			_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
				count.Add(1)
				for i := 0; i < 12; i++ {
					s.WriteToUDP(udpReply(binary.BigEndian.Uint32(b)+1, 9), a)
				}
			})
			c := udpClient(t, port)
			start := time.Now()
			_, err := c.call(context.Background(), nfsProgram, 3, proc, nil, nil)
			if err == nil || time.Since(start) > time.Second {
				t.Fatalf("unbounded timeout: %v", err)
			}
			want := int32(1)
			if proc == 1 {
				want = 3
			}
			if count.Load() != want {
				t.Fatalf("sent %d requests, expected %d", count.Load(), want)
			}
			if proc != 1 && !strings.Contains(err.Error(), "outcome unknown") {
				t.Fatal(err)
			}
		})
	}
}

func TestUDPCancelAndReuse(t *testing.T) {
	seen := make(chan struct{}, 1)
	var count int
	_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
		count++
		if count == 1 {
			seen <- struct{}{}
			return
		}
		s.WriteToUDP(udpReply(binary.BigEndian.Uint32(b), 42), a)
	})
	c := udpClient(t, port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.call(ctx, nfsProgram, 3, 1, nil, nil); done <- err }()
	<-seen
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel hung")
	}
	d, err := c.call(context.Background(), nfsProgram, 3, 1, nil, nil)
	if err != nil || d.u32() != 42 {
		t.Fatalf("reuse %v", err)
	}
}

func TestUDPDiscoveryAndAutoVersion(t *testing.T) {
	var bad atomic.Bool
	var port int
	s, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if s == nil {
		t.Fatal("listen")
	}
	port = s.LocalAddr().(*net.UDPAddr).Port
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			n, a, err := s.ReadFromUDP(buf)
			if err != nil {
				return
			}
			d := &decoder{b: buf[:n]}
			xid := d.u32()
			d.u32()
			d.u32()
			prog, vers, proc := d.u32(), d.u32(), d.u32()
			d.u32()
			d.opaque(400)
			d.u32()
			d.opaque(400)
			var reply encoder
			for _, v := range []uint32{xid, 1, 0, 0, 0, 0} {
				reply.u32(v)
			}
			if prog == 100000 {
				if vers != 2 || proc != 3 {
					bad.Store(true)
				}
				p, v, transport, unused := d.u32(), d.u32(), d.u32(), d.u32()
				if transport != 17 || unused != 0 || (p != nfsProgram && p != mountProgram) || (v != 1 && v != 2 && v != 3) {
					bad.Store(true)
				}
				reply.u32(uint32(port))
			} else if prog == nfsProgram && vers == 3 && proc == 0 {
				binary.BigEndian.PutUint32(reply[20:24], 2)
				reply.u32(2)
				reply.u32(2) // PROG_MISMATCH includes both low and high versions.
			} else if prog == nfsProgram && vers == 2 && proc == 17 {
				for _, value := range []uint32{0, 8192, 4096, 100, 50, 40} {
					reply.u32(value)
				}
				reply.u32(2)
			} else if prog != nfsProgram || vers != 2 || proc != 0 {
				bad.Store(true)
			}
			s.WriteToUDP(reply, a)
		}
	}()
	t.Cleanup(func() { s.Close(); <-done })
	c, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "auto", Transport: "udp", PortmapPort: port, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Version() != "2" || c.Transport() != "udp" || bad.Load() || c.ReadSize != 4096 {
		t.Fatalf("wrong negotiation %s/%s, bad=%v", c.Version(), c.Transport(), bad.Load())
	}
	for _, limit := range []uint32{512, 1024, 4096} {
		configured, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "auto", Transport: "udp", UDPSize: limit, PortmapPort: port, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := configured.Reconnect(context.Background())
		configured.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := fresh.Tune(context.Background(), make([]byte, 32)); err != nil || fresh.ReadSize != limit || fresh.WriteSize != limit {
			t.Fatal("UDP limit lost after reconnect/tune", err, fresh.ReadSize, fresh.WriteSize)
		}
		fresh.Close()
	}
	for _, cfg := range []Config{{Version: "4.2", Transport: "udp"}, {Transport: "invalid"}, {Transport: "udp", UDPSize: 511}, {Transport: "udp", UDPSize: 4097}, {Transport: "tcp", UDPSize: 1024}} {
		cfg.Timeout = time.Second
		if _, err := Connect(context.Background(), cfg); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

func TestUDPUnknownAndMountOperationsAreNotReplayed(t *testing.T) {
	if udpReadOnly(mountProgram, 3, 1) || udpReadOnly(mountProgram, 1, 3) || udpReadOnly(999999, 2, 1) || udpReadOnly(nfsProgram, 4, 1) {
		t.Fatal("state-changing/unknown operation replayed")
	}
}

func TestUDPDatagramBoundsAndMalformedMutationReply(t *testing.T) {
	var count atomic.Int32
	_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
		count.Add(1)
		// Matching XID and MSG_DENIED, but missing its required reject payload.
		var reply encoder
		for _, v := range []uint32{binary.BigEndian.Uint32(b), 1, 1, 1} {
			reply.u32(v)
		}
		s.WriteToUDP(reply, a)
	})
	c := udpClient(t, port)
	if _, err := c.call(context.Background(), nfsProgram, 3, 7, nil, make(encoder, 65507)); err == nil || count.Load() != 0 {
		t.Fatalf("oversize request: %v", err)
	}
	if _, err := c.call(context.Background(), nfsProgram, 3, 7, nil, nil); err == nil || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("truncated reply hid ambiguity: %v", err)
	}
	if count.Load() != 1 {
		t.Fatal("malformed mutation reply caused replay")
	}
}

func TestUDPContextDeadlineBoundsRetries(t *testing.T) {
	var count atomic.Int32
	_, port := udpPeer(t, func(_ *net.UDPConn, _ *net.UDPAddr, _ []byte) { count.Add(1) })
	c := udpClient(t, port)
	c.udpRetryDelay = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.call(ctx, nfsProgram, 3, 1, nil, nil)
	if err == nil || time.Since(start) > time.Second || count.Load() > 1 {
		t.Fatalf("deadline: %d %v", count.Load(), err)
	}
}
