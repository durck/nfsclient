package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func nsmPeer(t *testing.T, state *atomic.Uint32, accepted ...*atomic.Int32) int {
	ready := make(chan struct{})
	var port int
	port = nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
		<-ready
		d := &decoder{b: raw}
		xid := d.u32()
		d.take(8)
		program, version, procedure := d.u32(), d.u32(), d.u32()
		d.u32()
		d.opaque(400)
		d.u32()
		d.opaque(400)
		var body encoder
		if program == 100000 && version == 2 && procedure == 3 {
			body.u32(uint32(port))
		} else if program == nsmProgram && version == 1 && procedure == 1 {
			d.opaque(1024)
			body.u32(0)
			body.u32(state.Load())
		} else {
			t.Errorf("unexpected NSM fixture request: %d/%d/%d", program, version, procedure)
		}
		return append(udpReply(xid, 0)[:24], body...)
	}, accepted...)
	close(ready)
	return port
}

func TestNSMListenerPair(t *testing.T) {
	l, u, err := listenNSMPair("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer u.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if port == 0 || port != u.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("TCP/UDP callback ports differ")
	}
	if other, udp, err := listenNSMPair("127.0.0.1", port); err == nil {
		other.Close()
		udp.Close()
		t.Fatal("explicit occupied port silently changed")
	}
	u.Close()
	if other, udp, err := listenNSMPair("127.0.0.1", port); err == nil {
		other.Close()
		udp.Close()
		t.Fatal("occupied TCP port accepted")
	}
	// Failed TCP binding must release the already-bound UDP socket.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal("failed allocation leaked UDP listener", err)
	}
	probe.Close()
}

func TestNSMListenerAndInvalidation(t *testing.T) {
	var state atomic.Uint32
	state.Store(3)
	port := nsmPeer(t, &state)
	cfg := Config{Version: "3", Transport: "tcp", Timeout: time.Second, Host: "127.0.0.1", PortmapPort: port, NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
	var invalidated atomic.Int32
	n, err := startNSM(context.Background(), cfg, "127.0.0.1", 0, func() { invalidated.Add(1) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	n.active.Store(1)
	if n.accepts(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 123}) {
		t.Fatal("foreign source accepted")
	}
	for _, transport := range []string{"tcp", "udp"} {
		call := func(program, version, procedure uint32, e encoder) (*decoder, error) {
			c, err := dialRPCTransport(context.Background(), "127.0.0.1", n.port, time.Second, false, transport)
			if err != nil {
				t.Fatal(err)
			}
			defer c.conn.Close()
			return c.call(context.Background(), program, version, procedure, nil, e)
		}
		var pm encoder
		pm.u32(nsmProgram)
		pm.u32(1)
		pm.u32(17)
		pm.u32(0)
		d, err := call(100000, 2, 3, pm)
		if err != nil || d.u32() != uint32(n.port) || len(d.b) != 0 {
			t.Fatalf("portmapper: %v", err)
		}
		var addr encoder
		addr.u32(nsmProgram)
		addr.u32(1)
		addr.str("udp")
		addr.str("")
		addr.str("")
		d, err = call(100000, 4, 3, addr)
		if err != nil || d.str() == "" || len(d.b) != 0 {
			t.Fatalf("rpcbind: %v", err)
		}
		var stat encoder
		stat.str(cfg.NLMClientIP)
		d, err = call(nsmProgram, 1, 1, stat)
		if err != nil || d.u32() != 0 || d.u32() != 1 {
			t.Fatalf("SM_STAT: %v", err)
		}
		var notify encoder
		notify.str("server.example")
		notify.u32(3)
		if _, err = call(nsmProgram, 1, 6, notify); err != nil {
			t.Fatal(err)
		}
		if n.lost.Load() {
			t.Fatal("duplicate epoch invalidated state")
		}
		if _, err = call(nsmProgram, 1, 6, append(notify, 1)); err == nil {
			t.Fatal("trailing callback accepted")
		}
		if _, err = call(nsmProgram, 1, 5, nil); err == nil {
			t.Fatal("remote simulated crash accepted")
		}
	}
	// The receive path applies a real UDP notification, not a direct test hook.
	var notify encoder
	notify.str("server.example")
	notify.u32(5)
	c, err := dialRPCTransport(context.Background(), "127.0.0.1", n.port, time.Second, false, "udp")
	if err != nil {
		t.Fatal(err)
	}
	defer c.conn.Close()
	if _, err := c.call(context.Background(), nsmProgram, 1, 6, nil, notify); err != nil {
		t.Fatal(err)
	}
	if !n.lost.Load() || invalidated.Load() != 1 {
		t.Fatal("restart did not latch invalidation")
	}
	if err := n.probe(context.Background()); err == nil {
		t.Fatal("lost state healed implicitly")
	}
}

func TestNSMBackgroundProbe(t *testing.T) {
	var state atomic.Uint32
	state.Store(3)
	cfg := Config{Version: "3", Transport: "tcp", Timeout: time.Second, PortmapPort: nsmPeer(t, &state), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
	changed := make(chan struct{}, 1)
	n, err := startNSM(context.Background(), cfg, "127.0.0.1", 0, func() { changed <- struct{}{} }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	n.active.Store(1)
	state.Store(5)
	select {
	case <-changed:
	case <-time.After(3 * time.Second):
		t.Fatal("polling missed changed server state")
	}
}

func TestNSMRecordBounds(t *testing.T) {
	for _, b := range [][]byte{binary.BigEndian.AppendUint32(nil, 0x80001001), make([]byte, 4*16), {0, 0, 0}} {
		if _, err := readNSMRecord(bytes.NewReader(b)); err == nil {
			t.Fatal("unbounded or truncated record accepted")
		}
	}
}

func TestNSMProbeRetainsConnection(t *testing.T) {
	var state atomic.Uint32
	state.Store(3)
	var accepted atomic.Int32
	cfg := Config{Version: "3", Transport: "tcp", Timeout: time.Second, PortmapPort: nsmPeer(t, &state, &accepted), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
	n, err := startNSM(context.Background(), cfg, "127.0.0.1", 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	before := accepted.Load()
	for range 20 {
		if err := n.probe(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := accepted.Load(); got != before {
		t.Fatalf("NSM probes opened %d additional TCP connections", got-before)
	}
	state.Store(5)
	if err := n.probe(context.Background()); err == nil || !n.lost.Load() {
		t.Fatal("changed epoch accepted", err)
	}
	if accepted.Load() != before {
		t.Fatal("monitor silently reconnected")
	}
}
