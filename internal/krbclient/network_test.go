package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/resolve"
	"nfsclient/internal/testutil/kdcfixture"
	"nfsclient/internal/testutil/loopback"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"golang.org/x/net/dns/dnsmessage"
)

func TestKDCDNSDatagramFraming(t *testing.T) {
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	dns.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := dns.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		var req dnsmessage.Message
		if err := req.Unpack(buf[:n]); err != nil {
			done <- err
			return
		}
		if len(req.Questions) != 1 || req.Questions[0].Type != dnsmessage.TypeSRV {
			done <- errors.New("wrong DNS query")
			return
		}
		target, _ := dnsmessage.NewName("server.nfs.test.")
		reply := dnsmessage.Message{Header: dnsmessage.Header{ID: req.ID, Response: true, Authoritative: true}, Questions: req.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: req.Questions[0].Name, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.SRVResource{Port: 8888, Target: target}}}}
		wire, err := reply.Pack()
		if err == nil {
			_, err = dns.WriteTo(wire, addr)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cl := &Client{Config: config.New(), settings: NewSettings(DNS(resolve.Config{Server: dns.LocalAddr().String()}))}
	cl.Config.LibDefaults.DNSLookupKDC = true
	records, err := cl.kdcEndpoints(ctx, "synthetic.invalid", "tcp")
	if err != nil || len(records) != 1 || records[0] != "server.nfs.test:8888" {
		t.Fatalf("SRV result: %v %v", records, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestKDCDNSCancellation(t *testing.T) {
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	seen := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			if _, _, err := dns.ReadFrom(buf); err != nil {
				return
			}
			once.Do(func() { close(seen) })
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cl := &Client{Config: config.New(), settings: NewSettings(DNS(resolve.Config{Server: dns.LocalAddr().String()}))}
	cl.Config.LibDefaults.DNSLookupKDC = true
	result := make(chan error, 1)
	go func() { _, err := cl.kdcEndpoints(ctx, "synthetic.invalid", "tcp"); result <- err }()
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("no SRV query")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled DNS succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation stalled")
	}
	dns.Close()
	<-done
}

func TestKDCUDPTooBigFallsBackToTCP(t *testing.T) {
	l, u, err := loopback.Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer u.Close()
	u.SetDeadline(time.Now().Add(time.Second))
	udpErr := make(chan error, 1)
	tcpErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 100)
		_, addr, err := u.ReadFrom(buf)
		if err != nil {
			udpErr <- err
			return
		}
		e := messages.NewKRBError(types.PrincipalName{NameString: []string{"krbtgt", "NFS.TEST"}}, "NFS.TEST", errorcode.KRB_ERR_RESPONSE_TOO_BIG, "synthetic")
		wire, err := e.Marshal()
		if err == nil {
			_, err = u.WriteTo(wire, addr)
		}
		udpErr <- err
	}()
	go func() {
		c, err := l.Accept()
		if err != nil {
			tcpErr <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 11)
		_, err = io.ReadFull(c, buf)
		if err == nil {
			_, err = c.Write([]byte{0, 0, 0, 5, 'r', 'e', 'p', 'l', 'y'})
		}
		tcpErr <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1000
	cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{l.Addr().String()}}}
	cl := &Client{Config: cfg, settings: NewSettings(NetworkContext(ctx))}
	reply, err := cl.sendToKDC([]byte("request"), "NFS.TEST")
	if err != nil || string(reply) != "reply" {
		t.Fatalf("fallback: %q %v", reply, err)
	}
	if err := <-udpErr; err != nil {
		t.Fatal(err)
	}
	if err := <-tcpErr; err != nil {
		t.Fatal(err)
	}
}

func TestKDCUDPRecoversWithinSetupDeadline(t *testing.T) {
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		var first []byte
		var source string
		for attempt := 0; attempt < 2; attempt++ {
			n, from, err := peer.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			if attempt == 0 {
				first, source = append([]byte(nil), buf[:n]...), from.String()
				continue // The first request/reply is lost.
			}
			if !bytes.Equal(first, buf[:n]) || source != from.String() {
				done <- errors.New("KDC retry changed bytes or source socket")
				return
			}
			_, err = peer.WriteTo([]byte("reply"), from)
			done <- err
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reply, err := kdcExchange(ctx, "udp", peer.LocalAddr().String(), []byte("request"), resolve.Config{})
	peer.Close()
	peerErr := <-done
	if err != nil || peerErr != nil || string(reply) != "reply" {
		t.Fatalf("recover lost UDP packet within setup budget: reply=%q error=%v peer=%v", reply, err, peerErr)
	}
}

func TestKDCUDPRetryBounds(t *testing.T) {
	for _, scenario := range []string{"exhausted", "deadline", "empty-response"} {
		t.Run(scenario, func(t *testing.T) {
			peer, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var count atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 100)
				for {
					_, addr, err := peer.ReadFrom(buf)
					if err != nil {
						return
					}
					count.Add(1)
					if scenario == "empty-response" {
						peer.WriteTo(nil, addr)
					}
				}
			}()
			t.Cleanup(func() { peer.Close(); <-done })
			conn, err := net.Dial("udp", peer.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			budget, delay := time.Second, 20*time.Millisecond
			if scenario == "deadline" {
				budget, delay = 50*time.Millisecond, time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			_, err = kdcUDPRoundTrip(ctx, conn, []byte("request"), delay)
			want := int32(1)
			switch scenario {
			case "exhausted":
				want = 3
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("exhaustion: %v", err)
				}
			case "deadline":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline: %v", err)
				}
			case "empty-response":
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("empty reply: %v", err)
				}
			}
			if count.Load() != want {
				t.Fatalf("sent %d requests, want %d", count.Load(), want)
			}
		})
	}
}

func TestKDCTCPFraming(t *testing.T) {
	for _, mode := range []string{"fragmented", "zero", "oversize", "high-bit", "short-header", "short-body"} {
		t.Run(mode, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				req := make([]byte, 11)
				if _, err := io.ReadFull(b, req); err != nil {
					done <- err
					return
				}
				if !bytes.Equal(req, append([]byte{0, 0, 0, 7}, []byte("request")...)) {
					done <- errors.New("wrong request framing")
					return
				}
				packet := append([]byte{0, 0, 0, 5}, []byte("reply")...)
				switch mode {
				case "zero":
					packet = []byte{0, 0, 0, 0}
				case "oversize":
					packet = binary.BigEndian.AppendUint32(nil, maxKDCMessage+1)
				case "high-bit":
					packet = []byte{128, 0, 0, 1}
				case "short-header":
					packet = packet[:2]
				case "short-body":
					packet = packet[:6]
				}
				for _, v := range packet {
					if _, err := b.Write([]byte{v}); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			reply, err := kdcRoundTrip(a, "tcp", []byte("request"))
			if mode == "fragmented" {
				if err != nil || string(reply) != "reply" {
					t.Fatalf("%q %v", reply, err)
				}
			} else if err == nil {
				t.Fatal("invalid frame accepted")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestKDCInterruptedIO(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			received := make(chan struct{})
			closed := make(chan struct{})
			var endpoint string
			if network == "tcp" {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				endpoint = l.Addr().String()
				go func() {
					defer close(closed)
					c, err := l.Accept()
					if err != nil {
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(2 * time.Second))
					buf := make([]byte, 11)
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					close(received)
					c.Read(buf)
				}()
			} else {
				c, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				endpoint = c.LocalAddr().String()
				go func() {
					defer close(closed)
					c.SetReadDeadline(time.Now().Add(2 * time.Second))
					buf := make([]byte, 100)
					if _, _, err := c.ReadFrom(buf); err == nil {
						close(received)
					}
				}()
			}
			result := make(chan error, 1)
			go func() {
				_, err := kdcExchange(ctx, network, endpoint, []byte("request"), resolve.Config{})
				result <- err
			}()
			select {
			case <-received:
			case <-time.After(time.Second):
				t.Fatal("KDC request not observed")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation left KDC I/O running")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("KDC socket not closed")
			}
		})
	}
}

func TestKDCCancelledDiscoveryAndFailover(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		io.Copy(io.Discard, c)
	}()
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{l.Addr().String(), l.Addr().String()}}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cl := &Client{Config: cfg, settings: NewSettings(NetworkContext(ctx))}
	start := time.Now()
	_, err = cl.sendToKDC([]byte("request"), "NFS.TEST")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("deadline: %v", err)
	}
	<-finished
	for _, dns := range []bool{false, true} {
		cfg.LibDefaults.DNSLookupKDC = dns
		if _, err := cl.kdcEndpoints(ctx, "unknown.invalid", "tcp"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cancelled discovery: %v", err)
		}
	}
}

// Socket deadlines can fire before the context's timer publishes Err(). A
// context with a real deadline but no timer makes that scheduling gap repeatable.
type pendingKDCDeadline struct {
	context.Context
	deadline time.Time
}

func (c pendingKDCDeadline) Deadline() (time.Time, bool) { return c.deadline, true }

func TestKDCDeadlineBeforeContextTimer(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			silent := kdcfixture.Start(t, func(string, []byte) []byte { return nil })
			ctx := pendingKDCDeadline{Context: context.Background(), deadline: time.Now().Add(50 * time.Millisecond)}
			cfg := config.New()
			cfg.LibDefaults.UDPPreferenceLimit = 1
			if network == "udp" {
				cfg.LibDefaults.UDPPreferenceLimit = 32700
			}
			cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{silent.Address, silent.Address}}}
			cl := &Client{Config: cfg, settings: NewSettings(NetworkContext(ctx))}
			_, err := cl.sendToKDC([]byte("request"), "NFS.TEST")
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("elapsed deadline before timer notification: %v", err)
			}
			if ctx.Err() != nil {
				t.Fatal("test must retain the delayed Err notification")
			}
			if _, err := cl.kdcEndpoints(ctx, "unknown.invalid", network); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expired discovery: %v", err)
			}
			calls := silent.TCP.Load() + silent.UDP.Load()
			if calls == 0 || calls > 2 {
				t.Fatalf("unexpected failover calls: %d", calls)
			}
		})
	}
}

func TestServiceTicketExpiryIsKDCValue(t *testing.T) {
	cl := &Client{cache: NewCache()}
	end := time.Now().Add(4 * time.Second).Truncate(time.Second)
	kt := messages.Ticket{SName: types.PrincipalName{NameString: []string{"nfs", "server.nfs.test"}}}
	cl.cache.addEntry(kt, time.Now(), time.Now(), end, end.Add(time.Hour), types.EncryptionKey{})
	got, ok := cl.ServiceTicketExpiry("nfs/server.nfs.test")
	if !ok || !got.Equal(end) {
		t.Fatal(fmt.Sprint(got, ok))
	}
	if _, ok := cl.ServiceTicketExpiry("nfs/missing"); ok {
		t.Fatal("invented expiry")
	}
}
