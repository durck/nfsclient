package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixture-only, one-client relay. It retains at most one bounded reply in memory,
// never logs packet contents, and joins its worker after closing both sockets.
type kernelGSS3UDPRelay struct {
	port     int
	version  uint32
	down, up *net.UDPConn
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	mode     string
	proc     uint32
	targets  int
	fresh    bool
	err      error
}

type kernelGSS3UDPCall struct{ xid, proc, control, seq, service uint32 }

func kernelGSS3UDPParseCall(packet []byte, versions ...uint32) (kernelGSS3UDPCall, error) {
	var call kernelGSS3UDPCall
	version := uint32(3)
	if len(versions) != 0 {
		version = versions[0]
	}
	if len(packet) > udpPayloadMax {
		return call, errors.New("oversized diagnostic datagram")
	}
	d := &decoder{b: packet}
	call.xid = d.u32()
	if d.u32() != 0 || d.u32() != 2 || d.u32() != nfsProgram || d.u32() != version {
		return call, errors.New("unexpected diagnostic RPC call header")
	}
	call.proc = d.u32()
	if d.u32() != 6 {
		return call, errors.New("diagnostic call is not RPCSEC_GSS")
	}
	cred := &decoder{b: d.opaque(400)}
	gssVersion := cred.u32()
	call.control, call.seq, call.service = cred.u32(), cred.u32(), cred.u32()
	cred.opaque(400)
	flavor := d.u32()
	verifier := d.opaque(400)
	if d.err != nil || cred.err != nil || len(cred.b) != 0 || gssVersion != 1 || call.control > 3 || call.service < 1 || call.service > 3 {
		return call, errors.New("invalid diagnostic GSS credential")
	}
	if call.control == 1 || call.control == 2 {
		if flavor != 0 || len(verifier) != 0 {
			return call, errors.New("invalid diagnostic GSS control verifier")
		}
	} else if flavor != 6 || len(verifier) == 0 {
		return call, errors.New("missing diagnostic GSS DATA verifier")
	}
	return call, nil
}

// Alter inside a counted opaque value, never its XDR padding. The ordinary
// client must reject this using its real GSS context, not relay verification.
func kernelGSS3UDPTamper(reply []byte, service uint32, body bool) ([]byte, error) {
	if len(reply) > udpPayloadMax {
		return nil, errors.New("oversized diagnostic reply")
	}
	copyReply := append([]byte(nil), reply...)
	d := &decoder{b: copyReply}
	d.u32()
	if d.u32() != 1 || d.u32() != 0 || d.u32() != 6 {
		return nil, errors.New("unexpected diagnostic GSS reply")
	}
	mic := d.opaque(400)
	status := d.u32()
	if d.err != nil || len(mic) == 0 || status != 0 {
		return nil, errors.New("missing successful diagnostic reply verifier")
	}
	if !body {
		mic[len(mic)-1] ^= 1
		return copyReply, nil
	}
	protected := d.opaque(udpPayloadMax)
	if service == 2 {
		d.opaque(400)
	} else if service != 3 {
		return nil, errors.New("expected protected diagnostic reply")
	}
	if d.err != nil || len(protected) == 0 || len(d.b) != 0 {
		return nil, errors.New("invalid protected diagnostic reply framing")
	}
	protected[len(protected)-1] ^= 1
	return copyReply, nil
}

func startKernelGSS3UDPRelay(t *testing.T, port int, versions ...uint32) *kernelGSS3UDPRelay {
	t.Helper()
	version := uint32(3)
	if len(versions) != 0 {
		version = versions[0]
	}
	return startKernelGSSUDPRelayAt(t, "127.0.0.1", port, version)
}

func startKernelGSSUDPRelayAt(t *testing.T, host string, port int, version uint32) *kernelGSS3UDPRelay {
	t.Helper()
	address := net.ParseIP(host)
	if address == nil {
		t.Fatal("native relay requires an explicit fixture IP")
	}
	down, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: address, Port: port})
	if err != nil {
		down.Close()
		t.Fatal(err)
	}
	r := &kernelGSS3UDPRelay{port: down.LocalAddr().(*net.UDPAddr).Port, version: version, down: down, up: up, done: make(chan struct{})}
	t.Cleanup(func() {
		r.close()
		if _, _, err := r.snapshot(); err != nil {
			t.Error(err)
		}
	})
	go func() {
		defer close(r.done)
		if err := r.run(); err != nil && !errors.Is(err, net.ErrClosed) {
			r.mu.Lock()
			r.err = err
			r.mu.Unlock()
		}
	}()
	return r
}

func (r *kernelGSS3UDPRelay) close() { r.once.Do(func() { r.down.Close(); r.up.Close(); <-r.done }) }
func (r *kernelGSS3UDPRelay) arm(mode string, proc uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode, r.proc = mode, proc
}
func (r *kernelGSS3UDPRelay) snapshot() (int, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.targets, r.fresh, r.err
}

func (r *kernelGSS3UDPRelay) run() error {
	buffer := make([]byte, 65536)
	var peer *net.UDPAddr
	var saved []byte
	var first kernelGSS3UDPCall
	for {
		n, addr, err := r.down.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		if peer == nil {
			peer = addr
		} else if peer.Port != addr.Port || !peer.IP.Equal(addr.IP) {
			return errors.New("diagnostic relay received another client")
		}
		request := append([]byte(nil), buffer[:n]...)
		call, err := kernelGSS3UDPParseCall(request, r.version)
		if err != nil {
			return err
		}
		r.mu.Lock()
		mode := r.mode
		target := mode != "" && call.control == 0 && call.proc == r.proc
		if target {
			r.targets++
		}
		index := r.targets
		r.mu.Unlock()
		if err := r.up.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
		if _, err := r.up.Write(request); err != nil {
			return err
		}
		var reply []byte
		for ignored := 0; ignored < 16; ignored++ {
			n, err = r.up.Read(buffer)
			if err != nil {
				return fmt.Errorf("diagnostic upstream reply: %w", err)
			}
			if n >= 4 && binary.BigEndian.Uint32(buffer[:n]) == call.xid {
				if n > udpPayloadMax {
					return errors.New("oversized diagnostic reply")
				}
				reply = append([]byte(nil), buffer[:n]...)
				break
			}
		}
		if reply == nil {
			return errors.New("too many unrelated diagnostic replies")
		}
		if target {
			switch mode {
			case "lost-create":
				continue // Count every request, but never answer a retransmission.
			case "loss-reorder", "replayed-reply":
				if index == 1 {
					first, saved = call, reply
					continue
				}
				if index == 2 {
					fresh := call.xid != first.xid && call.seq == first.seq+1 && call.service == first.service
					r.mu.Lock()
					r.fresh = fresh
					r.mu.Unlock()
					if !fresh {
						return errors.New("diagnostic retry reused XID or GSS sequence")
					}
					if mode == "replayed-reply" {
						reply = saved
						binary.BigEndian.PutUint32(reply, call.xid)
					} else {
						// Delayed attempt-one response arrives ahead of attempt two.
						if _, err := r.down.WriteToUDP(saved, peer); err != nil {
							return err
						}
					}
					saved = nil
				}
			case "altered-verifier", "altered-body":
				if index == 1 {
					reply, err = kernelGSS3UDPTamper(reply, call.service, mode == "altered-body")
					if err != nil {
						return err
					}
				}
			default:
				return errors.New("unknown diagnostic relay mode")
			}
		}
		if _, err := r.down.WriteToUDP(reply, peer); err != nil {
			return err
		}
	}
}

func TestKernelGSS3UDPRelayBounds(t *testing.T) {
	makeCall := func(xid, seq uint32) []byte {
		var e, cred encoder
		for _, n := range []uint32{xid, 0, 2, nfsProgram, 3, 6, 6} {
			e.u32(n)
		}
		for _, n := range []uint32{1, 0, seq, 2} {
			cred.u32(n)
		}
		cred.opaque([]byte("context"))
		e.opaque(cred)
		e.u32(6)
		e.opaque([]byte("mic"))
		return e
	}
	request := makeCall(10, 1)
	if call, err := kernelGSS3UDPParseCall(request); err != nil || call.xid != 10 || call.seq != 1 || call.proc != 6 || call.service != 2 {
		t.Fatalf("call framing: %+v %v", call, err)
	}
	for length := 0; length < len(request); length++ {
		if _, err := kernelGSS3UDPParseCall(request[:length]); err == nil {
			t.Fatalf("accepted truncated call at %d", length)
		}
	}
	oversized := make([]byte, udpPayloadMax+1)
	if _, err := kernelGSS3UDPParseCall(oversized); err == nil {
		t.Fatal("accepted oversized call")
	}
	bad := append([]byte(nil), request...)
	binary.BigEndian.PutUint32(bad[28:], 401)
	if _, err := kernelGSS3UDPParseCall(bad); err == nil {
		t.Fatal("accepted oversized credential")
	}
	for _, service := range []uint32{2, 3} {
		reply := gssUDPReply(10, 1, service)
		for _, body := range []bool{false, true} {
			changed, err := kernelGSS3UDPTamper(reply, service, body)
			if err != nil || bytes.Equal(changed, reply) || len(changed) != len(reply) {
				t.Fatalf("tamper bounds: %v", err)
			}
			for length := 0; length < 24; length++ {
				if _, err := kernelGSS3UDPTamper(reply[:length], service, body); err == nil {
					t.Fatalf("accepted truncated reply at %d", length)
				}
			}
		}
	}
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65536)
		for {
			n, a, e := up.ReadFromUDP(b)
			if e != nil {
				return
			}
			up.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { up.Close(); <-done })
	r := startKernelGSS3UDPRelay(t, up.LocalAddr().(*net.UDPAddr).Port)
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(request); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65536)
	n, err := c.Read(b)
	if err != nil || !bytes.Equal(b[:n], request) {
		t.Fatalf("relay changed datagram: %v", err)
	}
	// Closing an idle relay must release its blocking read immediately.
	r.close()
	if _, _, err := r.snapshot(); err != nil {
		t.Fatal(err)
	}
}

func TestKernelGSS3UDPRelayFaults(t *testing.T) {
	for _, service := range []uint32{2, 3} {
		for _, mode := range []string{"loss-reorder", "replayed-reply", "altered-verifier", "altered-body", "lost-create"} {
			t.Run(fmt.Sprintf("%d/%s", service, mode), func(t *testing.T) {
				up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					b := make([]byte, 65536)
					for {
						n, addr, err := up.ReadFromUDP(b)
						if err != nil {
							if errors.Is(err, net.ErrClosed) {
								err = nil
							}
							done <- err
							return
						}
						call, err := kernelGSS3UDPParseCall(b[:n])
						if err != nil {
							done <- err
							return
						}
						if _, err := up.WriteToUDP(gssUDPReply(call.xid, call.seq, service), addr); err != nil {
							done <- err
							return
						}
					}
				}()
				t.Cleanup(func() {
					up.Close()
					if err := <-done; err != nil {
						t.Error(err)
					}
				})
				r := startKernelGSS3UDPRelay(t, up.LocalAddr().(*net.UDPAddr).Port)
				c := udpClient(t, r.port)
				c.timeout, c.udpRetryDelay = 250*time.Millisecond, 30*time.Millisecond
				c.gss = &rpcGSS{context: testPrivacy{}, established: true, service: service, handle: []byte("context")}
				proc := uint32(6)
				if mode == "lost-create" {
					proc = 8
				}
				r.arm(mode, proc)
				d, err := c.call(context.Background(), nfsProgram, 3, proc, nil, encoder{0, 0, 0, 9})
				count, fresh, relayErr := r.snapshot()
				if relayErr != nil {
					t.Fatal(relayErr)
				}
				switch mode {
				case "loss-reorder":
					if err != nil || d == nil || d.u32() != 42 || count != 2 || !fresh {
						t.Fatalf("loss relay: count=%d fresh=%t err=%v", count, fresh, err)
					}
				case "lost-create":
					if err == nil || d != nil || count != 1 || !strings.Contains(err.Error(), "outcome unknown") {
						t.Fatalf("mutation relay: count=%d err=%v", count, err)
					}
				default:
					want := 1
					if mode == "replayed-reply" {
						want = 2
					}
					// testPrivacy intentionally has no encryption. Altering its
					// final payload byte can be accepted: verify the relay changed
					// that byte here; real krb5p rejection is required by the opt-in
					// diagnostic, using the MIT-issued GSS context.
					if mode == "altered-body" && service == 3 {
						if err != nil || d == nil || d.u32() != 43 || count != want {
							t.Fatalf("privacy relay mutation: count=%d err=%v", count, err)
						}
					} else if err == nil || d != nil || count != want || isRPCTimeout(err) {
						t.Fatalf("fault relay: count=%d err=%v", count, err)
					}
				}
			})
		}
	}
}
