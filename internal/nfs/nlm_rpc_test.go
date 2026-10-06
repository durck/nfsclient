package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func nlmTestEndpoint(t *testing.T, transport string, handler func([]byte) []byte, accepted ...*atomic.Int32) int {
	t.Helper()
	if transport == "udp" {
		_, port := udpPeer(t, func(conn *net.UDPConn, addr *net.UDPAddr, b []byte) {
			if reply := handler(b); reply != nil {
				conn.WriteToUDP(reply, addr)
			}
		})
		return port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			if len(accepted) > 0 {
				accepted[0].Add(1)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				for {
					b, err := readRecord(conn)
					if err != nil {
						return
					}
					if reply := handler(b); reply != nil {
						if _, err := conn.Write(record(reply, true)); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done; wg.Wait() })
	return l.Addr().(*net.TCPAddr).Port
}

func TestNLMWire(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, version := range []uint32{1, 4} {
			for _, mode := range []string{"explicit", "discovery", "unavailable", "bad-port", "trailing-port", "grace", "cancel", "timeout", "security"} {
				t.Run(fmt.Sprintf("%s/v%d/%s", transport, version, mode), func(t *testing.T) {
					var calls atomic.Int32
					var port int
					ready := make(chan struct{})
					fh := bytes.Repeat([]byte{0xa5}, 32)
					offset := uint64(19)
					if version == 4 {
						offset += 1 << 33
					}
					port = nlmTestEndpoint(t, transport, func(raw []byte) []byte {
						<-ready // Publish the discovered port before the UDP receive goroutine reads it.
						calls.Add(1)
						d := &decoder{b: raw}
						xid := d.u32()
						if d.u32() != 0 || d.u32() != 2 {
							t.Error("bad RPC call header")
						}
						prog, vers, proc := d.u32(), d.u32(), d.u32()
						flavor := d.u32()
						cred := &decoder{b: d.opaque(400)}
						if d.u32() != 0 || len(d.opaque(400)) != 0 {
							t.Error("changed verifier")
						}
						var body encoder
						if prog == 100000 {
							protocol := uint32(6)
							if transport == "udp" {
								protocol = 17
							}
							if vers != 2 || proc != 3 || flavor != 0 || len(cred.b) != 0 || d.u32() != nlmProgram || d.u32() != version || d.u32() != protocol || d.u32() != 0 {
								t.Error("bad NLM port discovery")
							}
							p := uint32(port)
							if mode == "unavailable" {
								p = 0
							}
							if mode == "bad-port" {
								p = 65536
							}
							body.u32(p)
							if mode == "trailing-port" {
								body.u32(0)
							}
						} else {
							if prog != nlmProgram || vers != version || proc != 1 || flavor != 1 {
								t.Error("not NLM TEST with AUTH_SYS")
							}
							cred.u32()
							if cred.str() != "nfs-viewer" || cred.u32() != 21 || cred.u32() != 22 || cred.u32() != 2 || cred.u32() != 23 || cred.u32() != 24 || cred.err != nil || len(cred.b) != 0 {
								t.Error("changed AUTH_SYS identity")
							}
							cookie := d.opaque(1024)
							if len(cookie) != 16 || !d.boolean() || net.ParseIP(d.str()) == nil || !bytes.Equal(d.opaque(64), fh) || len(d.opaque(1024)) != 16 || d.u32() == 0 {
								t.Error("bad TEST arguments")
							}
							var gotOffset, gotLength uint64
							if version == 1 {
								gotOffset, gotLength = uint64(d.u32()), uint64(d.u32())
							} else {
								gotOffset, gotLength = d.u64(), d.u64()
							}
							if gotOffset != offset || gotLength != 0 {
								t.Error("changed offset/EOF wire encoding")
							}
							body.opaque(cookie)
							if mode == "grace" {
								body.u32(4)
							} else {
								body.u32(0)
							}
						}
						if d.err != nil || len(d.b) != 0 {
							t.Error("truncated or trailing request")
						}
						if mode == "timeout" && prog == nlmProgram {
							return nil
						}
						reply := udpReply(xid, 0)
						return append(reply[:24], body...)
					})
					close(ready)
					rpc, err := dialRPCTransport(context.Background(), "127.0.0.1", port, time.Second, false, transport)
					if err != nil {
						t.Fatal(err)
					}
					defer rpc.conn.Close()
					cfg := &Config{Host: "must-not-resolve.invalid", PortmapPort: port, Timeout: time.Second, Transport: transport}
					if mode == "timeout" {
						cfg.Timeout = 150 * time.Millisecond
					}
					if mode == "explicit" {
						cfg.NLMPort = port
					}
					c := &Client{config: cfg, nfs: rpc, version: "3", Auth: Auth{UID: 21, GID: 22, Groups: []uint32{23, 24}}}
					if version == 1 {
						c.version = "2"
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if mode == "cancel" {
						cancel()
					}
					if mode == "security" {
						for _, security := range []string{"krb5", "krb5i", "krb5p", "tls"} {
							c.security = security
							cfg.TLS.Enabled = security == "tls"
							if security == "tls" {
								c.security = "sys"
							}
							if _, err := c.TestLock(ctx, fh, true, offset, LockToEOF); err == nil || !strings.Contains(err.Error(), "downgrade refused") {
								t.Fatalf("%s: %v", security, err)
							}
						}
						if calls.Load() != 0 {
							t.Fatal("security refusal sent traffic")
						}
						return
					}
					got, err := c.TestLock(ctx, fh, true, offset, LockToEOF)
					wantError := mode != "explicit" && mode != "discovery"
					if (err != nil) != wantError || got != nil {
						t.Fatalf("%+v %v", got, err)
					}
					wantCalls := int32(1)
					if mode == "discovery" || mode == "grace" || mode == "timeout" {
						wantCalls = 2
					}
					if mode == "cancel" {
						wantCalls = 0
					}
					if calls.Load() != wantCalls {
						t.Fatalf("calls=%d want=%d", calls.Load(), wantCalls)
					}
					if mode == "grace" && !strings.Contains(err.Error(), "grace") {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestNLMTestUDPRetry(t *testing.T) {
	var count atomic.Int32
	var first []byte
	_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
		if count.Add(1) == 1 {
			first = b
			return
		}
		if !bytes.Equal(first, b) {
			t.Error("retry changed TEST packet")
		}
		s.WriteToUDP(udpReply(binary.BigEndian.Uint32(b), 42), a)
	})
	c := udpClient(t, port)
	if _, err := c.call(context.Background(), nlmProgram, 4, 1, &Auth{}, nil); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 2 {
		t.Fatal("TEST did not retransmit")
	}
}
