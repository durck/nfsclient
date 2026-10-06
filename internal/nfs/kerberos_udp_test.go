package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gssUDPReply(xid, seq, service uint32) encoder {
	var reply encoder
	for _, v := range []uint32{xid, 1, 0, 6} {
		reply.u32(v)
	}
	mic, _ := (testMIC{}).MakeSignature(binary.BigEndian.AppendUint32(nil, seq))
	reply.opaque(mic)
	reply.u32(0)
	result := encoder{0, 0, 0, 42}
	if service == 2 {
		reply = append(reply, integrityEnvelope(seq, result)...)
	} else if service == 3 {
		reply.opaque(append(binary.BigEndian.AppendUint32(nil, seq), result...))
	} else {
		reply = append(reply, result...)
	}
	return reply
}

func TestGSSUDPRetriesUseFreshSequences(t *testing.T) {
	for _, service := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			packets := make(chan []byte, 3)
			var count atomic.Int32
			var first []byte
			_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
				packets <- b
				if count.Add(1) == 1 {
					first = append([]byte(nil), b...)
					return
				}
				// A late signed reply from attempt one must not replace attempt two.
				s.WriteToUDP(gssUDPReply(binary.BigEndian.Uint32(first), 1, service), a)
				s.WriteToUDP(gssUDPReply(binary.BigEndian.Uint32(b), 2, service), a)
			})
			c := udpClient(t, port)
			c.gss = &rpcGSS{context: testPrivacy{}, established: true, service: service, handle: []byte("context")}
			d, err := c.call(context.Background(), nfsProgram, 3, 1, nil, encoder{0, 0, 0, 99})
			if err != nil || d.u32() != 42 {
				t.Fatalf("retry result: %v", err)
			}
			if count.Load() != 2 || c.gss.seq != 2 {
				t.Fatal("wrong retry count or sequence")
			}
			one, two := <-packets, <-packets
			if bytes.Equal(one, two) || binary.BigEndian.Uint32(one) == binary.BigEndian.Uint32(two) {
				t.Fatal("reused GSS packet/XID")
			}
			for i, raw := range [][]byte{one, two} {
				x := &decoder{b: raw}
				x.take(24)
				if x.u32() != 6 {
					t.Fatal("not GSS")
				}
				cred := &decoder{b: x.opaque(400)}
				cred.take(8)
				seq, svc := cred.u32(), cred.u32()
				if seq != uint32(i+1) || svc != service {
					t.Fatal("wrong fresh sequence/service")
				}
				signed := len(raw) - len(x.b)
				if x.u32() != 6 {
					t.Fatal("missing request MIC")
				}
				if err := (testMIC{}).VerifySignature(raw[:signed], x.opaque(400)); err != nil {
					t.Fatal(err)
				}
				if service > 1 {
					body := x.opaque(maxRecord)
					if binary.BigEndian.Uint32(body) != seq {
						t.Fatal("body retained old sequence")
					}
					if service == 2 {
						if err := (testMIC{}).VerifySignature(body, x.opaque(400)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
		})
	}
}

func TestGSSUDPRejectsTampering(t *testing.T) {
	for _, mode := range []string{"verifier", "integrity-body", "privacy-sequence", "mutation-verifier"} {
		t.Run(mode, func(t *testing.T) {
			service := uint32(2)
			if mode == "privacy-sequence" {
				service = 3
			}
			var count atomic.Int32
			_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) {
				count.Add(1)
				reply := gssUDPReply(binary.BigEndian.Uint32(b), 1, service)
				if strings.Contains(mode, "verifier") {
					reply[20] ^= 1
				} else if service == 2 {
					reply[len(reply)-1] ^= 1
				} else {
					reply[len(reply)-5] ^= 1
				}
				s.WriteToUDP(reply, a)
			})
			c := udpClient(t, port)
			c.gss = &rpcGSS{context: testPrivacy{}, established: true, service: service}
			proc := uint32(1)
			if mode == "mutation-verifier" {
				proc = 7
			}
			d, err := c.call(context.Background(), nfsProgram, 3, proc, nil, nil)
			if err == nil || d != nil || count.Load() != 1 {
				t.Fatalf("bad reply exposed/retried: %v", err)
			}
			if proc == 7 && !strings.Contains(err.Error(), "outcome unknown") {
				t.Fatal(err)
			}
			if _, err := c.call(context.Background(), nfsProgram, 3, 1, nil, nil); err == nil {
				t.Fatal("reused failed GSS session")
			}
		})
	}
}

func TestGSSUDPLossDoesNotReplayControlOrMutations(t *testing.T) {
	for _, mode := range []string{"read", "write", "init", "destroy", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			var count atomic.Int32
			_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) { count.Add(1) })
			c := udpClient(t, port)
			c.timeout = 80 * time.Millisecond
			c.gss = &rpcGSS{context: testMIC{}, established: true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var err error
			expected := int32(1)
			switch mode {
			case "read":
				_, err = c.call(ctx, nfsProgram, 3, 1, nil, nil)
				expected = 3
			case "write":
				_, err = c.call(ctx, nfsProgram, 3, 7, nil, nil)
			case "init":
				c.gss.established = false
				_, err = c.callLocked(ctx, nfsProgram, 3, 0, nil, nil, 1)
			case "destroy":
				_, err = c.callLocked(ctx, nfsProgram, 3, 0, nil, nil, 3)
			case "cancelled":
				cancel()
				_, err = c.call(ctx, nfsProgram, 3, 1, nil, nil)
				expected = 0
			}
			if err == nil || count.Load() != expected {
				t.Fatalf("%s: packets=%d want=%d err=%v", mode, count.Load(), expected, err)
			}
		})
	}
}

func TestGSSUDPExpiryStopsReadRetries(t *testing.T) {
	var count atomic.Int32
	_, port := udpPeer(t, func(s *net.UDPConn, a *net.UDPAddr, b []byte) { count.Add(1) })
	c := udpClient(t, port)
	c.udpRetryDelay = time.Second
	c.gss = &rpcGSS{context: testMIC{}, established: true, expiry: time.Now().Add(40 * time.Millisecond)}
	_, err := c.call(context.Background(), nfsProgram, 3, 1, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "context expired") || count.Load() != 1 {
		t.Fatalf("expired read retried or lost expiry diagnostic: packets=%d err=%v", count.Load(), err)
	}
}
