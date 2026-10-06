package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

func TestPNFSBackchannelNegotiation(t *testing.T) {
	runPNFSBackchannelNegotiation(t, 0)
}

func TestPNFSGSSBackchannelNegotiation(t *testing.T) {
	for _, service := range []uint32{2, 3} {
		t.Run(fmt.Sprint(service), func(t *testing.T) { runPNFSBackchannelNegotiation(t, service) })
	}
}

func runPNFSBackchannelNegotiation(t *testing.T, service uint32) {
	for _, minor := range []uint32{1, 2} {
		for _, tc := range []struct {
			name   string
			limits [5]uint32
			ok     bool
		}{
			{"offered", [5]uint32{65536, 65536, 65536, 8, 1}, true},
			{"reduced", [5]uint32{1024, 4096, 1024, 8, 1}, true},
			{"large-request", [5]uint32{65537, 65536, 65536, 8, 1}, false},
			{"large-response", [5]uint32{65536, 65537, 65536, 8, 1}, false},
			{"large-cache", [5]uint32{65536, 65536, 65537, 8, 1}, false},
			{"small-request", [5]uint32{1023, 65536, 65536, 8, 1}, false},
			{"small-response", [5]uint32{65536, 1023, 1024, 8, 1}, false},
			{"small-cache", [5]uint32{65536, 65536, 1023, 8, 1}, true},
			{"no-cache", [5]uint32{65536, 65536, 0, 8, 1}, true},
			{"changed-ops", [5]uint32{65536, 65536, 65536, 7, 1}, false},
			{"large-ops", [5]uint32{65536, 65536, 65536, 16, 1}, false},
			{"no-slots", [5]uint32{65536, 65536, 65536, 8, 0}, false},
			{"extra-slots", [5]uint32{65536, 65536, 65536, 8, 2}, false},
		} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, tc.name), func(t *testing.T) {
				v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
					var e encoder
					switch code {
					case 42:
						d.take(8)
						d.str()
						d.take(12)
						e.u64(123)
						e.u32(1)
						e.u32(0x20000)
						e.u32(0)
						e.u64(1)
						e.opaque([]byte("server"))
						e.opaque([]byte("scope"))
						e.u32(0)
					case 43:
						d.u64()
						d.u32()
						if d.u32() != 2 {
							return nil, 0, errors.New("missing backchannel flag")
						}
						d.take(28) // Ordinary fore-channel offer.
						for _, want := range []uint32{0, 65536, 65536, 65536, 8, 1, 0} {
							if got := d.u32(); got != want {
								return nil, 0, fmt.Errorf("backchannel offer %d, want %d", got, want)
							}
						}
						if d.u32() != pnfsCallbackProgram || d.u32() != 1 {
							return nil, 0, errors.New("callback program/auth mismatch")
						}
						if service == 0 {
							if d.u32() != 0 {
								return nil, 0, errors.New("wrong AUTH_NONE offer")
							}
						} else if d.u32() != 6 || d.u32() != service || !bytes.Equal(d.opaque(380), []byte("server-handle")) || !bytes.Equal(d.opaque(380), []byte("client-handle")) {
							return nil, 0, errors.New("wrong GSS service or context handle direction")
						}
						e = append(e, bytes.Repeat([]byte{3}, 16)...)
						e.u32(1)
						e.u32(2)
						for _, n := range []uint32{0, 1 << 20, 1 << 20, 65536, 16, 1, 0} {
							e.u32(n)
						}
						e.u32(0)
						for _, n := range tc.limits {
							e.u32(n)
						}
						e.u32(0)
					case 53:
						e = append(e, d.take(16)...)
						e.u32(d.u32())
						d.take(12)
						for range 4 {
							e.u32(0)
						}
					case 58:
						d.boolean()
					case 24:
					case 10:
						e.opaque([]byte("root"))
					default:
						return nil, 0, fmt.Errorf("unexpected operation %d", code)
					}
					return e, 0, nil
				})
				v.recall = &layoutRecall{}
				if service != 0 {
					v.recall.gss = &gssBackchannel{service: service, foreHandle: []byte("server-handle"), handle: []byte("client-handle")}
				}
				err := v.initialize(context.Background())
				if tc.ok && err != nil || !tc.ok && err == nil {
					t.Fatal(tc.name, err)
				}
				if tc.ok && (v.c.ReadSize != 32768 || v.c.WriteSize != 32768) {
					t.Fatal("backchannel restricted foreground transfer sizes")
				}
			})
		}
	}
}

func TestPNFSInvalidCallbackDoesNotChangeRecall(t *testing.T) {
	r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{2}, 16)}
	call := append(callbackCall(r, 1, true), 0) // Complete recall followed by malformed trailing bytes.
	if _, err := r.callback(call); err == nil {
		t.Fatal("malformed callback accepted")
	}
	if r.recalled || r.sequence != 0 || r.reply != nil {
		t.Fatal("malformed callback changed state")
	}
}

func TestPNFSCallbackNegotiatedLimits(t *testing.T) {
	for _, mode := range []string{"fits", "request", "response", "cache"} {
		t.Run(mode, func(t *testing.T) {
			r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{2}, 16), requestLimit: 4096, responseLimit: 4096, cacheLimit: 4096}
			length := 1000
			switch mode {
			case "fits":
				length = 900
				r.responseLimit = 1024
				r.cacheLimit = 1024
			case "request":
				r.requestLimit = 1024
			case "response":
				r.responseLimit = 1024
			case "cache":
				r.cacheLimit = 1024
			}
			base := callbackCall(r, 1, true)
			call := append(encoder(nil), base[:40]...)
			call.opaque(bytes.Repeat([]byte{'t'}, length))
			call = append(call, base[44:]...)
			reply, err := r.callback(call)
			if mode == "fits" {
				if err != nil || !r.recalled || len(reply) > 1024 {
					t.Fatal(len(reply), err)
				}
				cached, err := r.callback(call)
				if err != nil || !bytes.Equal(cached, reply) {
					t.Fatal("reply cache mismatch", err)
				}
			} else {
				want := map[string]uint32{"request": 10065, "response": 10066, "cache": 10067}[mode]
				if err != nil {
					t.Fatal("size refusal closed callback channel", err)
				}
				d := &decoder{b: reply}
				d.take(24)
				if d.u32() != want || d.str() != string(bytes.Repeat([]byte{'t'}, length)) || d.u32() != 1 || d.u32() != 11 || d.u32() != want || d.err != nil || len(d.b) != 0 {
					t.Fatal("invalid CB_SEQUENCE size refusal", reply)
				}
				if r.recalled || r.sequence != 0 || r.reply != nil || r.request != nil {
					t.Fatal("limit refusal changed state")
				}
				if _, err := r.callback(callbackCall(r, 1, true)); err != nil || !r.recalled || r.sequence != 1 {
					t.Fatal("valid recall refused after size error", err)
				}
			}
		})
	}
}

func TestPNFSCallbackUncachedReplay(t *testing.T) {
	for _, recall := range []bool{false, true} {
		t.Run(fmt.Sprintf("recall=%t", recall), func(t *testing.T) {
			r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{2}, 16), requestLimit: 4096, responseLimit: 4096, cacheLimit: 1024}
			base := callbackCall(r, 1, recall)
			binary.BigEndian.PutUint32(base[88:92], 0) // csa_cachethis = false.
			tag := string(bytes.Repeat([]byte{'t'}, 1000))
			call := append(encoder(nil), base[:40]...)
			call.str(tag)
			call = append(call, base[44:]...)
			check := func(reply []byte, wantStatus uint32, wantCount uint32) {
				t.Helper()
				d := &decoder{b: reply}
				if d.u32() != binary.BigEndian.Uint32(call[:4]) {
					t.Fatal("callback reply XID mismatch")
				}
				d.take(20)
				if d.u32() != wantStatus || d.str() != tag || d.u32() != wantCount || d.u32() != 11 || d.u32() != 0 || !bytes.Equal(d.take(16), r.session) || d.u32() != 1 {
					t.Fatal("callback sequence response mismatch", reply)
				}
				d.take(12)
				if recall && (d.u32() != 5 || d.u32() != wantStatus) {
					t.Fatal("uncached error must be on the second operation", reply)
				}
				if d.err != nil || len(d.b) != 0 {
					t.Fatal("malformed callback response", d.err)
				}
			}
			count := uint32(1)
			if recall {
				count++
			}
			if _, err := r.callback(append(append([]byte(nil), call...), 0)); err == nil || r.recalled || r.sequence != 0 || r.request != nil || r.reply != nil {
				t.Fatal("malformed uncached callback changed state", err)
			}
			reply, err := r.callback(call)
			if err != nil || r.recalled != recall || r.sequence != 1 || len(reply) <= int(r.cacheLimit) || len(reply) > int(r.responseLimit) {
				t.Fatal("valid uncached callback refused", len(reply), err)
			}
			check(reply, 0, count)
			if len(r.reply)+24 > int(r.cacheLimit) || len(r.request) > int(r.requestLimit) {
				t.Fatal("uncached replay bookkeeping exceeded negotiated bounds")
			}
			r.recalled = false
			binary.BigEndian.PutUint32(call[:4], 18) // A retry may use another RPC XID.
			replay, err := r.callback(call)
			if err != nil || r.recalled || r.sequence != 1 {
				t.Fatal("uncached replay executed twice or failed", err)
			}
			wantStatus := uint32(0)
			if recall {
				wantStatus = 10068 // NFS4ERR_RETRY_UNCACHED_REP.
			}
			check(replay, wantStatus, count)
			changed := append([]byte(nil), call...)
			changed[44] ^= 1 // Same sequence with a changed compound tag.
			if _, err := r.callback(changed); err == nil {
				t.Fatal("changed uncached retransmission accepted")
			}
			next := callbackCall(r, 2, true)
			nextReply, err := r.callback(next)
			if err != nil || !r.recalled || r.sequence != 2 {
				t.Fatal("next recall refused after uncached replay", err)
			}
			r.recalled = false
			if replay, err := r.callback(next); err != nil || r.recalled || !bytes.Equal(replay, nextReply) {
				t.Fatal("cached replay failed after an uncached slot", err)
			}
		})
	}
}

func TestPNFSCallbackUncachedUnsupportedReplay(t *testing.T) {
	for _, code := range []uint32{6, 10044} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			r := &layoutRecall{session: bytes.Repeat([]byte{1}, 16), active: true, fh: []byte("file"), state: bytes.Repeat([]byte{2}, 16), requestLimit: 4096, responseLimit: 4096, cacheLimit: 1024}
			base := callbackCall(r, 1, true)
			binary.BigEndian.PutUint32(base[88:92], 0)
			binary.BigEndian.PutUint32(base[96:100], code)
			call := append(encoder(nil), base[:40]...)
			call.str(string(bytes.Repeat([]byte{'t'}, 1000)))
			call = append(call, base[44:100]...)
			original, err := r.callback(call)
			if err != nil || r.sequence != 1 || r.recalled || binary.BigEndian.Uint32(original[24:28]) != 10004 {
				t.Fatal("unexpected unsupported callback response", err)
			}
			replay, err := r.callback(call)
			if err != nil || !bytes.Equal(replay, original) || r.recalled {
				t.Fatal("uncached replay replaced unsupported-operation error", err)
			}
		})
	}
}
