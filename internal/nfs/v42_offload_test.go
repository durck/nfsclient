package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWriteSameRangeValidation(t *testing.T) {
	for _, tc := range []struct {
		offset, count uint64
		pattern       []byte
	}{
		{0, 0, []byte{1}}, {0, 1, nil}, {0, 1, make([]byte, 4097)},
		{^uint64(0), 1, []byte{1}}, {0, ^uint64(0), []byte{1, 2}},
	} {
		if _, err := ValidateWriteSame(tc.offset, tc.count, tc.pattern); err == nil {
			t.Fatal("invalid range accepted", tc.offset, tc.count)
		}
	}
	if n, err := ValidateWriteSame(1<<40, 3, []byte{1, 2}); err != nil || n != 6 {
		t.Fatal(n, err)
	}
}

func TestOffloadProfileIsolation(t *testing.T) {
	for _, cfg := range []Config{
		{Version: "3"}, {Version: "auto"}, {Version: "4.1"}, {Version: "4.2", Transport: "udp"},
		{Version: "4.2", Transport: "iwarp"},
	} {
		cfg.Offload = true
		if _, err := Connect(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "offload requires") {
			t.Fatal(cfg.Version, cfg.Transport, cfg.Security, err)
		}
	}
	c := &Client{config: &Config{Offload: true}, v4: &v4Client{recall: &layoutRecall{offloadEnabled: true}}}
	if _, err := c.ReadPNFSToProgress(context.Background(), []byte("file"), 0, nil, PNFSOptions{}, nil); err == nil || !strings.Contains(err.Error(), "requires --pnfs") {
		t.Fatal("offload enabled pNFS implicitly", err)
	}
}

func offloadCallback(r *layoutRecall, sequence uint32, fh, id []byte, result offloadReply) encoder {
	var e encoder
	for _, n := range []uint32{99, 0, 2, pnfsCallbackProgram, 1, 1, 0, 0, 0, 0} {
		e.u32(n)
	}
	e.str("")
	e.u32(2)
	e.u32(0)
	e.u32(2)
	e.u32(11)
	e = append(e, r.session...)
	e.u32(sequence)
	e.u32(0)
	e.u32(0)
	e.u32(1)
	e.u32(0)
	e.u32(15)
	e.opaque(fh)
	e = append(e, id...)
	e.u32(uint32(result.status))
	if result.status == 0 {
		if len(result.id) > 0 {
			e.u32(1)
			e = append(e, result.id...)
		} else {
			e.u32(0)
		}
		e.u64(result.count)
		e.u32(result.stable)
		e = append(e, result.verifier...)
	} else {
		e.u64(result.count)
	}
	return e
}

func TestOffloadCallback(t *testing.T) {
	for _, kind := range []string{"ok", "early", "wrong-file", "wrong-state", "duplicate", "conflicting", "trailing", "excess", "nested", "truncated", "failure", "cache-limit"} {
		t.Run(kind, func(t *testing.T) {
			id := bytes.Repeat([]byte{8}, 16)
			r := &layoutRecall{session: bytes.Repeat([]byte{9}, 16), minor: 2, offloadEnabled: true, offload: &offloadPending{fh: []byte("file"), id: id, length: 6}}
			fh, replyID := []byte("file"), id
			result := offloadReply{count: 6, stable: 2, verifier: []byte("verifier")}
			switch kind {
			case "early":
				r.offload.id = nil
			case "wrong-file":
				fh = []byte("other")
			case "wrong-state":
				replyID = bytes.Repeat([]byte{4}, 16)
			case "excess":
				result.count = 7
			case "nested":
				result.id = id
			case "failure":
				result.status = 5
				result.count = 2
			case "cache-limit":
				r.cacheLimit = 32
			}
			call := offloadCallback(r, 1, fh, replyID, result)
			if kind == "trailing" {
				call = append(call, 0)
			}
			if kind == "truncated" {
				call = call[:len(call)-1]
			}
			reply, err := r.callback(call)
			malformed := kind == "trailing" || kind == "truncated" || kind == "excess" || kind == "nested"
			if (err != nil) != malformed {
				t.Fatal(err)
			}
			accepted := kind == "ok" || kind == "duplicate" || kind == "conflicting" || kind == "failure"
			if (r.offload.result != nil) != accepted {
				t.Fatal("completion publication", r.offload.result)
			}
			if malformed && r.sequence != 0 {
				t.Fatal("malformed callback consumed slot")
			}
			if kind == "early" && binary.BigEndian.Uint32(reply[24:28]) != 10008 {
				t.Fatal("early callback needs DELAY")
			}
			if kind == "duplicate" {
				again, err := r.callback(call)
				if err != nil || !bytes.Equal(reply, again) {
					t.Fatal("callback replay", err)
				}
			}
			if kind == "conflicting" {
				result.count = 4
				if _, err := r.callback(offloadCallback(r, 2, fh, replyID, result)); err == nil || r.offload.result.count != 6 {
					t.Fatal("conflicting completion accepted")
				}
			}
		})
	}
}

func TestOffloadZeroCache(t *testing.T) {
	id := bytes.Repeat([]byte{8}, 16)
	r := &layoutRecall{session: bytes.Repeat([]byte{9}, 16), minor: 2, offloadEnabled: true, requestLimit: 4096, responseLimit: 4096, offload: &offloadPending{fh: []byte("file"), id: id, length: 6}}
	call := offloadCallback(r, 1, []byte("file"), id, offloadReply{count: 6, stable: 2, verifier: []byte("verifier")})
	// An explicit caching request cannot fit the negotiated zero-sized cache.
	reply, err := r.callback(call)
	if err != nil || binary.BigEndian.Uint32(reply[24:28]) != 10067 || r.sequence != 0 || r.offload.result != nil {
		t.Fatal("zero cache ignored", err)
	}
	binary.BigEndian.PutUint32(call[88:92], 0)
	reply, err = r.callback(call)
	if err != nil || binary.BigEndian.Uint32(reply[24:28]) != 0 || r.offload.result == nil || !r.uncached {
		t.Fatal("uncached completion", err)
	}
	reply, err = r.callback(call)
	if err != nil || binary.BigEndian.Uint32(reply[24:28]) != 10068 || r.offload.result.count != 6 {
		t.Fatal("uncached retransmission", err)
	}
}

func TestOffloadLifecycle(t *testing.T) {
	runOffloadLifecycle(t, "")
}

func runOffloadLifecycle(t *testing.T, security string) {
	for _, copyMode := range []bool{false, true} {
		for _, kind := range []string{"callback", "early", "poll", "retired-state", "cancel", "cancel-failed", "bad-status", "callback-failure", "truncated-initial"} {
			t.Run(fmt.Sprintf("copy=%t/%s", copyMode, kind), func(t *testing.T) {
				var c *Client
				var protectedCallback func(encoder) error
				calls, cancels, polls := 0, 0, 0
				id := bytes.Repeat([]byte{8}, 16)
				callback := func(seq uint32) {
					result := offloadReply{count: 6, stable: 2, verifier: []byte("verifier")}
					if kind == "callback-failure" {
						result.status = 5
						result.count = 2
					}
					call := offloadCallback(c.v4.recall, seq, []byte("destination"), id, result)
					var err error
					if protectedCallback != nil {
						err = protectedCallback(call)
					} else {
						_, err = c.v4.recall.callback(call)
					}
					if err != nil {
						t.Error(err)
					}
				}
				c = copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
					var e encoder
					switch code {
					case 32:
						return nil, 0, nil
					case 60, 70:
						calls++
						if code == 60 {
							d.take(32)
							d.u64()
							d.u64()
							d.u64()
							if !d.boolean() || d.boolean() || d.u32() != 0 {
								return nil, 0, errors.New("wrong async COPY requirements")
							}
						} else {
							d.take(16)
							d.u32()
							for range 4 {
								d.u64()
							}
							d.u32()
							d.u64()
							d.opaque(4096)
						}
						if kind == "truncated-initial" {
							return []byte{0}, 0, nil
						}
						if kind == "early" {
							callback(1)
						}
						e.u32(1)
						e = append(e, id...)
						e.u64(0)
						e.u32(0)
						e = append(e, []byte("verifier")...)
						if code == 60 {
							e.u32(1)
							e.u32(0)
						}
					case 67:
						polls++
						if !bytes.Equal(d.take(16), id) {
							t.Error("poll identity")
						}
						if kind == "callback" || kind == "early" || kind == "poll" || kind == "callback-failure" || kind == "retired-state" {
							seq := uint32(1)
							if kind == "early" {
								seq = 2
							}
							callback(seq)
						}
						if kind == "retired-state" {
							return nil, 10025, nil
						}
						e.u64(6)
						if kind == "bad-status" {
							e.u32(2)
						} else if kind == "poll" {
							e.u32(1)
							e.u32(0)
						} else {
							e.u32(0)
						}
					case 66:
						cancels++
						if !bytes.Equal(d.take(16), id) {
							t.Error("cancel identity")
						}
						if kind == "cancel-failed" {
							return nil, 5, nil
						}
					default:
						return nil, 0, fmt.Errorf("unexpected op %d", code)
					}
					return e, 0, nil
				})
				c.v4.recall = &layoutRecall{session: bytes.Repeat([]byte{9}, 16), minor: 2, offloadEnabled: true}
				if security != "" {
					protectedCallback = offloadMITCallbacks(t, c, security)
				}
				wait := 1200 * time.Millisecond
				var n uint64
				var err error
				if copyMode {
					n, err = c.CopyRangeAsync(context.Background(), []byte("source"), []byte("destination"), 0, 0, 6, wait)
				} else {
					n, err = c.WriteSame(context.Background(), []byte("destination"), 0, 3, []byte{1, 2}, wait)
				}
				good := kind == "callback" || kind == "early" || kind == "poll" || kind == "retired-state"
				if (err == nil) != good || good && n != 6 || calls != 1 {
					t.Fatal(n, err, calls)
				}
				if (kind == "cancel" || kind == "cancel-failed") && (cancels != 1 || !errors.Is(err, context.DeadlineExceeded)) {
					t.Fatal(cancels, err)
				}
				if kind == "callback-failure" && (n != 2 || !errors.Is(err, Status(5))) {
					t.Fatal(n, err)
				}
				if kind == "bad-status" && (polls != 1 || cancels != 0 || !c.v4.stateLost.Load()) {
					t.Fatal(polls, cancels, err)
				}
				if kind == "truncated-initial" && (polls != 0 || cancels != 0) {
					t.Fatal("unknown initial operation replayed")
				}
			})
		}
	}
}

func TestWriteSameWire(t *testing.T) {
	for _, kind := range []string{"stable", "unstable", "short", "unsupported", "bad-count", "bad-stable", "bad-array", "truncated", "bad-verifier"} {
		t.Run(kind, func(t *testing.T) {
			calls, commits := 0, 0
			c := copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 70:
					calls++
					if !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) || d.u32() != 2 || d.u64() != 1<<40 || d.u64() != 2 || d.u64() != 3 || d.u64() != ^uint64(0) || d.u32() != 0 || d.u64() != 0 || !bytes.Equal(d.opaque(4096), []byte{0xab, 0xcd}) {
						return nil, 0, errors.New("incorrect WRITE_SAME arguments")
					}
					if kind == "unsupported" {
						return nil, 10004, nil
					}
					if kind == "bad-array" {
						e.u32(2)
						return e, 0, nil
					}
					e.u32(0)
					n := uint64(6)
					if kind == "short" {
						n = 4
					}
					if kind == "bad-count" {
						n = 7
					}
					e.u64(n)
					stable := uint32(2)
					if kind == "unstable" || kind == "bad-verifier" {
						stable = 0
					}
					if kind == "bad-stable" {
						stable = 3
					}
					e.u32(stable)
					if kind != "truncated" {
						e = append(e, []byte("verifier")...)
					}
				case 5:
					commits++
					if d.u64() != 1<<40 || d.u32() != 0 {
						return nil, 0, errors.New("incorrect COMMIT")
					}
					e = append(e, []byte("verifier")...)
					if kind == "bad-verifier" {
						e[0]++
					}
				default:
					return nil, 0, errors.New("unexpected operation")
				}
				return e, 0, nil
			})
			c.v4.recall = &layoutRecall{offloadEnabled: true}
			n, err := c.WriteSame(context.Background(), []byte("destination"), 1<<40, 3, []byte{0xab, 0xcd}, time.Second)
			good := kind == "stable" || kind == "unstable"
			if (err == nil) != good || good && n != 6 || calls != 1 {
				t.Fatal(n, err, calls)
			}
			wantCommit := kind == "unstable" || kind == "bad-verifier"
			if (commits == 1) != wantCommit {
				t.Fatal("COMMIT", commits)
			}
			if kind == "short" && (n != 4 || !strings.Contains(err.Error(), "no continuation")) {
				t.Fatal(n, err)
			}
		})
	}
}
