package nfs

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"nfsclient/internal/testutil/loopback"
)

func TestNLMCallbackIdentityAndDuplicates(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		m := &nsmMonitor{cfg: Config{NLMClientIP: "127.0.0.1"}}
		var replies []NLMStatus
		cb := &nlmCallbacks{version: version, monitor: m, entries: make(map[string]*nlmPending), send: func(_ context.Context, cookie []byte, status NLMStatus, _ Auth) error {
			if !bytes.Equal(cookie, []byte("server-cookie")) {
				t.Error("callback cookie not echoed")
			}
			replies = append(replies, status)
			return nil
		}}
		l := &nlmLock{fh: bytes.Repeat([]byte{7}, 32), owner: []byte("owner"), svid: 123, info: LockInfo{Write: true, Offset: 8, Length: 8}}
		p := cb.register(l)
		args := func(owner string) encoder {
			var e encoder
			e.opaque([]byte("server-cookie"))
			if l.info.Write {
				e.u32(1)
			} else {
				e.u32(0)
			}
			e.str("127.0.0.1")
			e.opaque(l.fh)
			e.opaque([]byte(owner))
			e.u32(l.svid)
			encodeNLMRange(&e, version, l.info.Offset, l.info.Length)
			return e
		}
		cb.dispatch(10, &decoder{b: args("wrong")})
		if len(replies) != 0 || len(p.done) != 0 {
			t.Fatal("unknown identity accepted")
		}
		for _, change := range []func(*nlmLock){
			func(l *nlmLock) { l.fh = bytes.Repeat([]byte{8}, 32) },
			func(l *nlmLock) { l.svid++ },
			func(l *nlmLock) { l.info.Write = false },
			func(l *nlmLock) { l.info.Offset++ },
			func(l *nlmLock) { l.info.Length++ },
		} {
			saved := *l
			change(l)
			cb.dispatch(10, &decoder{b: args("owner")})
			*l = saved
			if len(replies) != 0 || len(p.done) != 0 {
				t.Fatal("mismatched grant accepted")
			}
		}
		bad := append(args("owner"), 0)
		if cb.dispatch(10, &decoder{b: bad}) != 4 || len(replies) != 0 {
			t.Fatal("malformed callback accepted")
		}
		for range 2 {
			if cb.dispatch(10, &decoder{b: args("owner")}) != 0 {
				t.Fatal("grant rejected")
			}
		}
		if len(replies) != 2 || replies[0] != 0 || replies[1] != 0 || len(p.done) != 1 {
			t.Fatal("duplicate grant changed outcome", replies)
		}
		cb.disable(l)
		cb.dispatch(10, &decoder{b: args("owner")})
		if replies[2] != 1 {
			t.Fatal("cancelled grant accepted")
		}
		cb.remove(l)
		l.info.Write, l.info.Length = false, LockToEOF
		if version == 4 {
			l.info.Offset = 1 << 33
		}
		p = cb.register(l)
		if cb.dispatch(10, &decoder{b: args("owner")}) != 0 || len(p.done) != 1 || replies[3] != 0 {
			t.Fatal("shared EOF/high range not granted")
		}
	}
}

func TestNLMNativeWaitLifecycle(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		for _, mode := range []string{"grant", "grant-cancel-race", "immediate", "cancel", "cancel-denied", "drop-cancel", "drop-unlock", "drop-lock", "grant-send-failure", "epoch-loss", "sync-grant", "sync-grant-cancel-race", "sync-grant-send-failure"} {
			t.Run(string(rune('0'+version))+"/"+mode, func(t *testing.T) {
				synchronous := strings.HasPrefix(mode, "sync-")
				mode = strings.TrimPrefix(mode, "sync-")
				var epoch atomic.Uint32
				epoch.Store(3)
				var locks, cancels, unlocks, grants atomic.Int32
				var n *nlmClient
				port := nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
					d := &decoder{b: raw}
					xid := d.u32()
					d.take(16)
					procedure := d.u32()
					d.u32()
					d.opaque(400)
					d.u32()
					d.opaque(400)
					var body encoder
					if procedure != 0 {
						cookie := d.opaque(1024)
						var exclusive uint32
						if procedure == 2 || procedure == 3 {
							if d.u32() != 1 {
								t.Error("nonblocking native request")
							}
							exclusive = d.u32()
						}
						tuple := append([]byte(nil), d.b...)
						d.opaque(1024)
						d.opaque(64)
						d.opaque(1024)
						d.u32()
						if version == 1 {
							d.u32()
							d.u32()
						} else {
							d.u64()
							d.u64()
						}
						status := uint32(0)
						switch procedure {
						case 2:
							locks.Add(1)
							if d.u32() != 0 || d.u32() != 1 {
								t.Error("bad epoch/reclaim")
							}
							if mode == "drop-lock" {
								return nil
							}
							if mode != "immediate" {
								status = 3
							}
							if mode == "grant" || mode == "grant-send-failure" || mode == "grant-cancel-race" {
								// Deliberately deliver before the initial BLOCKED response.
								var grant encoder
								grant.opaque([]byte("new-server-cookie"))
								grant.u32(exclusive)
								grant = append(grant, tuple[:len(tuple)-8]...)
								deliver := func() {
									if !synchronous {
										n.callbacks().dispatch(10, &decoder{b: grant})
										return
									}
									var call encoder
									for _, v := range []uint32{123, 0, 2, nlmProgram, version, 5, 0, 0, 0, 0} {
										call.u32(v)
									}
									n.monitor.respond(append(call, grant...), func(reply []byte) error {
										grants.Add(1)
										if mode == "grant-cancel-race" {
											time.Sleep(300 * time.Millisecond)
										}
										if mode == "grant-send-failure" {
											return errors.New("GRANTED response lost")
										}
										d := &decoder{b: reply}
										d.take(20)
										if d.u32() != 0 || !bytes.Equal(d.opaque(1024), []byte("new-server-cookie")) || d.u32() != 0 || len(d.b) != 0 || d.err != nil {
											t.Error("invalid synchronous grant reply")
										}
										return nil
									})
								}
								if mode == "grant-cancel-race" {
									go func() { time.Sleep(10 * time.Millisecond); deliver() }()
								} else {
									deliver()
								}
							}
							if mode == "epoch-loss" {
								epoch.Store(5)
							}
						case 3:
							cancels.Add(1)
							if mode == "drop-cancel" {
								return nil
							}
							if mode == "cancel-denied" || mode == "grant-cancel-race" {
								status = 1
							}
						case 4:
							unlocks.Add(1)
							if mode == "drop-unlock" {
								return nil
							}
						default:
							t.Error("unexpected procedure", procedure)
						}
						if d.err != nil || len(d.b) != 0 {
							t.Error("malformed mutation")
						}
						body.opaque(cookie)
						body.u32(status)
					}
					return append(udpReply(xid, 0)[:24], body...)
				})
				cfg := Config{Version: "3", Transport: "tcp", Timeout: time.Second, PortmapPort: nsmPeer(t, &epoch), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
				if version == 1 {
					cfg.Version = "2"
				}
				rpc, err := dialRPC(context.Background(), "127.0.0.1", port, cfg.Timeout, false)
				if err != nil {
					t.Fatal(err)
				}
				c := &Client{version: cfg.Version, config: &cfg, Auth: Auth{UID: 21, GID: 22}}
				n = &nlmClient{c: c, rpc: rpc, version: version, locks: make(map[uint64]*nlmLock)}
				tcp, udp, err := loopback.Pair()
				if err != nil {
					t.Fatal(err)
				}
				listenPort := tcp.Addr().(*net.TCPAddr).Port
				tcp.Close()
				udp.Close()
				n.monitor, err = startNSM(context.Background(), cfg, "127.0.0.1", listenPort, func() { rpc.conn.Close() }, nil)
				if err != nil {
					rpc.conn.Close()
					t.Fatal(err)
				}
				c.nlm = n
				defer c.Close()
				n.callbacks().send = func(context.Context, []byte, NLMStatus, Auth) error {
					grants.Add(1)
					if mode == "grant-cancel-race" {
						time.Sleep(300 * time.Millisecond)
					}
					if mode == "grant-send-failure" {
						return errors.New("grant send failed")
					}
					return nil
				}
				id, err := c.LockRangeNativeWait(context.Background(), bytes.Repeat([]byte{1}, 32), true, 8, 8, 250*time.Millisecond)
				switch mode {
				case "grant", "immediate":
					if err != nil || id == 0 || !n.locks[id].confirmed {
						t.Fatal("not confirmed", id, err)
					}
					if mode == "grant" && grants.Load() != 1 {
						t.Fatal("callback absent")
					}
					if err := c.Unlock(context.Background(), id); err != nil {
						t.Fatal(err)
					}
				case "cancel", "cancel-denied", "grant-cancel-race":
					if id != 0 || !errors.Is(err, context.DeadlineExceeded) || n.monitor.state.record.Dirty || cancels.Load() != 1 || unlocks.Load() != 1 {
						t.Fatal("incomplete cancellation", id, err, cancels.Load(), unlocks.Load())
					}
				default:
					if id == 0 || !errors.Is(err, ErrLockUncertain) || !n.monitor.state.record.Dirty {
						t.Fatal("lost uncertainty", id, err)
					}
					if n.monitor.state.record.Locks[0].Confirmed {
						t.Fatal("pending request recoverable as held")
					}
					if mode == "drop-lock" && (cancels.Load() != 0 || unlocks.Load() != 0) || mode == "drop-cancel" && unlocks.Load() != 0 {
						t.Fatal("replayed unknown mutation")
					}
				}
				if locks.Load() != 1 {
					t.Fatal("LOCK replay", locks.Load())
				}
			})
		}
	}
}
