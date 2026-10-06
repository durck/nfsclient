package nfs

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestNLMRetainedState(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		for _, mode := range []string{"success", "denied", "grace", "blocked", "drop-lock", "cookie", "drop-unlock"} {
			t.Run(string(rune('0'+version))+"/"+mode, func(t *testing.T) {
				var state atomic.Uint32
				state.Store(3)
				var locks, unlocks atomic.Int32
				var owner []byte
				var svid uint32
				port := nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
					d := &decoder{b: raw}
					xid := d.u32()
					d.take(8)
					if d.u32() != nlmProgram || d.u32() != version {
						t.Error("wrong NLM program/version")
					}
					procedure := d.u32()
					flavor := d.u32()
					cred := &decoder{b: d.opaque(400)}
					d.u32()
					d.opaque(400)
					var body encoder
					if procedure != 0 {
						if flavor != 1 {
							t.Error("wrong lock credentials")
						}
						cred.u32()
						cred.str()
						if cred.u32() != 21 || cred.u32() != 22 {
							t.Error("mutated retained identity")
						}
						cookie := d.opaque(1024)
						if procedure == 2 {
							locks.Add(1)
							if d.u32() != 0 || d.u32() != 1 {
								t.Error("blocking or shared request")
							}
						} else if procedure == 4 {
							unlocks.Add(1)
						} else {
							t.Error("unexpected mutation procedure")
						}
						if d.str() != "127.0.0.1" || !bytes.Equal(d.opaque(64), bytes.Repeat([]byte{1}, 32)) {
							t.Error("changed caller/handle")
						}
						oh, pid := d.opaque(1024), d.u32()
						if procedure == 2 {
							owner, svid = append([]byte{}, oh...), pid
						} else if !bytes.Equal(owner, oh) || svid != pid {
							t.Error("unlock changed owner")
						}
						if version == 1 {
							//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
							if d.u32() != 0 || d.u32() != 0 {
								t.Error("wrong EOF range")
							}
						} else {
							//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
							if d.u64() != 0 || d.u64() != 0 {
								t.Error("wrong EOF range")
							}
						}
						if procedure == 2 && (d.u32() != 0 || d.u32() != 1) {
							t.Error("reclaim or wrong NSM epoch")
						}
						if d.err != nil || len(d.b) != 0 {
							t.Error("invalid lock request")
						}
						if mode == "drop-lock" && procedure == 2 || mode == "drop-unlock" && procedure == 4 && unlocks.Load() == 1 {
							return nil
						}
						if mode == "cookie" {
							cookie = []byte("wrong")
						}
						body.opaque(cookie)
						status := uint32(0)
						if mode == "denied" {
							status = 1
						}
						if mode == "grace" {
							status = 4
						}
						if mode == "blocked" {
							status = 3
						}
						body.u32(status)
					}
					return append(udpReply(xid, 0)[:24], body...)
				})
				cfg := Config{Version: "3", Transport: "tcp", Timeout: 200 * time.Millisecond, PortmapPort: nsmPeer(t, &state), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
				if version == 1 {
					cfg.Version = "2"
				}
				rpc, err := dialRPC(context.Background(), "127.0.0.1", port, cfg.Timeout, false)
				if err != nil {
					t.Fatal(err)
				}
				c := &Client{version: cfg.Version, config: &cfg, Auth: Auth{UID: 21, GID: 22}}
				n := &nlmClient{c: c, rpc: rpc, version: version, locks: make(map[uint64]*nlmLock)}
				n.monitor, err = startNSM(context.Background(), cfg, "127.0.0.1", 0, func() { rpc.conn.Close() }, func(ctx context.Context) error { _, err := rpc.call(ctx, nlmProgram, version, 0, nil, nil); return err })
				if err != nil {
					rpc.conn.Close()
					t.Fatal(err)
				}
				c.nlm = n
				defer c.Close()
				fh := bytes.Repeat([]byte{1}, 32)
				id, err := c.Lock(context.Background(), fh, true)
				if mode == "denied" || mode == "grace" {
					if id != 0 || err == nil || len(c.Locks()) != 0 || n.monitor.state.record.Dirty {
						t.Fatal("clean refusal retained state", id, err)
					}
					return
				}
				if mode == "drop-lock" || mode == "cookie" || mode == "blocked" {
					if id == 0 || !errors.Is(err, ErrLockUncertain) || len(c.Locks()) != 1 || !c.Locks()[0].Uncertain {
						t.Fatal("uncertain acquisition lost", id, err)
					}
					if err := c.Unlock(context.Background(), id); !errors.Is(err, ErrLockUncertain) {
						t.Fatal("uncertain unlock accepted", err)
					}
					if locks.Load() != 1 || unlocks.Load() != 0 {
						t.Fatal("mutation replayed")
					}
					return
				}
				if err != nil || id == 0 || len(c.Locks()) != 1 || !n.monitor.state.record.Dirty {
					t.Fatal(id, err)
				}
				if err := n.checkIO(fh, true); err != nil {
					t.Fatal(err)
				}
				c.Auth.UID = 99
				if err := n.checkIO(fh, true); err == nil {
					t.Fatal("different identity used lock")
				}
				err = c.Unlock(context.Background(), id) // Uses saved credentials.
				if mode == "drop-unlock" {
					if !errors.Is(err, ErrLockUncertain) || !c.Locks()[0].Uncertain || !n.monitor.state.record.Dirty {
						t.Fatal("uncertain unlock lost", err)
					}
				} else if err != nil || len(c.Locks()) != 0 || n.monitor.state.record.Dirty {
					t.Fatal("unlock not finalized", err)
				}
				if locks.Load() != 1 || unlocks.Load() != 1 {
					t.Fatal("mutation count changed")
				}
				if mode == "drop-unlock" {
					n.monitor.close()
					rpc.conn.Close()
					c.nlm = nil
					retryRPC, err := dialRPC(context.Background(), "127.0.0.1", port, cfg.Timeout, false)
					if err != nil {
						t.Fatal(err)
					}
					defer retryRPC.conn.Close()
					monitor, err := startNSMMode(context.Background(), cfg, "127.0.0.1", 0, nil, nil, true)
					if err != nil {
						t.Fatal(err)
					}
					defer monitor.close()
					recovery := &nlmClient{c: c, rpc: retryRPC, monitor: monitor, version: version, locks: make(map[uint64]*nlmLock)}
					count, err := recovery.recoverSavedLocks(context.Background())
					if err != nil || count != 1 || monitor.state.record.Dirty || len(monitor.state.record.Locks) != 0 || unlocks.Load() != 2 || locks.Load() != 1 {
						t.Fatal("explicit recovery after lost UNLOCK", count, err)
					}
				}
			})
		}
	}
}
