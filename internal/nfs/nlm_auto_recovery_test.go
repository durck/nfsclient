package nfs

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise durable crash records, real RPC framing, NSM checks, and the next
// acquisition together. No TEST or LOCK may replace an old acquisition.
func TestNLMAutomaticCrashCleanup(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		for _, mode := range []string{"success", "empty", "uid", "gid", "groups", "mixed", "version", "unconfirmed", "cancel", "drop", "partial-drop", "denied", "grace", "cookie", "restart"} {
			t.Run(fmt.Sprintf("v%d/%s", version, mode), func(t *testing.T) {
				ctx := context.Background()
				cfg := Config{Version: "3", Transport: "tcp", Timeout: 300 * time.Millisecond, NLMAutoRecover: true, NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
				if version == 1 {
					cfg.Version = "2"
				}
				auth := Auth{UID: 21, GID: 22, Groups: []uint32{23, 24}}
				state, err := openNSMState(cfg.NLMStateDir, cfg.NLMClientIP, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				var saved []nsmSavedLock
				if mode != "empty" {
					for i := range 2 {
						saved = append(saved, nsmSavedLock{Version: version, Info: LockInfo{ID: uint64(i + 1), Write: true, Offset: uint64(i * 64), Length: 32}, FH: bytes.Repeat([]byte{1}, 32), Owner: bytes.Repeat([]byte{byte(i + 2)}, 16), SVID: uint32(i + 41), Auth: auth, Confirmed: true})
					}
					if mode == "mixed" {
						saved[1].Auth.UID++
					}
					if mode == "version" {
						saved[1].Version = 5 - version
					}
					if mode == "unconfirmed" {
						saved[1].Confirmed = false
					}
					state.record.Locks, state.record.Dirty, state.record.LastSVID = saved, true, 42
					if err := state.append(); err != nil {
						t.Fatal(err)
					}
				}
				state.close() // Simulate process death without an UNLOCK.
				if mode != "empty" {
					if s, err := openNSMState(cfg.NLMStateDir, cfg.NLMClientIP, "127.0.0.1"); err == nil {
						s.close()
						t.Fatal("default startup accepted crash state")
					}
				}
				var epoch atomic.Uint32
				epoch.Store(3)
				cfg.PortmapPort = nsmPeer(t, &epoch)
				var mu sync.Mutex
				var procedures []uint32
				var newOwner []byte
				var newPID uint32
				port := nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
					mu.Lock()
					defer mu.Unlock()
					d := &decoder{b: raw}
					xid := d.u32()
					d.take(8)
					if d.u32() != nlmProgram || d.u32() != version {
						t.Error("changed NLM protocol")
					}
					proc := d.u32()
					if d.u32() != 1 {
						t.Error("missing AUTH_SYS")
					}
					cred := &decoder{b: d.opaque(400)}
					cred.u32()
					cred.str()
					if cred.u32() != auth.UID || cred.u32() != auth.GID || cred.u32() != 2 || cred.u32() != 23 || cred.u32() != 24 || cred.err != nil || len(cred.b) != 0 {
						t.Error("changed cleanup credentials")
					}
					d.u32()
					d.opaque(400)
					cookie := d.opaque(1024)
					if proc == 2 && (d.u32() != 0 || d.u32() != 1) {
						t.Error("unexpected blocking/shared acquisition")
					}
					if d.str() != cfg.NLMClientIP || !bytes.Equal(d.opaque(64), bytes.Repeat([]byte{1}, 32)) {
						t.Error("changed caller or file")
					}
					owner, pid := d.opaque(1024), d.u32()
					var offset, length uint64
					if version == 1 {
						offset, length = uint64(d.u32()), uint64(d.u32())
					} else {
						offset, length = d.u64(), d.u64()
					}
					if proc == 2 {
						if len(procedures) != len(saved) || pid <= 42 && mode != "empty" || offset != 0 || length != 0 || d.u32() != 0 || d.u32() == 0 {
							t.Error("new acquisition preceded cleanup or reused an old identity")
						}
						newOwner, newPID = slices.Clone(owner), pid
					} else if proc == 4 {
						if pid == newPID && newPID != 0 {
							if !bytes.Equal(owner, newOwner) || offset != 0 || length != 0 {
								t.Error("changed new lock release")
							}
						} else {
							found := false
							for _, old := range saved {
								if old.SVID == pid && bytes.Equal(old.Owner, owner) && offset == old.Info.Offset && length == old.Info.Length {
									found = true
								}
							}
							if !found {
								t.Error("cleanup changed saved identity/range")
							}
						}
					} else {
						t.Error("cleanup sent a procedure other than UNLOCK")
					}
					if d.err != nil || len(d.b) != 0 {
						t.Error("invalid request framing")
					}
					procedures = append(procedures, proc)
					if mode == "drop" || mode == "partial-drop" && len(procedures) == 2 {
						return nil
					}
					status := uint32(0)
					if mode == "denied" {
						status = 1
					}
					if mode == "grace" {
						status = 4
					}
					if mode == "cookie" {
						cookie = []byte("incorrect")
					}
					if mode == "restart" {
						epoch.Store(5)
					}
					var body encoder
					body.opaque(cookie)
					body.u32(status)
					return append(udpReply(xid, 0)[:24], body...)
				})
				rpc, err := dialRPC(ctx, "127.0.0.1", port, cfg.Timeout, false)
				if err != nil {
					t.Fatal(err)
				}
				defer rpc.conn.Close()
				monitor, err := startNSMMode(ctx, cfg, "127.0.0.1", 0, nil, nil, true)
				if mode == "unconfirmed" {
					if err == nil {
						monitor.close()
						t.Fatal("unknown LOCK outcome admitted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if monitor != nil {
						monitor.close()
					}
				}()
				c := &Client{config: &cfg, version: cfg.Version, Auth: auth}
				n := &nlmClient{c: c, rpc: rpc, monitor: monitor, version: version, locks: make(map[uint64]*nlmLock)}
				c.nlm = n
				switch mode {
				case "uid":
					c.Auth.UID++
				case "gid":
					c.Auth.GID++
				case "groups":
					c.Auth.Groups = []uint32{24, 23}
				case "cancel":
					cancelled, cancel := context.WithCancel(ctx)
					cancel()
					ctx = cancelled
				}
				err = n.prepareAutomaticRecovery(ctx)
				if mode == "partial-drop" {
					if err == nil || !monitor.lost.Load() || len(monitor.state.record.Locks) != 1 {
						t.Fatal("partial cleanup did not retain exactly the remaining owner", err)
					}
					remaining := monitor.state.record.Locks[0].SVID
					monitor.close()
					rpc.conn.Close()
					monitor, err = startNSMMode(ctx, cfg, "127.0.0.1", 0, nil, nil, true)
					if err != nil {
						t.Fatal(err)
					}
					if len(monitor.state.record.Locks) != 1 || monitor.state.record.Locks[0].SVID != remaining {
						t.Fatal("partial progress was not durable")
					}
					retry, err := dialRPC(ctx, "127.0.0.1", port, cfg.Timeout, false)
					if err != nil {
						t.Fatal(err)
					}
					defer retry.conn.Close()
					n = &nlmClient{c: c, rpc: retry, monitor: monitor, version: version, locks: make(map[uint64]*nlmLock)}
					c.nlm = n
					if err := n.prepareAutomaticRecovery(ctx); err != nil || monitor.state.record.Dirty || len(monitor.state.record.Locks) != 0 {
						t.Fatal("fresh cleanup could not finish remaining owner", err)
					}
					mu.Lock()
					defer mu.Unlock()
					if !slices.Equal(procedures, []uint32{4, 4, 4}) {
						t.Fatal("partial recovery replayed completed work", procedures)
					}
					return
				}
				if mode == "success" || mode == "empty" {
					if err != nil || monitor.state.record.Dirty || len(n.locks) != 0 {
						t.Fatal("cleanup failed", err)
					}
					id, err := c.Lock(ctx, bytes.Repeat([]byte{1}, 32), true)
					if err != nil {
						t.Fatal("new lock refused after complete cleanup", err)
					}
					if err := c.Unlock(ctx, id); err != nil {
						t.Fatal(err)
					}
					mu.Lock()
					defer mu.Unlock()
					want := []uint32{4, 4, 2, 4}
					if mode == "empty" {
						want = []uint32{2, 4}
					}
					if !slices.Equal(procedures, want) {
						t.Fatal("unexpected mutation sequence", procedures)
					}
				} else {
					if err == nil || !monitor.lost.Load() || !monitor.state.record.Dirty || len(monitor.state.record.Locks) != 2 {
						t.Fatal("failed cleanup was not quarantined", err)
					}
					if _, err := c.Lock(context.Background(), bytes.Repeat([]byte{1}, 32), true); err == nil {
						t.Fatal("new lock allowed after failed cleanup")
					}
					mu.Lock()
					defer mu.Unlock()
					want := 0
					if mode == "drop" || mode == "denied" || mode == "grace" || mode == "cookie" || mode == "restart" {
						want = 1
					}
					if len(procedures) != want || slices.Contains(procedures, uint32(2)) {
						t.Fatal("mutation after refusal or cleanup replay", procedures)
					}
				}
			})
		}
	}
}

func TestNLMAutomaticRecoveryProfile(t *testing.T) {
	if err := validateNLMConfig(Config{NLMAutoRecover: true}); err == nil {
		t.Fatal("automatic cleanup accepted without explicit legacy identity")
	}
}
