package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// A restart must preserve every recorded owner and range and may send only one
// reclaim per lock. The journal must quarantine an unknown wire outcome.
func TestNLMReclaimJournalAndWire(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		for _, mode := range []string{"success", "same-epoch", "skipped-epoch", "changed-owner", "changed-state", "late", "blocked", "drop", "cookie", "truncated", "restart-again", "second-denied"} {
			t.Run(string(rune('0'+version))+"/"+mode, func(t *testing.T) {
				ctx := context.Background()
				var epoch atomic.Uint32
				epoch.Store(5)
				if mode == "same-epoch" {
					epoch.Store(3)
				}
				if mode == "skipped-epoch" {
					epoch.Store(7)
				}
				cfg := Config{Version: "3", Transport: "tcp", Timeout: 200 * time.Millisecond, NLMReclaim: true, PortmapPort: nsmPeer(t, &epoch), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
				if version == 1 {
					cfg.Version = "2"
				}
				state, err := openNSMState(cfg.NLMStateDir, cfg.NLMClientIP, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				old := &nlmClient{version: version, nextID: 9, locks: map[uint64]*nlmLock{}, monitor: &nsmMonitor{state: state, peer: "127.0.0.1", peerState: 3}}
				for i := uint64(1); i <= 2; i++ {
					old.locks[i] = &nlmLock{info: LockInfo{ID: i, Write: i == 2, Offset: i * 100, Length: 51}, fh: bytes.Repeat([]byte{byte(i)}, 32), owner: bytes.Repeat([]byte{byte(i + 10)}, 16), svid: uint32(i + 40), auth: Auth{UID: 21, GID: 22, Groups: []uint32{23}}, confirmed: true, blocking: true}
				}
				state.record.LastSVID = 42
				if err := old.saveLocks(); err != nil {
					t.Fatal(err)
				}
				state.close()
				var calls atomic.Int32
				var journalFile atomic.Pointer[os.File]
				port := nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
					d := &decoder{b: raw}
					xid := d.u32()
					d.take(8)
					if d.u32() != nlmProgram || d.u32() != version || d.u32() != 2 {
						t.Error("unexpected NLM request")
					}
					if d.u32() != 1 {
						t.Error("wrong auth flavor")
					}
					cred := &decoder{b: d.opaque(400)}
					cred.u32()
					cred.str()
					if cred.u32() != 21 || cred.u32() != 22 || cred.u32() != 1 || cred.u32() != 23 || cred.err != nil || len(cred.b) != 0 {
						t.Error("changed lock credentials")
					}
					d.u32()
					d.opaque(400)
					cookie := d.opaque(1024)
					id := uint64(calls.Add(1))
					l := old.locks[id]
					if l == nil {
						t.Error("replayed reclaim")
						return nil
					}
					write := uint32(0)
					if l.info.Write {
						write = 1
					}
					if d.u32() != 0 || d.u32() != write || d.str() != cfg.NLMClientIP || !bytes.Equal(d.opaque(64), l.fh) || !bytes.Equal(d.opaque(1024), l.owner) || d.u32() != l.svid {
						t.Error("changed owner/handle/mode")
					}
					var offset, length uint64
					if version == 1 {
						offset, length = uint64(d.u32()), uint64(d.u32())
					} else {
						offset, length = d.u64(), d.u64()
					}
					if offset != l.info.Offset || length != l.info.Length || d.u32() != 1 || d.u32() != 1 || d.err != nil || len(d.b) != 0 {
						t.Error("changed range, local epoch or non-reclaim LOCK")
					}
					// Read the persisted journal while the request is in flight.
					file := journalFile.Load()
					info, readErr := file.Stat()
					if readErr != nil {
						t.Error(readErr)
						return nil
					}
					data := make([]byte, info.Size())
					if _, readErr = file.ReadAt(data, 0); readErr != nil {
						t.Error(readErr)
						return nil
					}
					var latest nsmRecord
					for len(data) > 0 {
						if len(data) < 4 {
							t.Error("truncated journal")
							return nil
						}
						size := int(binary.BigEndian.Uint32(data[:4]))
						if size < 1 || len(data) < 4+size+32 {
							t.Error("truncated journal record")
							return nil
						}
						if err := json.Unmarshal(data[4:4+size], &latest); err != nil {
							t.Error(err)
							return nil
						}
						data = data[4+size+32:]
					}
					uncertain := false
					for _, saved := range latest.Locks {
						if saved.Info.ID == id && !saved.Confirmed {
							uncertain = true
						}
					}
					if !uncertain {
						t.Error("LOCK sent before durable uncertainty")
					}
					if mode == "drop" {
						return nil
					}
					if mode == "cookie" {
						cookie = []byte("wrong")
					}
					if mode == "restart-again" {
						epoch.Store(7)
					}
					var body encoder
					body.opaque(cookie)
					status := uint32(0)
					if mode == "late" {
						status = 4
					}
					if mode == "blocked" {
						status = 3
					}
					if mode == "second-denied" && id == 2 {
						status = 1
					}
					if mode != "truncated" {
						body.u32(status)
					}
					return append(udpReply(xid, 0)[:24], body...)
				})
				rpc, err := dialRPC(ctx, "127.0.0.1", port, cfg.Timeout, false)
				if err != nil {
					t.Fatal(err)
				}
				defer rpc.conn.Close()
				monitor, err := startNSMMode(ctx, cfg, "127.0.0.1", 0, func() { rpc.conn.Close() }, nil, true)
				if err != nil {
					t.Fatal(err)
				}
				defer monitor.close()
				journalFile.Store(monitor.state.file)
				n := &nlmClient{rpc: rpc, monitor: monitor, version: version, locks: map[uint64]*nlmLock{}}
				if mode == "changed-owner" {
					monitor.state.record.Locks[0].Owner = bytes.Repeat([]byte{99}, 16)
				}
				if mode == "changed-state" {
					monitor.state.record.State += 2
				}
				err = n.reclaimSavedLocks(ctx, old)
				if mode == "success" {
					if err != nil || calls.Load() != 2 || n.nextID != 9 || monitor.lost.Load() || monitor.state.record.State != 1 {
						t.Fatal("reclaim failed", err, calls.Load())
					}
					for id, l := range n.locks {
						if !l.confirmed || l.info != old.locks[id].info || l.blocking {
							t.Fatal("reclaimed inventory changed")
						}
					}
				} else if err == nil {
					t.Fatal("unsafe reclaim accepted")
				}
				preflight := mode == "same-epoch" || mode == "skipped-epoch" || mode == "changed-owner" || mode == "changed-state"
				want := int32(1)
				if preflight {
					want = 0
				}
				if mode == "success" || mode == "second-denied" {
					want = 2
				}
				if calls.Load() != want {
					t.Fatal("unexpected reclaim count", calls.Load(), want)
				}
				monitor.close()
				reopened, openErr := openNSMStateMode(cfg.NLMStateDir, cfg.NLMClientIP, "127.0.0.1", true)
				unknown := mode == "drop" || mode == "cookie" || mode == "truncated" || mode == "blocked" || mode == "restart-again"
				if reopened != nil {
					reopened.close()
				}
				if unknown && openErr == nil || !unknown && openErr != nil {
					t.Fatal("journal quarantine mismatch", openErr)
				}
			})
		}
	}
}

func TestNLMReclaimLocalRefusals(t *testing.T) {
	for _, mode := range []string{"disabled", "empty", "unconfirmed", "uncertain", "identity", "attempted", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Version: "3", NLMReclaim: true}
			c := &Client{version: "3", config: &cfg, Auth: Auth{UID: 21}}
			l := &nlmLock{info: LockInfo{ID: 1}, confirmed: true, auth: c.Auth, owner: []byte{1}, fh: []byte{2}, svid: 3}
			c.nlm = &nlmClient{locks: map[uint64]*nlmLock{1: l}}
			ctx := context.Background()
			switch mode {
			case "disabled":
				cfg.NLMReclaim = false
			case "empty":
				delete(c.nlm.locks, 1)
			case "unconfirmed":
				l.confirmed = false
			case "uncertain":
				l.info.Uncertain = true
			case "identity":
				c.Auth.UID++
			case "attempted":
				c.nlm.reclaimAttempted = true
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if fresh, err := c.ReclaimLocks(ctx); err == nil || fresh != nil {
				t.Fatal("unsafe reclaim accepted")
			}
			if mode == "canceled" {
				if _, err := c.ReclaimLocks(ctx); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
		})
	}
	if err := validateNLMConfig(Config{NLMReclaim: true}); err == nil {
		t.Fatal("reclaim without monitored profile accepted")
	}
}
