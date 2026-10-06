package nfs

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// Model statd acknowledging immediately while its separate lockd callback is
// withheld. Releasing that callback after LOCK destroys a fresh lock as well as
// stale ones: the notification names a host, not an individual lock owner.
func TestNSMNotifyDelayedCleanupQuarantinesNewLocks(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			cfg := Config{Version: "3", Transport: "tcp", Timeout: time.Second, NLMAutoRecover: true, NLMAutoNotify: true, NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
			if version == 1 {
				cfg.Version = "2"
			}
			saved := crashNotifySaved(version)
			s, err := openNSMState(cfg.NLMStateDir, cfg.NLMClientIP, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			s.record.Locks, s.record.Dirty, s.record.LastSVID = []nsmSavedLock{saved}, true, saved.SVID
			if err := s.append(); err != nil {
				t.Fatal(err)
			}
			s.close()
			var epoch, notifications, locks, unlocks atomic.Uint32
			var held, pendingCleanup atomic.Bool
			held.Store(true)
			epoch.Store(3)
			cfg.PortmapPort = nsmNotifyPeer(t, &epoch, func(d *decoder) encoder {
				if d.str() != cfg.NLMClientIP || d.u32() != 3 {
					t.Error("notification identity or epoch changed")
				}
				notifications.Add(1)
				pendingCleanup.Store(true)
				return encoder{} // Receipt precedes deferred host-wide cleanup.
			})
			port := nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
				d := &decoder{b: raw}
				xid := d.u32()
				d.take(8)
				program, wireVersion, proc := d.u32(), d.u32(), d.u32()
				d.u32()
				d.opaque(400)
				d.u32()
				d.opaque(400)
				cookie := d.opaque(1024)
				if program != nlmProgram || wireVersion != version {
					t.Error("wrong NLM endpoint")
				}
				switch proc {
				case 2:
					locks.Add(1)
					held.Store(true)
				case 4:
					unlocks.Add(1)
					held.Store(false)
				default:
					t.Errorf("unexpected lock procedure %d", proc)
				}
				var body encoder
				body.opaque(cookie)
				body.u32(0)
				return append(udpReply(xid, 0)[:24], body...)
			})
			ctx := context.Background()
			for restart := range 3 {
				m, err := startNSMMode(ctx, cfg, "127.0.0.1", 0, nil, nil, true)
				if err != nil {
					t.Fatal(err)
				}
				rpc, err := dialRPC(ctx, "127.0.0.1", port, cfg.Timeout, false)
				if err != nil {
					m.close()
					t.Fatal(err)
				}
				c := &Client{config: &cfg, version: cfg.Version, Auth: saved.Auth}
				n := &nlmClient{c: c, rpc: rpc, monitor: m, version: version, locks: map[uint64]*nlmLock{}}
				c.nlm = n
				if err := n.prepareAutomaticRecovery(ctx); !errors.Is(err, ErrNSMNotificationUnverified) {
					t.Errorf("restart %d: void acknowledgement incorrectly proved lockd cleanup", restart)
				}
				if !m.state.record.NotifyAcknowledged || m.state.record.NotifyEpoch != 3 {
					t.Errorf("restart %d: receipt or quarantine lost", restart)
				}
				if _, err := c.Lock(ctx, saved.FH, true); err == nil {
					t.Errorf("restart %d: new LOCK admitted before deferred cleanup", restart)
				}
				// Deliver the queued host-wide cleanup only after the fresh LOCK
				// attempt. No sleeps or assumptions about scheduler timing.
				if restart == 1 && pendingCleanup.Swap(false) && held.Swap(false) {
					t.Error("delayed notification destroyed a fresh acknowledged lock")
				}
				m.close()
				rpc.conn.Close()
			}
			if notifications.Load() != 1 || locks.Load() != 0 || unlocks.Load() != 1 {
				t.Fatalf("quarantine violated: notifications=%d locks=%d cleanup=%d", notifications.Load(), locks.Load(), unlocks.Load())
			}
		})
	}
}

func TestNSMNotificationJournalQuarantine(t *testing.T) {
	for _, mode := range []string{"legacy-cleared", "receipt-regressed", "clean-v1", "clean-v2"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			s, err := openNSMState(dir, "127.0.0.1", "127.0.0.2")
			if err != nil {
				t.Fatal(err)
			}
			if mode == "clean-v1" {
				s.record.Version = 1
			}
			if mode == "legacy-cleared" || mode == "receipt-regressed" {
				s.record.NotifyEpoch = 3
				if err := s.append(); err != nil {
					t.Fatal(err)
				}
				s.record.State = 3 // Existing pre-send record also means possibly sent.
				if err := s.append(); err != nil {
					t.Fatal(err)
				}
				if mode == "receipt-regressed" {
					s.record.NotifyAcknowledged = true
					if err := s.append(); err != nil {
						t.Fatal(err)
					}
					s.record.NotifyAcknowledged = false
				} else {
					s.record.NotifyEpoch = 0 // Old code falsely recorded completion.
				}
			}
			if err := s.append(); err != nil {
				t.Fatal(err)
			}
			s.close()
			s, err = openNSMStateMode(dir, "127.0.0.1", "127.0.0.2", true)
			if mode == "clean-v1" || mode == "clean-v2" {
				if err != nil {
					t.Fatal("ordinary cleanup journal refused", err)
				}
				defer s.close()
				if s.record.State != 3 || s.record.NotifyEpoch != 0 {
					t.Fatal("clean epoch changed incorrectly", s.record)
				}
			} else if err == nil {
				s.close()
				t.Fatal("unproven notification completion escaped quarantine")
			}
		})
	}
	for _, r := range []nsmRecord{
		{Version: 2, State: 1, NotifyAcknowledged: true},
		{Version: 2, State: 1, NotifyEpoch: 3, NotifyAcknowledged: true},
		{Version: 2, State: 3, NotifyEpoch: 3, NotifyAcknowledged: true, Dirty: true},
	} {
		if validateSavedNLMLocks(r) == nil {
			t.Fatal("invalid notification receipt admitted", r)
		}
	}
}
