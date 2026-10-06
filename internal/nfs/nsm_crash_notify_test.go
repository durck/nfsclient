package nfs

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func nsmNotifyPeer(t *testing.T, epoch *atomic.Uint32, notify func(*decoder) encoder) int {
	t.Helper()
	ready := make(chan struct{})
	var port int
	port = nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
		<-ready
		d := &decoder{b: raw}
		xid := d.u32()
		d.take(8)
		program, version, proc := d.u32(), d.u32(), d.u32()
		d.u32()
		d.opaque(400)
		d.u32()
		d.opaque(400)
		var body encoder
		switch {
		case program == 100000 && version == 2 && proc == 3:
			d.take(16)
			body.u32(uint32(port))
		case program == nsmProgram && version == 1 && proc == 1:
			d.str()
			body.u32(0)
			body.u32(epoch.Load())
		case program == nsmProgram && version == 1 && proc == 6:
			body = notify(d)
		default:
			t.Errorf("unexpected NSM request %d/%d/%d", program, version, proc)
		}
		if d.err != nil || len(d.b) != 0 {
			t.Error("NSM framing", d.err, len(d.b))
		}
		if body == nil && proc == 6 {
			return nil
		}
		return append(udpReply(xid, 0)[:24], body...)
	})
	close(ready)
	return port
}

func crashNotifySaved(version uint32) nsmSavedLock {
	return nsmSavedLock{Version: version, Info: LockInfo{ID: 1, Write: true, Offset: 4, Length: 8}, FH: bytes.Repeat([]byte{1}, 32), Owner: bytes.Repeat([]byte{2}, 16), SVID: 41, Auth: Auth{UID: 21, GID: 22, Groups: []uint32{23}}, Confirmed: true}
}

func TestNSMAutomaticCrashNotification(t *testing.T) {
	for _, version := range []uint32{1, 4} {
		for _, mode := range []string{"success", "empty", "drop", "drop-retry", "trailing", "restart", "cancel", "identity", "version", "unknown", "epoch-exhausted", "journal-failure", "partial-cleanup", "pending-intent", "pending-clean", "pending-epoch", "source-mismatch"} {
			t.Run(fmt.Sprintf("v%d/%s", version, mode), func(t *testing.T) { runCrashNotify(t, version, mode) })
		}
	}
}

func runCrashNotify(t *testing.T, version uint32, mode string) {
	t.Helper()
	cfg := Config{Version: "3", Transport: "tcp", Timeout: 300 * time.Millisecond, NLMAutoRecover: true, NLMAutoNotify: true, NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
	if version == 1 {
		cfg.Version = "2"
	}
	s, err := openNSMState(cfg.NLMStateDir, cfg.NLMClientIP, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	saved := crashNotifySaved(version)
	if mode != "empty" {
		s.record.Locks = []nsmSavedLock{saved}
		s.record.Dirty = true
		s.record.LastSVID = 41
		if mode == "unknown" {
			s.record.Locks[0].Confirmed = false
		}
		if mode == "version" {
			s.record.Locks[0].Version = 5 - version
		}
		if err := s.append(); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "pending-intent" || mode == "pending-clean" || mode == "pending-epoch" {
		s.record.NotifyEpoch = 3
		if err := s.append(); err != nil {
			t.Fatal(err)
		}
		if mode != "pending-intent" {
			s.record.Locks = nil
			s.record.Dirty = false
			if err := s.append(); err != nil {
				t.Fatal(err)
			}
		}
		if mode == "pending-epoch" {
			s.record.State = 3
			if err := s.append(); err != nil {
				t.Fatal(err)
			}
		}
	}
	s.close()
	var serverEpoch atomic.Uint32
	serverEpoch.Store(3)
	var mu sync.Mutex
	var order []string
	var notifyCount atomic.Int32
	cfg.PortmapPort = nsmNotifyPeer(t, &serverEpoch, func(d *decoder) encoder {
		mu.Lock()
		defer mu.Unlock()
		if d.str() != cfg.NLMClientIP || d.u32() != 3 {
			t.Error("notification identity/epoch changed")
		}
		notifyCount.Add(1)
		order = append(order, "notify")
		if mode == "drop" || mode == "drop-retry" && notifyCount.Load() == 1 {
			return nil
		}
		if mode == "trailing" {
			return encoder{0}
		}
		if mode == "restart" {
			serverEpoch.Store(5)
		}
		return encoder{}
	})
	port := nlmTestEndpoint(t, "tcp", func(raw []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		d := &decoder{b: raw}
		xid := d.u32()
		d.take(8)
		if d.u32() != nlmProgram || d.u32() != version {
			t.Error("NLM profile changed")
		}
		proc := d.u32()
		d.u32()
		d.opaque(400)
		d.u32()
		d.opaque(400)
		cookie := d.opaque(1024)
		if proc == 2 {
			d.u32()
			d.u32()
		}
		if d.str() != cfg.NLMClientIP {
			t.Error("changed caller")
		}
		fh := d.opaque(64)
		owner := d.opaque(1024)
		pid := d.u32()
		var off, length uint64
		if version == 1 {
			off, length = uint64(d.u32()), uint64(d.u32())
		} else {
			off, length = d.u64(), d.u64()
		}
		if proc == 4 && pid == saved.SVID {
			if !bytes.Equal(fh, saved.FH) || !bytes.Equal(owner, saved.Owner) || off != 4 || length != 8 {
				t.Error("changed cleanup identity/range")
			}
			order = append(order, "cleanup")
			if mode == "partial-cleanup" {
				return nil
			}
		} else if proc == 2 {
			if d.u32() != 0 || d.u32() != 3 && mode != "empty" || mode != "empty" && notifyCount.Load() < 1 {
				t.Error("new LOCK before notification/with old epoch")
			}
			order = append(order, "lock")
		} else if proc == 4 {
			order = append(order, "unlock")
		} else {
			t.Errorf("unexpected NLM procedure %d", proc)
		}
		if d.err != nil || len(d.b) != 0 {
			t.Error("NLM framing", d.err, len(d.b))
		}
		var body encoder
		body.opaque(cookie)
		body.u32(0)
		return append(udpReply(xid, 0)[:24], body...)
	})
	if mode == "source-mismatch" {
		cfg.NLMClientIP = "127.0.0.2"
	}
	ctx := context.Background()
	m, err := startNSMMode(ctx, cfg, "127.0.0.1", 0, nil, nil, true)
	if mode == "unknown" || mode == "source-mismatch" {
		if err == nil {
			m.close()
			t.Fatal("invalid crash profile admitted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { m.close() }()
	if mode == "epoch-exhausted" {
		m.state.record.State = math.MaxInt32
	}
	rpc, err := dialRPC(ctx, "127.0.0.1", port, cfg.Timeout, false)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.conn.Close()
	c := &Client{config: &cfg, version: cfg.Version, Auth: saved.Auth}
	n := &nlmClient{c: c, rpc: rpc, monitor: m, version: version, locks: map[uint64]*nlmLock{}}
	c.nlm = n
	if mode == "identity" {
		c.Auth.UID++
	}
	if mode == "journal-failure" {
		if err := m.state.file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "cancel" {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		ctx = cancelled
	}
	err = n.prepareAutomaticRecovery(ctx)
	if mode == "drop-retry" {
		if err == nil || !m.lost.Load() || m.state.record.NotifyEpoch != 3 {
			t.Fatal("lost notification was not quarantined", err)
		}
		m.close()
		if wrong, err := startNSMMode(ctx, Config{Version: cfg.Version, Transport: cfg.Transport, Timeout: cfg.Timeout, NLMAutoRecover: true, NLMClientIP: cfg.NLMClientIP, NLMStateDir: cfg.NLMStateDir, PortmapPort: cfg.PortmapPort}, "127.0.0.1", 0, nil, nil, true); err == nil {
			wrong.close()
			t.Fatal("pending notification bypassed without option")
		}
		m, err = startNSMMode(ctx, cfg, "127.0.0.1", 0, nil, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		n = &nlmClient{c: c, rpc: rpc, monitor: m, version: version, locks: map[uint64]*nlmLock{}}
		c.nlm = n
		err = n.prepareAutomaticRecovery(ctx)
	}
	if mode != "empty" {
		if err == nil || !m.lost.Load() {
			t.Fatal("notification uncertainty did not poison connection", err)
		}
		if _, err := c.Lock(context.Background(), saved.FH, true); err == nil {
			t.Fatal("new lock after notification uncertainty")
		}
		sent := mode == "success" || mode == "pending-intent" || mode == "pending-clean" || mode == "drop" || mode == "drop-retry" || mode == "trailing" || mode == "restart"
		ack := mode == "success" || mode == "pending-intent" || mode == "pending-clean" || mode == "restart"
		if sent || mode == "pending-epoch" {
			if m.state.record.NotifyEpoch != 3 || m.state.record.Dirty || m.state.record.State != 3 {
				t.Fatal("notification intent lost", m.state.record)
			}
		}
		wantCount := int32(0)
		if sent {
			wantCount = 1
		}
		if notifyCount.Load() != wantCount || m.state.record.NotifyAcknowledged != ack {
			t.Fatal("notification repeated or receipt evidence changed", notifyCount.Load(), m.state.record)
		}
		return
	}
	if err != nil || m.state.record.NotifyEpoch != 0 || m.state.record.Dirty {
		t.Fatal("clean startup unnecessarily quarantined", err)
	}
	if err := n.prepareAutomaticRecovery(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := c.Lock(ctx, saved.FH, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(order, []string{"lock", "unlock"}) {
		t.Fatal("clean startup sent notification", order)
	}
}

func TestNSMNotificationProcessDeath(t *testing.T) {
	if phase := os.Getenv("NFS_VIEWER_NOTIFY_DEATH"); phase != "" {
		s, err := openNSMState(os.Getenv("NFS_VIEWER_NOTIFY_DIR"), "127.0.0.1", "127.0.0.1")
		if err != nil {
			os.Exit(21)
		}
		s.record.Locks = []nsmSavedLock{crashNotifySaved(4)}
		s.record.Dirty = true
		s.record.LastSVID = 41
		if err := s.append(); err != nil {
			os.Exit(22)
		}
		if phase != "before-intent" {
			s.record.NotifyEpoch = 3
			if err := s.append(); err != nil {
				os.Exit(23)
			}
		}
		if phase == "after-cleanup" || phase == "before-send" || phase == "after-ack" {
			s.record.Locks = nil
			s.record.Dirty = false
			if err := s.append(); err != nil {
				os.Exit(24)
			}
		}
		if phase == "before-send" || phase == "after-ack" {
			s.record.State = 3
			if err := s.append(); err != nil {
				os.Exit(25)
			}
		}
		if phase == "after-ack" {
			s.record.NotifyAcknowledged = true
			if err := s.append(); err != nil {
				os.Exit(26)
			}
		}
		os.Exit(71) // Abrupt death: no clean close/unlock callback.
	}
	for _, phase := range []string{"before-intent", "after-intent", "after-cleanup", "before-send", "after-ack"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNSMNotificationProcessDeath$", "-test.timeout=8s")
			cmd.Env = append(os.Environ(), "NFS_VIEWER_NOTIFY_DEATH="+phase, "NFS_VIEWER_NOTIFY_DIR="+dir)
			out, err := cmd.CombinedOutput()
			if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 71 {
				t.Fatalf("child did not die at synced boundary: %v %s", err, out)
			}
			s, err := openNSMStateMode(dir, "127.0.0.1", "127.0.0.1", true)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if phase == "after-ack" {
				if s.record.State != 3 || s.record.NotifyEpoch != 3 || !s.record.NotifyAcknowledged {
					t.Fatal(s.record)
				}
			} else if phase == "before-intent" {
				if s.record.State != 1 || s.record.NotifyEpoch != 0 || !s.record.Dirty {
					t.Fatal(s.record)
				}
			} else if s.record.NotifyEpoch != 3 || s.record.State != 1 && s.record.State != 3 {
				t.Fatal("pending epoch lost", s.record)
			}
		})
	}
}

func TestNSMNotificationInvalidEpoch(t *testing.T) {
	for _, r := range []nsmRecord{{Version: 2, State: 1, NotifyEpoch: 2}, {Version: 2, State: 1, NotifyEpoch: 5}, {Version: 2, State: 3, NotifyEpoch: 1}, {Version: 1, State: 1, NotifyEpoch: 3}, {Version: 2, State: math.MaxInt32, NotifyEpoch: math.MaxInt32 - 2}, {Version: 2, State: 3, NotifyEpoch: 3, Dirty: true}} {
		if validateSavedNLMLocks(r) == nil {
			t.Fatal("invalid pending epoch admitted", r)
		}
	}
}
