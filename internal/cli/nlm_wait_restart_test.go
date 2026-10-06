package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
)

// The external fixture driver waits for each marker, confirms the queued LOCK
// in its capture, and restarts only the named service on the disposable server.
func TestNLMFreeBSDWaitRestart(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NLM_WAIT_RESTART") != "1" {
		t.Skip("requires coordinated disposable statd/lockd restarts")
	}
	for _, version := range []string{"2", "3"} {
		for _, service := range []string{"statd", "lockd"} {
			t.Run(version+"/"+service, func(t *testing.T) {
				name := fmt.Sprintf("restart-%s-%s-%s", runtime.GOOS, version, service)
				cfg := retainedNLMConfig(t, version, "tcp", name)
				s := retainedNLMSession(t, cfg)
				peerCfg := cfg
				peerCfg.NLMClientIP, peerCfg.NLMListenIP, peerCfg.NLMStateDir = "", "", ""
				peer := retainedNLMSession(t, peerCfg)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				warm, err := s.LockRange(ctx, "locked-write", true, 0, 1)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Client.Unlock(ctx, warm); err != nil {
					t.Fatal(err)
				}
				marker := filepath.Join(t.TempDir(), "ready")
				if err := os.WriteFile(marker, []byte("READY\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := peer.Put(ctx, marker, name+".ready"); err != nil {
					t.Fatal(err)
				}
				id, err := s.LockNativeWait(ctx, "locked-write", true, 8, 8, 30*time.Second)
				if id == 0 || !errors.Is(err, nfs.ErrLockUncertain) || errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("restart did not invalidate queued lock", id, err)
				}
				if locks := s.Client.Locks(); len(locks) != 1 || !locks[0].Uncertain {
					t.Fatal("pending owner lost", locks)
				}
				if err := s.Client.Unlock(ctx, id); !errors.Is(err, nfs.ErrLockUncertain) {
					t.Fatal("replayed uncertain unlock", err)
				}
				s.Client.Close()
				for {
					if _, _, err := peer.Resolve(ctx, name+".restarted", false); err == nil {
						break
					}
					if ctx.Err() != nil {
						t.Fatal("service restart did not finish")
					}
					time.Sleep(100 * time.Millisecond)
				}
				fresh := retainedNLMSession(t, cfg)
				if count, err := fresh.Client.RecoverNLMLocks(ctx); count != 0 || err == nil || !strings.Contains(err.Error(), "unconfirmed LOCK") {
					t.Fatal("pending crash journal recovered as held", count, err)
				}
				if _, err := peer.Put(ctx, marker, name+".done"); err != nil {
					t.Fatal(err)
				}
				t.Logf("NLM_WAIT_RESTART platform=%s version=%s service=%s pending_quarantined no_unlock_replay", runtime.GOOS, version, service)
			})
		}
	}
}
