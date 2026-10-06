package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// The guest runner exclusively owns the server and performs one restart after
// the request marker. Tests never invoke service managers themselves.
func TestMicrosoftADNFSServerRestart(t *testing.T) {
	control := os.Getenv("NFS_VIEWER_MSAD_RESTART_CONTROL")
	if os.Getenv("NFS_VIEWER_MSAD_NFS") != "1" || control == "" {
		t.Skip("requires the dedicated Microsoft AD restart runner")
	}
	base := os.Getenv("NFS_VIEWER_MSAD_NFS_CREDENTIALS")
	if !filepath.IsAbs(base) || !filepath.IsAbs(control) {
		t.Fatal("absolute fixture directories required")
	}
	host := msadTestHost(t)
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	cfg := nfs.Config{Host: host, Version: "4.1", Security: "krb5p", NFSPort: 2049, Timeout: 5 * time.Second, Kerberos: nfs.KerberosConfig{ConfigFile: filepath.Join(base, "krb5.conf"), Keytab: filepath.Join(base, "nv-alice.keytab"), Principal: "nv-alice@MSAD.NFS.TEST", SPN: "nfs/nfs-interop.msad.nfs.test"}}
	c, err := nfs.Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := session.New(c, host, false, false, nil)
	defer func() { s.Client.Close() }()
	if err := s.Use(ctx, "/"); err != nil {
		t.Fatal(err)
	}
	if err := s.CD(ctx, "/data"); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("restart-and-verified-resume\x00"), 16384)
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, source, "restart.bin"); err != nil {
		t.Fatal(err)
	}
	partialSource := filepath.Join(t.TempDir(), "upload-prefix")
	if err := os.WriteFile(partialSource, payload[:65536], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, partialSource, "restart-upload.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(ctx, "restart-upload.bin", true); err != nil {
		t.Fatal(err)
	}
	s.Client.WriteSize = 32768
	dest := filepath.Join(t.TempDir(), "download")
	if err := os.WriteFile(dest+".nfs-part", payload[:len(payload)/2], 0600); err != nil {
		t.Fatal(err)
	}
	autoClient, err := nfs.Connect(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	automatic := session.New(autoClient, host, false, false, nil)
	defer func() { automatic.Client.Close() }()
	if err := automatic.Use(ctx, "/"); err != nil {
		t.Fatal(err)
	}
	if err := automatic.CD(ctx, "/data"); err != nil {
		t.Fatal(err)
	}
	autoDest := filepath.Join(t.TempDir(), "automatic-download")
	restarted, attempts := false, 0
	var interruptedAt uint64
	var uploadInterruptedAt int64
	_, err = automatic.GetResumeRetry(ctx, "restart.bin", autoDest, 3, func(done, _ uint64) {
		if done == 0 {
			attempts++
		}
		if done < 32768 || restarted {
			return
		}
		restarted, interruptedAt = true, done
		// Capture real read data and its initial metadata before restarting.
		// The other session also holds a lock across this same server restart.
		if _, err := s.Lock(ctx, "restart.bin", true); err != nil {
			t.Fatal(err)
		}
		requested := false
		var uploadErr error
		uploadInterruptedAt, uploadErr = s.PutResume(ctx, source, "restart-upload.bin", func(done, total uint64) {
			if done < 98304 || requested {
				return
			}
			requested = true
			if err := os.WriteFile(filepath.Join(control, "request"), []byte("restart\n"), 0600); err != nil {
				t.Fatal(err)
			}
			for {
				if _, err := os.Stat(filepath.Join(control, "done")); err == nil {
					break
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(100 * time.Millisecond):
				}
			}
		})
		if !requested || uploadErr == nil || uploadInterruptedAt < 98304 || uploadInterruptedAt >= int64(len(payload)) {
			t.Fatal("upload did not stop on lost state during restart", requested, uploadInterruptedAt, uploadErr)
		}
	})
	if err != nil || !restarted || attempts != 2 || automatic.Client == autoClient {
		t.Fatalf("automatic restart recovery: attempts=%d error=%v", attempts, err)
	}
	assertRecoveryFile(t, autoDest, payload)
	if automatic.CWD != "/data" || automatic.Client.Identity() != autoClient.Identity() || automatic.Client.Security() != "krb5p" || automatic.Client.Version() != "4.1" {
		t.Fatal("automatic recovery changed session profile")
	}
	t.Logf("MSAD_AUTO_RESUME version=4.1 security=krb5p bytes=%d interrupted_at=%d attempts=%d real_restart source_pinned prefix_verified", len(payload), interruptedAt, attempts)
	var afterRestart bytes.Buffer
	if _, err := s.Cat(ctx, "restart.bin", &afterRestart); err == nil || afterRestart.Len() != 0 {
		t.Fatal("lost lock allowed protected read", err)
	}
	if locks := s.Client.Locks(); len(locks) != 2 || !locks[0].Uncertain || !locks[1].Uncertain {
		t.Fatal("restart lock loss not visible", locks)
	}
	if err := s.Reconnect(ctx); !errors.Is(err, nfs.ErrLocksHeld) {
		t.Fatal("implicit lock discard", err)
	}
	sh := &Shell{Session: s, Out: io.Discard, Err: io.Discard}
	if _, err := sh.Execute(ctx, "reconnect --discard-locks"); err != nil {
		t.Fatal(err)
	}
	if len(s.Client.Locks()) != 0 {
		t.Fatal("reconnect claimed restored locks")
	}
	if s.CWD != "/data" || s.Client.Version() != "4.1" || s.Client.Security() != "krb5p" || s.Client.Identity() != c.Identity() {
		t.Fatal("reconnect did not preserve session profile")
	}
	if _, err := s.GetResume(ctx, "restart.bin", dest, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("content changed after restart", err)
	}
	id, err := s.Lock(ctx, "restart.bin", true)
	if err != nil {
		t.Fatal("explicit fresh lock", err)
	}
	if err := s.Client.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	id, err = s.Lock(ctx, "restart-upload.bin", true)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.PutResume(ctx, source, "restart-upload.bin", nil); err != nil || n != int64(len(payload)) {
		t.Fatal("AD upload resume after restart", n, err)
	}
	var uploaded bytes.Buffer
	if _, err := s.Cat(ctx, "restart-upload.bin", &uploaded); err != nil || !bytes.Equal(uploaded.Bytes(), payload) {
		t.Fatal("AD resumed upload bytes", err)
	}
	if err := s.Client.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Logf("MSAD_UPLOAD_RESUME version=4.1 security=krb5p bytes=%d interrupted_at=%d real_restart prefix_verified fresh_write_lock", len(payload), uploadInterruptedAt)
	t.Log("MSAD_LOCK_RESTART uncertain protected_io_refused explicit_discard fresh_lock")
	t.Logf("MSAD_RESTART version=4.1 security=krb5p cwd=/data bytes=%d retained_prefix=%d", len(payload), len(payload)/2)
}
