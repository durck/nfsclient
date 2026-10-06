package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// Test-only readiness probe: Linux lockd can keep locks_in_grace true after
// nfsd's v4_end_grace reports Y. Retry only a definitive GRACE denial, using a
// fresh OPEN/lock owner each time. Public LOCK never waits or retries.
func TestMicrosoftADNFSLockReadiness(t *testing.T) {
	if os.Getenv("NFS_VIEWER_MSAD_LOCK_READINESS") != "1" || os.Getenv("NFS_VIEWER_MSAD_NFS") != "1" {
		t.Skip("dedicated fixture readiness probe")
	}
	base := os.Getenv("NFS_VIEWER_MSAD_NFS_CREDENTIALS")
	if !filepath.IsAbs(base) {
		t.Fatal("absolute credential directory required")
	}
	host := msadTestHost(t)
	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Second)
	defer cancel()
	c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: "4.1", NFSPort: 2049, Timeout: 5 * time.Second, Security: "krb5p", Kerberos: nfs.KerberosConfig{ConfigFile: filepath.Join(base, "krb5.conf"), Keytab: filepath.Join(base, "nv-alice.keytab"), Principal: "nv-alice@MSAD.NFS.TEST", SPN: "nfs/nfs-interop.msad.nfs.test"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := session.New(c, host, false, false, nil)
	if err := s.Use(ctx, "/"); err != nil {
		t.Fatal(err)
	}
	dir, _, err := s.Resolve(ctx, "data", true)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("lock-readiness-%d", time.Now().UnixNano())
	n, err := c.Create(ctx, dir.Handle, name, 0600, false)
	if err != nil {
		t.Fatal(err)
	}
	for attempts := 0; ; attempts++ {
		id, err := c.Lock(ctx, n.Handle, false)
		if err == nil {
			if err := c.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			if err := c.Remove(ctx, dir.Handle, name); err != nil {
				t.Fatal(err)
			}
			t.Logf("LOCK_READY definitive_grace_denials=%d", attempts)
			return
		}
		if !errors.Is(err, nfs.Status(10013)) || id != 0 || len(c.Locks()) != 0 {
			t.Fatal("unexpected readiness failure", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
