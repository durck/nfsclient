package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// Linux 6.8 does not implement IO_ADVISE. Its real NOTSUPP response must
// survive without releasing the caller's lock or pretending hints took effect.
func TestKernelV42Advice(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: "4.2", Timeout: 15 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := session.New(c, host, false, false, nil)
	if err := s.Use(ctx, "/data"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Advise(ctx, "seed", 0, 0, 258); err == nil {
		t.Fatal("advice without retained state accepted")
	}
	id, err := s.Lock(ctx, "seed", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Advise(ctx, "seed", 0, 0, 258); !errors.Is(err, nfs.Status(10004)) {
		t.Fatal("expected kernel NOTSUPP", err)
	}
	locks := c.Locks()
	if len(locks) != 1 || locks[0].Uncertain {
		t.Fatal("unsupported advice damaged lock", locks)
	}
	dst := filepath.Join(t.TempDir(), "result")
	if _, err := s.Get(ctx, "seed", dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(dst); err != nil || !bytes.Equal(b, []byte("kernel RPC-with-TLS fixture\n")) {
		t.Fatal("locked read after unsupported advice", err)
	}
	if err := c.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Logf("V42_ADVICE platform=%s real_NOTSUPP retained_lock_and_read_verified", runtime.GOOS)
}

func TestKernelV42AdviceCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	args := []string{host, "--nfs-version", "4.2", "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "15s", "-c", "lock seed read", "-c", "advise seed 0 0 sequential,read"}
	out, err := runKerberosCLI(t, args)
	message := fmt.Sprint(err) + " " + out
	if err == nil || (!strings.Contains(message, "NFS4ERR_NOTSUPP") && !strings.Contains(message, "10004") && !strings.Contains(strings.ToLower(message), "not supported")) {
		t.Fatal("expected CLI unsupported advice", err, strconv.Quote(out))
	}
	t.Logf("V42_ADVICE_CLI platform=%s real_NOTSUPP_verified", runtime.GOOS)
}
