package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

func lockWaitSession(t *testing.T, ctx context.Context, host, ca, version string) *session.Session {
	t.Helper()
	c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: version, Timeout: 5 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	s := session.New(c, host, false, false, nil)
	if err := s.Use(ctx, "/data"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKernelLockWait(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			owner := lockWaitSession(t, ctx, host, ca, version)
			waiter := lockWaitSession(t, ctx, host, ca, version)
			name := fmt.Sprintf("lockwait-api-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			local := filepath.Join(t.TempDir(), "source")
			payload := []byte("bounded lock waiting\n")
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Put(ctx, local, name); err != nil {
				t.Fatal(err)
			}
			id, err := owner.Lock(ctx, name, true)
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if got, err := waiter.LockWait(ctx, name, true, 0, nfs.LockToEOF, 350*time.Millisecond); got != 0 || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout: id=%d err=%v", got, err)
			}
			if elapsed := time.Since(started); elapsed < 300*time.Millisecond || elapsed > 3*time.Second {
				t.Fatal("unbounded or premature timeout", elapsed)
			}
			if len(waiter.Client.Locks()) != 0 {
				t.Fatal("timeout leaked lock")
			}
			done := make(chan error, 1)
			go func() { time.Sleep(250 * time.Millisecond); done <- owner.Client.Unlock(ctx, id) }()
			got, err := waiter.LockWait(ctx, name, true, 0, nfs.LockToEOF, 5*time.Second)
			if releaseErr := <-done; releaseErr != nil {
				t.Fatal(releaseErr)
			}
			if err != nil || got == 0 {
				t.Fatal("grant after release", got, err)
			}
			var content bytes.Buffer
			if _, err := waiter.Cat(ctx, name, &content); err != nil || !bytes.Equal(content.Bytes(), payload) {
				t.Fatal("protected read", err)
			}
			if err := waiter.Client.Unlock(ctx, got); err != nil {
				t.Fatal(err)
			}
			// A pending waiter must not silently switch to a replacement name.
			id, err = owner.Lock(ctx, name, true)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				time.Sleep(250 * time.Millisecond)
				err := owner.Client.Rename(ctx, owner.Root.Handle, name, owner.Root.Handle, name+"-old")
				if err == nil {
					_, err = owner.Put(ctx, local, name)
				}
				done <- err
			}()
			got, err = waiter.LockWait(ctx, name, true, 0, nfs.LockToEOF, 5*time.Second)
			if renameErr := <-done; renameErr != nil {
				t.Fatal(renameErr)
			}
			if err == nil || got != 0 || len(waiter.Client.Locks()) != 0 {
				t.Fatal("replacement accepted or leaked lock", got, err)
			}
			if err := owner.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, _, err := waiter.Resolve(ctx, name, false); err != nil {
				t.Fatal(err)
			}
			t.Logf("LOCK_WAIT platform=%s version=%s bounded_timeout grant_after_release protected_read replacement_refused no_retained_lock", runtime.GOOS, version)
		})
	}
}

func TestKernelLockWaitCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			owner := lockWaitSession(t, ctx, host, ca, version)
			name := fmt.Sprintf("lockwait-cli-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			local := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(local, []byte("bounded lock waiting\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Put(ctx, local, name); err != nil {
				t.Fatal(err)
			}
			id, err := owner.Lock(ctx, name, true)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{host, "--nfs-version", version, "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "5s"}
			out, err := runKerberosCLI(t, append(args, "-c", "lock --wait 350ms "+name+" read"))
			if err == nil || !strings.Contains(fmt.Sprint(err)+out, "deadline exceeded") {
				t.Fatal("CLI timeout", err, out)
			}
			done := make(chan error, 1)
			go func() { time.Sleep(400 * time.Millisecond); done <- owner.Client.Unlock(ctx, id) }()
			dst := filepath.Join(t.TempDir(), "result")
			out, err = runKerberosCLI(t, append(args, "-c", "lock --wait 5s "+name+" read", "-c", "get "+name+" "+strconv.Quote(dst)))
			if releaseErr := <-done; releaseErr != nil {
				t.Fatal(releaseErr)
			}
			if err != nil {
				t.Fatal(err, out)
			}
			if b, err := os.ReadFile(dst); err != nil || string(b) != "bounded lock waiting\n" {
				t.Fatal("CLI protected read", err)
			}
			t.Logf("LOCK_WAIT_CLI platform=%s version=%s timeout_and_grant_verified", runtime.GOOS, version)
		})
	}
}

func TestLockWaitCLIInvalidArguments(t *testing.T) {
	for _, flag := range []string{"--wait", "--wait-native"} {
		for _, line := range []string{"lock --wait", "lock --wait 1s seed", "lock --wait 0 seed read", "lock --wait -1s seed read", "lock --wait 25h seed read", "lock --wait bad seed read", "lock --wait 1s seed write 0 0", "lock --wait 1s seed wrong"} {
			line = strings.Replace(line, "--wait", flag, 1)
			sh := &Shell{Out: io.Discard, Err: io.Discard}
			if _, err := sh.Execute(context.Background(), line); err == nil {
				t.Fatal("invalid command accepted", line)
			}
		}
	}
}
