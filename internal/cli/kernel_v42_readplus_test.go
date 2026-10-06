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
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func TestKernelV42ReadPlus(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	connect := func(version string) *session.Session {
		c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: version, Timeout: 15 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}})
		if err != nil {
			t.Fatal(err)
		}
		s := session.New(c, host, false, false, nil)
		t.Cleanup(func() { s.Client.Close() })
		if err := s.Use(ctx, "/data"); err != nil {
			t.Fatal(err)
		}
		return s
	}
	dir := t.TempDir()
	for _, version := range []string{"4.0", "4.1"} {
		if _, err := connect(version).GetPlus(ctx, "seed", filepath.Join(dir, version), nil); !errors.Is(err, nfs.ErrRequiresV42) {
			t.Fatal(err)
		}
	}
	s, other := connect("4.2"), connect("4.2")
	name := fmt.Sprintf("plus-api-%s-%d", runtime.GOOS, time.Now().UnixNano())
	src := filepath.Join(dir, "source")
	if err := os.WriteFile(src, bytes.Repeat([]byte{'Z'}, 262144), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, src, name); err != nil {
		t.Fatal(err)
	}
	if err := s.Allocate(ctx, name, 262144, 131072); err != nil {
		t.Fatal(err)
	}
	if err := s.Deallocate(ctx, name, 65536, 65536); err != nil {
		t.Fatal(err)
	}
	for _, locked := range []bool{false, true} {
		var id uint64
		if locked {
			var err error
			id, err = s.Lock(ctx, name, false)
			if err != nil {
				t.Fatal(err)
			}
		}
		dst := filepath.Join(dir, fmt.Sprint(locked))
		var last uint64
		n, err := s.GetPlus(ctx, name, dst, func(done, total uint64) {
			if total != 393216 || done < last || done > total {
				t.Errorf("progress %d/%d after %d", done, total, last)
			}
			last = done
		})
		if err != nil || n != 393216 || last != 393216 {
			t.Fatal(n, err, last)
		}
		b, err := os.ReadFile(dst)
		if err != nil || !bytes.Equal(b, spaceExpected()) {
			t.Fatal("READ_PLUS bytes", err)
		}
		if locked {
			if err := s.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.GetPlus(ctx, name, dst, nil); !errors.Is(err, session.ErrDestinationExists) {
			t.Fatal("overwrite accepted", err)
		}
	}
	// Publication must preserve a destination created during the transfer.
	race := filepath.Join(dir, "race")
	_, err := s.GetPlus(ctx, name, race, func(done, total uint64) {
		if done == total {
			if err := os.WriteFile(race, []byte("racer"), 0600); err != nil {
				t.Error(err)
			}
		}
	})
	if !errors.Is(err, session.ErrDestinationExists) {
		t.Fatal("publication collision", err)
	}
	if b, err := os.ReadFile(race); err != nil || string(b) != "racer" {
		t.Fatal("racer modified", err)
	}
	canceled, cancelRead := context.WithCancel(ctx)
	dst := filepath.Join(dir, "canceled")
	_, err = s.GetPlus(canceled, name, dst, func(done, _ uint64) {
		if done > 0 {
			cancelRead()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
	if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled file published", err)
	}
	// A partial lock does not authorize reading the entire file.
	id, err := s.LockRange(ctx, name, false, 0, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPlus(ctx, name, filepath.Join(dir, "partial"), nil); err == nil {
		t.Fatal("partial lock accepted")
	}
	if err := s.Client.Unlock(ctx, id); err != nil {
		t.Fatal(err)
	}
	// Mutate from another connection after data arrives, before publication.
	node, _, err := other.Resolve(ctx, name, false)
	if err != nil {
		t.Fatal(err)
	}
	dst = filepath.Join(dir, "changed")
	_, err = s.GetPlus(ctx, name, dst, func(done, total uint64) {
		if done == total {
			if _, err := other.Client.WriteFrom(ctx, node.Handle, bytes.NewReader([]byte("changed"))); err != nil {
				t.Error(err)
			}
		}
	})
	if !errors.Is(err, session.ErrDownloadSourceChanged) {
		t.Fatal("changed source published", err)
	}
	if _, err := os.Lstat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if leaked, err := filepath.Glob(filepath.Join(dir, ".nfs-download-*")); err != nil || len(leaked) != 0 {
		t.Fatal("temporary download leak", leaked, err)
	}
	// Retain the mutated file for independent server-side verification.
	if err := os.WriteFile(src, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, src, name+"-empty"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GetPlus(ctx, name+"-empty", filepath.Join(dir, "empty"), nil); err != nil || n != 0 {
		t.Fatal("empty READ_PLUS", n, err)
	}
	t.Logf("V42_READ_PLUS platform=%s bytes_verified whole_read_lock cancellation collision changed_source partial_lock empty_file verified", runtime.GOOS)
}

func TestKernelV42ReadPlusCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "result")
	if err := os.WriteFile(src, bytes.Repeat([]byte{'Z'}, 262144), 0600); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("plus-cli-%s-%d", runtime.GOOS, time.Now().UnixNano())
	args := []string{host, "--nfs-version", "4.2", "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "15s"}
	for _, cmd := range []string{"put " + strconv.Quote(src) + " " + name, "allocate " + name + " 262144 131072", "deallocate " + name + " 65536 65536", "getplus " + name + " " + strconv.Quote(dst)} {
		args = append(args, "-c", cmd)
	}
	if out, err := runKerberosCLI(t, args); err != nil {
		t.Fatal(err, out)
	}
	if b, err := os.ReadFile(dst); err != nil || !bytes.Equal(b, spaceExpected()) {
		t.Fatal("CLI READ_PLUS content", err)
	}
	t.Logf("V42_READ_PLUS_CLI platform=%s size=393216 bytes_verified", runtime.GOOS)
}
