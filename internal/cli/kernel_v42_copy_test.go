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

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func copySource() []byte {
	b := make([]byte, 262144)
	for i := range b {
		b[i] = byte((i*31 + i/257) % 251)
	}
	return b
}
func copyExpected() []byte {
	b := make([]byte, 327680)
	copy(b, bytes.Repeat([]byte{'D'}, 32768))
	copy(b[32768:], copySource()[65536:196608])
	copy(b[262144:], copySource()[:65536])
	return b
}

func TestKernelV42Copy(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprint(locked), func(t *testing.T) {
			dir := t.TempDir()
			src, dst, out := filepath.Join(dir, "source"), filepath.Join(dir, "destination"), filepath.Join(dir, "result")
			if err := os.WriteFile(src, copySource(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, bytes.Repeat([]byte{'D'}, 65536), 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("copy-api-%s-%t-%d", runtime.GOOS, locked, time.Now().UnixNano())
			if _, err := s.Put(ctx, src, name+"-src"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, dst, name+"-dst"); err != nil {
				t.Fatal(err)
			}
			var locks []uint64
			if locked {
				id, err := s.Lock(ctx, name+"-src", false)
				if err != nil {
					t.Fatal(err)
				}
				locks = append(locks, id)
				id, err = s.Lock(ctx, name+"-dst", true)
				if err != nil {
					t.Fatal(err)
				}
				locks = append(locks, id)
			}
			for _, r := range [][3]uint64{{65536, 32768, 131072}, {0, 262144, 65536}} {
				if n, err := s.CopyRange(ctx, name+"-src", name+"-dst", r[0], r[1], r[2], false); err != nil || n != r[2] {
					t.Fatal("server COPY", n, err)
				}
			}
			// ext4 has no reflink support: CLONE must remain an explicit error.
			if _, err := s.CopyRange(ctx, name+"-src", name+"-dst", 0, 0, 65536, true); !errors.Is(err, nfs.Status(10004)) {
				t.Fatal("ext4 CLONE expected NOTSUPP", err)
			}
			for _, invalid := range [][2]string{{name + "-src", name + "-src"}, {"link", name + "-dst"}, {name + "-src", "."}} {
				if _, err := s.CopyRange(ctx, invalid[0], invalid[1], 0, 0, 1, false); err == nil {
					t.Fatal("invalid source/destination accepted", invalid)
				}
			}
			if _, err := s.CopyRange(ctx, name+"-src", name+"-dst", 262144, 0, 1, false); err == nil {
				t.Fatal("past EOF accepted")
			}
			if _, err := s.CopyRange(ctx, name+"-src", "readonly", 0, 0, 1, false); !errors.Is(err, nfs.Status(13)) {
				t.Fatal("write denied destination", err)
			}
			if _, err := s.GetPlus(ctx, name+"-dst", out, nil); err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(out); err != nil || !bytes.Equal(b, copyExpected()) {
				t.Fatal("copied bytes", err)
			}
			for _, id := range locks {
				if err := c.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("V42_COPY platform=%s locked=%t synchronous_ranges_bytes_verified clone_real_NOTSUPP", runtime.GOOS, locked)
		})
	}
}

func TestKernelV42CopyCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	dir := t.TempDir()
	src, dst, out := filepath.Join(dir, "source"), filepath.Join(dir, "destination"), filepath.Join(dir, "result")
	if err := os.WriteFile(src, copySource(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, bytes.Repeat([]byte{'D'}, 65536), 0600); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("copy-cli-%s-%d", runtime.GOOS, time.Now().UnixNano())
	args := []string{host, "--nfs-version", "4.2", "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "15s"}
	for _, cmd := range []string{"put " + strconv.Quote(src) + " " + name + "-src", "put " + strconv.Quote(dst) + " " + name + "-dst", "copyrange " + name + "-src " + name + "-dst 65536 32768 131072", "copyrange " + name + "-src " + name + "-dst 0 262144 65536", "getplus " + name + "-dst " + strconv.Quote(out)} {
		args = append(args, "-c", cmd)
	}
	if output, err := runKerberosCLI(t, args); err != nil {
		t.Fatal(err, output)
	}
	if b, err := os.ReadFile(out); err != nil || !bytes.Equal(b, copyExpected()) {
		t.Fatal("CLI copy bytes", err)
	}
	t.Logf("V42_COPY_CLI platform=%s synchronous_ranges_bytes_verified", runtime.GOOS)
}
