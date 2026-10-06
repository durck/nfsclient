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

// The fixture selects a dedicated export and records callback behavior separately
// from byte verification. Both current stock servers refuse WRITE_SAME.
func TestServerOffload(t *testing.T) {
	host := os.Getenv("NFS_VIEWER_OFFLOAD_HOST")
	if host == "" {
		t.Skip("dedicated offload fixture not selected")
	}
	for _, held := range []bool{false, true} {
		t.Run(fmt.Sprint(held), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			c, err := nfs.Connect(ctx, nfs.Config{Host: host, NFSPort: offloadTestPort(t), Version: "4.2", Offload: true, Timeout: 5 * time.Second, Auth: nfs.Auth{}})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s := session.New(c, host, false, false, nil)
			if err := s.Use(ctx, "/"); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
			payload := copySource()
			original := bytes.Repeat([]byte{'D'}, 65536)
			if err := os.WriteFile(src, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, original, 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("offload-%s-%t", runtime.GOOS, held)
			for _, file := range []struct{ local, remote string }{{src, name + "-src"}, {dst, name + "-dst"}} {
				if _, err := s.Put(ctx, file.local, file.remote); err != nil {
					t.Fatal(err)
				}
			}
			if held {
				if _, err := s.Lock(ctx, name+"-src", false); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Lock(ctx, name+"-dst", true); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := s.CopyRangeAsync(ctx, name+"-src", name+"-dst", 65536, 32768, 131072, 10*time.Second); err != nil || n != 131072 {
				t.Fatal(n, err)
			}
			if n, err := s.CopyRangeAsync(ctx, name+"-src", name+"-dst", 0, 262144, 65536, 10*time.Second); err != nil || n != 65536 {
				t.Fatal(n, err)
			}
			if _, err := s.WriteSame(ctx, name+"-dst", 0, 10, []byte{1, 2}, time.Second); !errors.Is(err, nfs.Status(10004)) {
				t.Fatal("expected stock WRITE_SAME NOTSUPP", err)
			}
			var out bytes.Buffer
			if _, err := s.Cat(ctx, name+"-dst", &out); err != nil || !bytes.Equal(out.Bytes(), copyExpected()) {
				t.Fatal("copy/refusal bytes", err)
			}
			for _, l := range c.Locks() {
				if err := c.Unlock(ctx, l.ID); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("OFFLOAD_NATIVE platform=%s held=%t copy_complete writesame_NOTSUPP preserved_bytes", runtime.GOOS, held)
		})
	}
}

func TestServerOffloadCLI(t *testing.T) {
	host := os.Getenv("NFS_VIEWER_OFFLOAD_HOST")
	if host == "" {
		t.Skip("dedicated offload fixture not selected")
	}
	dir := t.TempDir()
	src, dst, out := filepath.Join(dir, "src"), filepath.Join(dir, "dst"), filepath.Join(dir, "out")
	if err := os.WriteFile(src, copySource(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, bytes.Repeat([]byte{'D'}, 65536), 0600); err != nil {
		t.Fatal(err)
	}
	name := "offload-cli-" + runtime.GOOS
	args := []string{host, "--nfs-port", strconv.Itoa(offloadTestPort(t)), "--nfs-version", "4.2", "--offload", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
	for _, line := range []string{"put " + strconv.Quote(src) + " " + name + "-src", "put " + strconv.Quote(dst) + " " + name + "-dst", "copyasync " + name + "-src " + name + "-dst 65536 32768 131072 10s", "copyasync " + name + "-src " + name + "-dst 0 262144 65536 10s", "get " + name + "-dst " + strconv.Quote(out)} {
		args = append(args, "-c", line)
	}
	if output, err := runKerberosCLI(t, args); err != nil {
		t.Fatal(err, output)
	}
	if result, err := os.ReadFile(out); err != nil || !bytes.Equal(result, copyExpected()) {
		t.Fatal("CLI bytes", err)
	}
	refusal := []string{host, "--nfs-port", strconv.Itoa(offloadTestPort(t)), "--nfs-version", "4.2", "--offload", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "-c", "writesame " + name + "-dst 0 10 aabb 1s"}
	if output, err := runKerberosCLI(t, refusal); err == nil || !bytes.Contains([]byte(output), []byte("not supported")) {
		t.Fatal("CLI NOTSUPP", err, string(output))
	}
	t.Logf("OFFLOAD_CLI platform=%s copy_complete writesame_NOTSUPP", runtime.GOOS)
}

func offloadTestPort(t *testing.T) int {
	t.Helper()
	if value := os.Getenv("NFS_VIEWER_OFFLOAD_PORT"); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			t.Fatal("invalid offload fixture port")
		}
		return port
	}
	return 2049
}
