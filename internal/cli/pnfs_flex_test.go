package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The source and digest must be independently read through a native NFS client.
// This test neither creates nor changes the selected remote source.
func TestNativeFlexRead(t *testing.T) {
	name := os.Getenv("NFS_VIEWER_FLEX_SOURCE")
	if name == "" {
		t.Skip("native Flex source not selected")
	}
	wantHash := os.Getenv("NFS_VIEWER_FLEX_SHA256")
	if len(wantHash) != 64 || strings.ContainsAny(name, "/\\") {
		t.Fatal("explicit source basename and native SHA256 required")
	}
	host, port, advertised, target := pnfsFixture(t)
	baseOptions, dsArgs := pnfsNativeOptions(t, "flex", advertised, target)
	for _, version := range []string{"4.1", "4.2"} {
		for _, parallel := range []int{1, 8} {
			t.Run(fmt.Sprintf("%s/p%d", version, parallel), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				s := pnfsSession(t, ctx, version)
				o := baseOptions
				o.Parallelism = parallel
				dir := t.TempDir()
				check := func(label string) {
					t.Helper()
					dest := filepath.Join(dir, label)
					n, err := s.GetPNFS(ctx, name, dest, o, nil)
					b, readErr := os.ReadFile(dest)
					if err != nil || readErr != nil || n != int64(len(b)) || fmt.Sprintf("%x", sha256.Sum256(b)) != wantHash {
						t.Fatal(label, n, err, readErr)
					}
				}
				check("initial")
				id, err := s.Lock(ctx, name, false)
				if err != nil {
					t.Fatal(err)
				}
				check("locked")
				if len(s.Client.Locks()) != 1 || s.Client.Locks()[0].Uncertain {
					t.Fatal("MDS lock lost")
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				cctx, ccancel := context.WithCancel(ctx)
				cancelDest := filepath.Join(dir, "cancelled")
				n, err := s.GetPNFS(cctx, name, cancelDest, o, func(done, total uint64) {
					if done > 0 {
						ccancel()
					}
				})
				ccancel()
				if n <= 0 || err == nil {
					t.Fatal("cancellation not exercised", n, err)
				}
				if _, err := os.Stat(cancelDest); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("cancelled publication", err)
				}
				check("after-cancel")
				bad := o
				bad.DataServers = map[string]string{"192.0.2.254:2049": target}
				if _, err := s.GetPNFS(ctx, name, filepath.Join(dir, "unapproved"), bad, nil); err == nil {
					t.Fatal("unapproved DS accepted")
				}
				check("after-refusal")
				if leftovers, err := filepath.Glob(filepath.Join(dir, ".nfs-download-*")); err != nil || len(leftovers) != 0 {
					t.Fatal("temporary leak", leftovers, err)
				}
				t.Logf("FLEX_NATIVE platform=%s version=%s parallel=%d source=%s sha256=%s read locked cancel reuse approval verified", runtime.GOOS, version, parallel, name, wantHash)
			})
		}
		t.Run(version+"/cli", func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "download")
			args := []string{host, "--nfs-version", version, "--nfs-port", strconv.Itoa(port), "--pnfs", "--export", pnfsFixtureExport(), "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--progress", "never", "-c", "getpnfs " + name + " " + strconv.Quote(dest) + " --layout flex " + dsArgs}
			out, err := runKerberosCLI(t, args)
			b, readErr := os.ReadFile(dest)
			if err != nil || readErr != nil || fmt.Sprintf("%x", sha256.Sum256(b)) != wantHash {
				t.Fatal(err, readErr, out)
			}
			t.Logf("FLEX_CLI platform=%s version=%s sha256=%s binary=%t", runtime.GOOS, version, wantHash, os.Getenv("NFS_VIEWER_TEST_BINARY") != "")
		})
	}
}
