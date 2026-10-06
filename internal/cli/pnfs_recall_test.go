package cli

import (
	"bytes"
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

// Requires the dedicated instrumented server, with its recall trigger enabled.
// The trigger uses Ganesha's real layout state and callback sender; it is not a
// claim that unmodified Gluster normally initiates layout recalls.
func TestGlusterPNFSRecall(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_RECALL") != "1" {
		t.Skip("instrumented pNFS recall fixture not selected")
	}
	_, _, advertised, target := pnfsFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		for _, held := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/held=%t", version, held), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				s := pnfsSession(t, ctx, version)
				payload := pnfsPayload()
				name := fmt.Sprintf("pnfs-recall-%s-%s-%t-%d", runtime.GOOS, version, held, time.Now().UnixNano())
				dir := t.TempDir()
				source := filepath.Join(dir, "source")
				if err := os.WriteFile(source, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Put(ctx, source, name); err != nil {
					t.Fatal(err)
				}
				var lock uint64
				if held {
					var err error
					lock, err = s.Lock(ctx, name, false)
					if err != nil {
						t.Fatal(err)
					}
				}
				paused := false
				dest := filepath.Join(dir, "recalled")
				n, err := s.GetPNFS(ctx, name, dest, nfs.PNFSOptions{DataServers: map[string]string{advertised: target}, Parallelism: 8}, func(done, total uint64) {
					if done > 0 && !paused {
						paused = true
						time.Sleep(1200 * time.Millisecond)
					}
				})
				if !paused || err == nil || !strings.Contains(err.Error(), "layout recalled") || n <= 0 || n >= int64(len(payload)) {
					t.Fatalf("recall not observed: n=%d err=%v", n, err)
				}
				if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recalled download published", err)
				}
				if files, err := filepath.Glob(filepath.Join(dir, ".nfs-download-*")); err != nil || len(files) != 0 {
					t.Fatal("temporary file leak", files, err)
				}
				if held {
					locks := s.Client.Locks()
					if len(locks) != 1 || locks[0].Uncertain {
						t.Fatal("recall lost held lock", locks)
					}
					if err := s.Client.Unlock(ctx, lock); err != nil {
						t.Fatal("unlock after recall", err)
					}
				}
				mds := filepath.Join(dir, "mds")
				if _, err := s.Get(ctx, name, mds); err != nil {
					t.Fatal("MDS unusable after layout return", err)
				}
				if got, err := os.ReadFile(mds); err != nil || !bytes.Equal(got, payload) {
					t.Fatal("MDS bytes after recall", err)
				}
				t.Logf("PNFS_RECALL platform=%s version=%s held=%t remote=%s stopped_at=%d no_publication cleanup MDS_reuse verified", runtime.GOOS, version, held, name, n)
			})
		}
	}
}
