package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfsclient/internal/nfs"
)

func TestFreeBSDPNFSWrite(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_WRITE") != "1" {
		t.Skip("disposable pNFS write fixture not selected")
	}
	runNativePNFSWrite(t, "file")
}

func TestNativeFlexWrite(t *testing.T) {
	if os.Getenv("NFS_VIEWER_FLEX_WRITE") != "1" {
		t.Skip("disposable Flex write fixture not selected")
	}
	runNativePNFSWrite(t, "flex")
}

func runNativePNFSWrite(t *testing.T, layout string) {
	layoutArgs, prefix := "", "pnfs-write"
	if layout == "flex" {
		layoutArgs, prefix = " --layout flex", "pnfs-flex-write"
	}
	_, _, advertised, target := pnfsFixture(t)
	baseOptions, dsArgs := pnfsNativeOptions(t, layout, advertised, target)
	for _, version := range []string{"4.1", "4.2"} {
		for _, mode := range []string{"api", "cli"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				s := pnfsSession(t, ctx, version)
				other := pnfsSession(t, ctx, version)
				expected := pnfsPayload()
				local := filepath.Join(t.TempDir(), "source")
				if err := os.WriteFile(local, expected, 0600); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("%s-%s-%s-%s-%d", prefix, runtime.GOOS, version, mode, time.Now().UnixNano())
				if _, err := s.Put(ctx, local, name); err != nil {
					t.Fatal(err)
				}
				options := baseOptions
				if _, err := s.PutPNFSRange(ctx, local, name, 0, options, nil); err == nil {
					t.Fatal("unlocked write permitted")
				}
				id, err := s.Lock(ctx, name, true)
				if err != nil {
					t.Fatal(err)
				}
				node, _, err := s.Resolve(ctx, name, false)
				if err != nil {
					t.Fatal(err)
				}
				sh := &Shell{Session: s, Out: io.Discard, Err: io.Discard, LocalDir: filepath.Dir(local)}
				for attempt := 0; attempt < 3; attempt++ {
					patch := bytes.Repeat([]byte{byte(0xa1 + attempt)}, 65553)
					offset := uint64(17 + attempt*65571)
					if err := os.WriteFile(local, patch, 0600); err != nil {
						t.Fatal(err)
					}
					var n int64
					if mode == "cli" {
						_, err = sh.Execute(ctx, fmt.Sprintf("putrangepnfs %s %s %d %s", strconv.Quote(local), name, offset, dsArgs)+layoutArgs)
						n = int64(len(patch))
					} else if attempt == 0 {
						n, err = s.Client.WritePNFSRangeFromProgress(ctx, node.Handle, offset, uint64(len(patch)), bytes.NewReader(patch), options, nil)
					} else {
						n, err = s.PutPNFSRange(ctx, local, name, offset, options, nil)
					}
					if err != nil || n != int64(len(patch)) {
						t.Fatal("pNFS write", attempt, n, err)
					}
					copy(expected[offset:], patch)
					var out bytes.Buffer
					if n, err := s.Client.ReadTo(ctx, node.Handle, &out); err != nil || n != int64(len(expected)) || !bytes.Equal(out.Bytes(), expected) {
						t.Fatal("MDS complete-file readback", attempt, n, err)
					}
					if _, err := other.Lock(ctx, name, true); !errors.Is(err, nfs.Status(10010)) {
						t.Fatal("original lock lost", err)
					}
					locks := s.Client.Locks()
					if len(locks) != 1 || locks[0].ID != id || locks[0].Uncertain {
						t.Fatal("lock inventory changed")
					}
				}
				if _, err := s.PutPNFSRange(ctx, local, name, uint64(len(expected)), options, nil); err == nil {
					t.Fatal("unexpected extension")
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				if otherID, err := other.Lock(ctx, name, true); err != nil {
					t.Fatal("unlock did not release", err)
				} else if err := other.Client.Unlock(ctx, otherID); err != nil {
					t.Fatal(err)
				}
				if dir := os.Getenv("NFS_VIEWER_PNFS_WRITE_EVIDENCE"); dir != "" {
					data, _ := json.MarshalIndent(map[string]any{"platform": runtime.GOOS, "version": version, "mode": mode, "remote": name, "sha256": fmt.Sprintf("%x", sha256.Sum256(expected)), "size": len(expected), "writes": 3}, "", "  ")
					if err := os.WriteFile(filepath.Join(dir, runtime.GOOS+"-"+version+"-"+mode+".json"), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				t.Log("three pNFS writes, complete MDS readback, preserved outside bytes and original lock, refusal to extend, exact unlock")
			})
		}
	}
}
