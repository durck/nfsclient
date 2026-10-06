package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
)

// Stock FreeBSD refreshes the MDS ctime during LAYOUTRETURN. Source verification
// must complete before that cleanup, while repeated DS sessions retain state.
func TestFreeBSDPNFSRepeatedSessions(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_FREEBSD_SEQUENCE") != "1" {
		t.Skip("stock FreeBSD repeated-session fixture not selected")
	}
	_, _, advertised, target := pnfsFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		for _, held := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/held=%t", version, held), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				s := pnfsSession(t, ctx, version)
				other := pnfsSession(t, ctx, version)
				payload := pnfsPayload()
				local := filepath.Join(t.TempDir(), "source")
				if err := os.WriteFile(local, payload, 0600); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("pnfs12-%s-%s-%t-%d", runtime.GOOS, version, held, time.Now().UnixNano())
				if _, err := s.Put(ctx, local, name); err != nil {
					t.Fatal(err)
				}
				if held {
					if _, err := s.Lock(ctx, name, false); err != nil {
						t.Fatal(err)
					}
				}
				node, _, err := s.Resolve(ctx, name, true)
				if err != nil {
					t.Fatal(err)
				}
				options := nfs.PNFSOptions{DataServers: map[string]string{advertised: target}}
				type attempt struct {
					Bytes                     int64
					BeforeChange, AfterChange uint64
					BeforeCTime, AfterCTime   time.Time
				}
				var attempts []attempt
				for range 3 {
					var out bytes.Buffer
					n, err := s.Client.ReadPNFSToProgress(ctx, node.Handle, uint64(len(payload)), &out, options, nil)
					if err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
						t.Fatal("DS read", n, err)
					}
					before, err := s.Client.GetAttr(ctx, node.Handle)
					if err != nil {
						t.Fatal(err)
					}
					dir := t.TempDir()
					dest := filepath.Join(dir, "result")
					n, err = s.GetPNFS(ctx, name, dest, options, nil)
					if n != int64(len(payload)) || err != nil {
						t.Fatal("complete pNFS download", n, err)
					}
					data, err := os.ReadFile(dest)
					if err != nil || !bytes.Equal(data, payload) {
						t.Fatal("published bytes differ", err)
					}
					after, err := s.Client.GetAttr(ctx, node.Handle)
					if err != nil {
						t.Fatal(err)
					}
					if before.Change != after.Change || before.Size != after.Size || !before.MTime.Equal(after.MTime) || before.CTime.Equal(after.CTime) {
						t.Fatal("unexpected metadata change", before, after)
					}
					files, err := os.ReadDir(dir)
					if err != nil || len(files) != 1 || files[0].Name() != "result" {
						t.Fatal("download missing or leaked temporary", files, err)
					}
					attempts = append(attempts, attempt{n, before.Change, after.Change, before.CTime, after.CTime})
					out.Reset()
					if n, err := s.Client.ReadTo(ctx, node.Handle, &out); err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
						t.Fatal("MDS state lost", n, err)
					}
					if held {
						locks := s.Client.Locks()
						if len(locks) != 1 || locks[0].Uncertain {
							t.Fatal("held lock lost")
						}
						if _, err := other.Lock(ctx, name, true); !errors.Is(err, nfs.Status(10010)) {
							t.Fatal("lock contention lost", err)
						}
					}
				}
				if held {
					if err := s.Client.Unlock(ctx, s.Client.Locks()[0].ID); err != nil {
						t.Fatal(err)
					}
				}
				if dir := os.Getenv("NFS_VIEWER_PNFS_SEQUENCE_EVIDENCE_DIR"); dir != "" {
					evidence := struct {
						Platform, Version, Remote, SHA256 string
						Held                              bool
						Attempts                          []attempt
					}{runtime.GOOS, version, name, fmt.Sprintf("%x", sha256.Sum256(payload)), held, attempts}
					b, err := json.MarshalIndent(evidence, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%s-%t.json", runtime.GOOS, version, held)), b, 0600); err != nil {
						t.Fatal(err)
					}
				}
				t.Logf("PNFS13 platform=%s version=%s held=%t remote=%s bytes=%d six_successive_DS_sessions exact_bytes MDS_reuse full_publication no_temp verified", runtime.GOOS, version, held, name, len(payload))
			})
		}
	}
}
