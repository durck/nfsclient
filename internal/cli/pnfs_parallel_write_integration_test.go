package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"nfs-viewer/internal/nfs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLizardPNFSParallelWrite(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_MULTI_WRITE") != "1" {
		t.Skip("disposable multi-DS write fixture not selected")
	}
	fixture := pnfsMultiFixture(t)
	for _, version := range []string{"4.1", "4.2"} {
		for _, mode := range []string{"api", "cli"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				c, mds := fixture.observeMDS(t)
				s := c.connect(t, ctx, version)
				name := fmt.Sprintf("pnfs-multi-%s-%s-%s-%d", mode, runtime.GOOS, version, time.Now().UnixNano())
				t.Log("remote", name)
				local := filepath.Join(t.TempDir(), "source")
				want := pnfsMultiSource(t, local)
				f, err := os.OpenFile(local, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				for _, boundary := range []int64{64 << 20, 128 << 20} {
					if _, err := f.WriteAt(make([]byte, min(int64(128), pnfsMultiSize-boundary+64)), boundary-64); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Put(ctx, local, name); err != nil {
					t.Fatal("prepare corrupted file", err)
				}
				node, _, err := s.Resolve(ctx, name, false)
				if err != nil {
					t.Fatal(err)
				}
				id, err := s.Lock(ctx, name, true)
				if err != nil {
					t.Fatal(err)
				}
				observer := &pnfsMultiObserver{}
				options := nfs.PNFSOptions{DataServers: map[string]string{}, Parallelism: 8}
				var mappings []string
				for i, target := range c.targets {
					endpoint, _ := newPNFSMultiRelay(t, target, i, observer)
					options.DataServers[c.advertised[i]] = endpoint
					mappings = append(mappings, c.advertised[i]+"="+endpoint)
				}
				initial := sha256.New()
				if _, err := s.Client.ReadPNFSToProgress(ctx, node.Handle, pnfsMultiSize, initial, options, nil); err != nil {
					t.Fatal("placement probe", err)
				}
				if fmt.Sprintf("%x", initial.Sum(nil)) == want {
					t.Fatal("initial corruption missing")
				}
				boundary := pnfsMultiReads(t, observer.snapshot())
				observer.reset()
				observer.armBoundary(boundary)
				mds.reset()
				shell := &Shell{Session: s, Out: io.Discard, Err: io.Discard, LocalDir: filepath.Dir(local)}
				for _, edge := range []uint64{64 << 20, 128 << 20} {
					offset := edge - 64
					data := make([]byte, min(uint64(128), pnfsMultiSize-offset))
					for i := range data {
						p := offset + uint64(i)
						data[i] = byte((p*31 + p/251) % 256)
					}
					patch := filepath.Join(filepath.Dir(local), "patch")
					if err := os.WriteFile(patch, data, 0600); err != nil {
						t.Fatal(err)
					}
					if mode == "api" {
						n, err := s.PutPNFSRange(ctx, patch, name, offset, options, nil)
						if err != nil || n != int64(len(data)) {
							t.Fatal("parallel patch", n, err)
						}
					} else {
						_, err := shell.Execute(ctx, fmt.Sprintf("putrangepnfs %s %s %d --parallel 8 %s", strconv.Quote(patch), name, offset, strings.Join(mappings, " ")))
						if err != nil {
							t.Fatal("parallel CLI patch", err)
						}
					}
				}
				snap := observer.snapshot()
				if len(snap.Errors) != 0 || !snap.BarrierMatched || snap.BarrierTimedOut {
					t.Fatal("real writes did not overlap", snap)
				}
				if got := mds.snapshot(); len(got.Reads) != 0 || len(got.Errors) != 0 {
					t.Fatal("MDS data fallback", got)
				}
				sort.Slice(snap.Reads, func(i, j int) bool { return snap.Reads[i].Offset < snap.Reads[j].Offset })
				if len(snap.Reads) != 4 {
					t.Fatal("unexpected write count", len(snap.Reads))
				}
				for i, r := range snap.Reads {
					offset := []uint64{(64 << 20) - 64, 64 << 20, (128 << 20) - 64, 128 << 20}[i]
					n := uint32(64)
					if i == 3 {
						n = 17
					}
					data := make([]byte, n)
					for j := range data {
						p := offset + uint64(j)
						data[j] = byte((p*31 + p/251) % 256)
					}
					if r.Opcode != 38 || r.Offset != offset || r.Count != n || r.ReturnedBytes != n || r.WireStatus != 0 || r.PayloadSHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
						t.Fatal("wrong native stripe write", r)
					}
				}
				got := sha256.New()
				n, err := s.Client.ReadPNFSToProgress(ctx, node.Handle, pnfsMultiSize, got, options, nil)
				if err != nil || n != pnfsMultiSize || fmt.Sprintf("%x", got.Sum(nil)) != want {
					t.Fatal("complete readback", n, err)
				}
				locks := s.Client.Locks()
				if len(locks) != 1 || locks[0].ID != id || locks[0].Uncertain {
					t.Fatal("original lock lost")
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				delete(s.LockPaths, id)
				if dir := os.Getenv("NFS_VIEWER_PNFS_MULTI_WRITE_EVIDENCE"); dir != "" {
					data, _ := json.MarshalIndent(map[string]any{"remote": name, "platform": runtime.GOOS, "version": version, "mode": mode, "sha256": want, "size": pnfsMultiSize, "boundary": boundary, "snapshot": snap}, "", "  ")
					if err := os.WriteFile(filepath.Join(dir, runtime.GOOS+"-"+version+"-"+mode+".json"), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
