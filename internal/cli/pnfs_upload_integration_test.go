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

	"nfsclient/internal/session"
)

func TestFreeBSDPNFSUpload(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_UPLOAD") != "1" {
		t.Skip("disposable pNFS upload fixture not selected")
	}
	runNativePNFSUpload(t, "file")
}

func TestNativeFlexUpload(t *testing.T) {
	if os.Getenv("NFS_VIEWER_FLEX_WRITE") != "1" {
		t.Skip("disposable Flex write fixture not selected")
	}
	runNativePNFSUpload(t, "flex")
}

func runNativePNFSUpload(t *testing.T, layout string) {
	layoutArgs, prefix := "", "pnfs-upload"
	if layout == "flex" {
		layoutArgs, prefix = " --layout flex", "pnfs-flex-upload"
	}
	_, _, advertised, target := pnfsFixture(t)
	baseOptions, dsArgs := pnfsNativeOptions(t, layout, advertised, target)
	for _, version := range []string{"4.1", "4.2"} {
		for _, mode := range []string{"api", "cli"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				s := pnfsSession(t, ctx, version)
				payload := pnfsPayload()
				local := filepath.Join(t.TempDir(), "source")
				if err := os.WriteFile(local, payload, 0600); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("%s-%s-%s-%s-%d", prefix, runtime.GOOS, version, mode, time.Now().UnixNano())
				options := baseOptions
				sh := &Shell{Session: s, Out: io.Discard, Err: io.Discard, LocalDir: filepath.Dir(local)}
				upload := func(remote string) (int64, error) {
					if mode == "cli" {
						_, err := sh.Execute(ctx, fmt.Sprintf("putpnfs %s %s %s", strconv.Quote(local), remote, dsArgs)+layoutArgs)
						return int64(len(payload)), err
					}
					return s.PutPNFS(ctx, local, remote, options, nil)
				}
				n, err := upload(name)
				if err != nil || n != int64(len(payload)) {
					t.Fatal("new upload", n, err)
				}
				if len(s.Client.Locks()) != 0 || len(s.LockPaths) != 0 {
					t.Fatal("temporary lock leaked")
				}
				if _, err := upload(name); !errors.Is(err, session.ErrDestinationExists) {
					t.Fatal("collision not preserved", err)
				}
				node, _, err := s.Resolve(ctx, name, false)
				if err != nil {
					t.Fatal(err)
				}
				var got bytes.Buffer
				if _, err := s.Client.ReadTo(ctx, node.Handle, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
					t.Fatal("upload bytes differ", err)
				}
				id, err := s.Lock(ctx, name, true)
				if err != nil {
					t.Fatal(err)
				}
				patch := bytes.Repeat([]byte{0xd3}, 32785)
				if err := os.WriteFile(local, patch, 0600); err != nil {
					t.Fatal(err)
				}
				offset := uint64(len(payload) + 257)
				if _, err := s.PutPNFSRange(ctx, local, name, offset, options, nil); err == nil {
					t.Fatal("implicit extension")
				}
				if mode == "cli" {
					_, err = sh.Execute(ctx, fmt.Sprintf("putrangepnfs %s %s %d --extend %s", strconv.Quote(local), name, offset, dsArgs)+layoutArgs)
				} else {
					extended := options
					extended.Extend = true
					_, err = s.PutPNFSRange(ctx, local, name, offset, extended, nil)
				}
				if err != nil {
					t.Fatal("explicit extension", err)
				}
				expected := append(append(append([]byte(nil), payload...), make([]byte, 257)...), patch...)
				got.Reset()
				if _, err := s.Client.ReadTo(ctx, node.Handle, &got); err != nil || !bytes.Equal(got.Bytes(), expected) {
					t.Fatal("extended bytes or zero gap differ", err)
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				delete(s.LockPaths, id)
				// A source mutation must fail visibly and release only confirmed state.
				if err := os.WriteFile(local, payload, 0600); err != nil {
					t.Fatal(err)
				}
				changed := false
				partial, err := s.PutPNFS(ctx, local, name+"-partial", options, func(done, total uint64) {
					if done > 0 && !changed {
						changed = true
						if err := os.WriteFile(local, []byte("changed"), 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
				if !errors.Is(err, session.ErrUploadSourceChanged) || !changed || partial <= 0 || partial >= int64(len(payload)) {
					t.Fatal("source mutation", partial, changed, err)
				}
				if len(s.Client.Locks()) != 0 || len(s.LockPaths) != 0 {
					t.Fatal("known partial upload leaked lock")
				}
				partialNode, _, err := s.Resolve(ctx, name+"-partial", false)
				if err != nil {
					t.Fatal(err)
				}
				got.Reset()
				if _, err := s.Client.ReadTo(ctx, partialNode.Handle, &got); err != nil || !bytes.Equal(got.Bytes(), payload[:partial]) {
					t.Fatal("partial bytes differ", err)
				}
				if err := os.WriteFile(local, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if mode == "cli" {
					_, err = sh.Execute(ctx, fmt.Sprintf("putpnfs %s %s-empty %s", strconv.Quote(local), name, dsArgs)+layoutArgs)
				} else {
					_, err = s.PutPNFS(ctx, local, name+"-empty", options, nil)
				}
				if err != nil {
					t.Fatal("empty upload", err)
				}
				empty, _, err := s.Resolve(ctx, name+"-empty", false)
				if err != nil || !empty.Attr.HasSize || empty.Attr.Size != 0 {
					t.Fatal("empty file", err)
				}
				if dir := os.Getenv("NFS_VIEWER_PNFS_UPLOAD_EVIDENCE"); dir != "" {
					files := []map[string]any{}
					for label, data := range map[string][]byte{"": expected, "-partial": payload[:partial], "-empty": nil} {
						files = append(files, map[string]any{"remote": name + label, "size": len(data), "sha256": fmt.Sprintf("%x", sha256.Sum256(data))})
					}
					data, _ := json.MarshalIndent(map[string]any{"platform": runtime.GOOS, "version": version, "mode": mode, "files": files, "partial": partial}, "", "  ")
					if err := os.WriteFile(filepath.Join(dir, runtime.GOOS+"-"+version+"-"+mode+".json"), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				t.Log("new upload, no-replace collision, explicit extension and zero gap, source-mutation partial data, empty file, temporary lock cleanup")
			})
		}
	}
}
