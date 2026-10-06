package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

// Opt-in only: this fixture reboots an isolated kernel, retaining its export
// disk and statd state. It must never target an existing service namespace.
func TestLinuxNLMReclaim(t *testing.T) {
	root := os.Getenv("NFS_VIEWER_NLM_RECLAIM_ROOT")
	if root == "" {
		t.Skip("isolated rebooting Linux NLM fixture not selected")
	}
	for _, version := range []string{"2", "3"} {
		for _, mode := range []string{"ranges", "resume", "late"} {
			t.Run(version+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				name := "reclaim-" + runtime.GOOS + "-" + version + "-" + mode
				wait := func(file, token string) {
					t.Helper()
					for {
						data, err := os.ReadFile(filepath.Join(root, file))
						if err == nil && strings.TrimSpace(string(data)) == token {
							return
						}
						select {
						case <-ctx.Done():
							t.Fatal("fixture deadline", file, ctx.Err())
						case <-time.After(100 * time.Millisecond):
						}
					}
				}
				previous, _ := os.ReadFile(filepath.Join(root, "restart-request"))
				wait("grace-ended", strings.TrimSpace(string(previous)))
				cfg := nfs.Config{Host: "127.0.0.1", Version: version, Transport: "tcp", PortmapPort: 19511, MountPort: 19548, NFSPort: 19549, NLMPort: 19521, Timeout: 5 * time.Second, NLMClientIP: "127.0.0.2", NLMStateDir: filepath.Join(root, "journals", name), NLMReclaim: true, Auth: nfs.Auth{UID: 20001, GID: 20001}}
				if runtime.GOOS == "linux" {
					cfg.NLMClientIP = "127.0.0.3"
				}
				c, err := nfs.Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(c, cfg.Host, false, false, io.Discard)
				defer func() { s.Client.Close() }()
				if err := s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				data := bytes.Repeat([]byte("NLM restart preserves owner and data.\n"), 16384)
				local := filepath.Join(t.TempDir(), "input")
				if err := os.WriteFile(local, data, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Put(ctx, local, name); err != nil {
					t.Fatal(err)
				}
				if mode == "ranges" {
					if _, err := s.LockRange(ctx, name, false, 0, 4096); err != nil {
						t.Fatal(err)
					}
					if _, err := s.LockRange(ctx, name, true, 8192, 4096); err != nil {
						t.Fatal(err)
					}
				} else if _, err := s.Lock(ctx, name, false); err != nil {
					t.Fatal(err)
				}
				before := s.Client.Locks()
				probe := func(lock nfs.LockInfo, phase string, want bool) {
					t.Helper()
					length := lock.Length
					if length == nfs.LockToEOF {
						length = 0
					}
					token := fmt.Sprintf("%s-%s-%d", name, phase, lock.ID)
					request, _ := json.Marshal(map[string]any{"token": token, "name": name, "offset": lock.Offset, "length": length})
					if err := os.WriteFile(filepath.Join(root, "probe-request"), request, 0600); err != nil {
						t.Fatal(err)
					}
					for {
						data, _ := os.ReadFile(filepath.Join(root, "probe-result"))
						var result struct {
							Token    string
							Conflict bool
						}
						if json.Unmarshal(data, &result) == nil && result.Token == token {
							if result.Conflict != want {
								t.Fatalf("native POSIX contention %s: got %v, want %v", token, result.Conflict, want)
							}
							return
						}
						select {
						case <-ctx.Done():
							t.Fatal("native POSIX probe deadline", ctx.Err())
						case <-time.After(100 * time.Millisecond):
						}
					}
				}
				for _, lock := range before {
					probe(lock, "initial", true)
				}
				restart := func() {
					if err := os.WriteFile(filepath.Join(root, "restart-request"), []byte(name), 0600); err != nil {
						t.Fatal(err)
					}
					wait("restart-done", name)
				}
				if mode == "resume" {
					triggered := false
					output := filepath.Join(t.TempDir(), "output")
					n, err := s.GetResumeReclaim(ctx, name, output, func(done, total uint64) {
						if !triggered && done > 0 && done < total {
							triggered = true
							restart()
						}
					})
					if err != nil || n != int64(len(data)) || !triggered {
						t.Fatal("protected resume", n, triggered, err)
					}
					got, err := os.ReadFile(output)
					if err != nil || !bytes.Equal(got, data) {
						t.Fatal("resumed bytes differ", err)
					}
				} else {
					restart()
					if mode == "late" {
						wait("grace-ended", name)
					}
					err := s.Reclaim(ctx)
					if mode == "late" {
						if !errors.Is(err, nfs.NLMStatus(4)) {
							t.Fatal("late reclaim was not refused by kernel grace", err)
						}
						if err := s.Reclaim(ctx); err == nil || !strings.Contains(err.Error(), "already attempted") {
							t.Fatal("reclaim repeated", err)
						}
						if len(s.Client.Locks()) != 1 || !s.Client.Locks()[0].Uncertain {
							t.Fatal("late state not quarantined")
						}
						probe(before[0], "late-free", false)
						s.Client.Close()
						cleanup, err := nfs.Connect(ctx, cfg)
						if err != nil {
							t.Fatal(err)
						}
						defer cleanup.Close()
						if count, err := cleanup.RecoverNLMLocks(ctx); err != nil || count != 1 {
							t.Fatal("exact historical-owner cleanup", count, err)
						}
						t.Log("late reclaim rejected; historical owner cleaned without reacquisition")
						return
					}
					if err != nil {
						t.Fatal("reclaim", err)
					}
				}
				after := s.Client.Locks()
				if fmt.Sprint(before) != fmt.Sprint(after) || s.Client == c {
					t.Fatal("reclaimed inventory or connection", before, after)
				}
				wait("grace-ended", name)
				for _, lock := range after {
					probe(lock, "reclaimed", true)
					if err := s.Client.Unlock(ctx, lock.ID); err != nil {
						t.Fatal(err)
					}
					delete(s.LockPaths, lock.ID)
					probe(lock, "released", false)
				}
				t.Log("original inventory reclaimed, native conflicts observed, exact owners released")
			})
		}
	}
}
