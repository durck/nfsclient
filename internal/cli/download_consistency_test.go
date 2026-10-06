package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
	"nfsclient/internal/testutil/nfsv2"
)

func TestDownloadChangedSourceIsNotPublished(t *testing.T) {
	for _, overwrite := range []bool{false, true} {
		for _, change := range []string{"grow", "shrink", "rewrite", "after-last-read", "final-getattr-fails"} {
			t.Run(fmt.Sprintf("overwrite=%t/%s", overwrite, change), func(t *testing.T) {
				sh, root, _ := testShell(t)
				sh.Session.Client.ReadSize = 1024
				source := filepath.Join(root, "source")
				original := bytes.Repeat([]byte("source-data"), 1000)
				if err := os.WriteFile(source, original, 0600); err != nil {
					t.Fatal(err)
				}
				oldTime := time.Unix(1500000000, 0)
				if err := os.Chtimes(source, oldTime, oldTime); err != nil {
					t.Fatal(err)
				}
				dest := filepath.Join(sh.LocalDir, "result")
				if overwrite {
					if err := os.WriteFile(dest, []byte("original destination"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				changed := false
				n, err := sh.Session.GetWithOptions(context.Background(), "source", dest, session.TransferOptions{Overwrite: overwrite, Progress: func(done, total uint64) {
					if done > uint64(len(original)) {
						t.Fatalf("download exceeded original size: %d", done)
					}
					if done == 0 || changed {
						return
					}
					if (change == "after-last-read" || change == "final-getattr-fails") && done != total {
						return
					}
					changed = true
					var mutationErr error
					switch change {
					case "grow":
						mutationErr = os.WriteFile(source, append(append([]byte(nil), original...), original...), 0600)
					case "shrink":
						mutationErr = os.Truncate(source, 1024)
					case "rewrite", "after-last-read":
						mutationErr = os.WriteFile(source, bytes.Repeat([]byte("X"), len(original)), 0600)
					case "final-getattr-fails":
						mutationErr = os.Remove(source)
					}
					if mutationErr != nil {
						t.Fatal(mutationErr)
					}
					if change != "final-getattr-fails" {
						if err := os.Chtimes(source, oldTime, oldTime.Add(time.Hour)); err != nil {
							t.Fatal(err)
						}
					}
				}})
				if !changed || err == nil || n > int64(len(original)) {
					t.Fatalf("changed source accepted: changed=%t bytes=%d error=%v", changed, n, err)
				}
				data, readErr := os.ReadFile(dest)
				if overwrite {
					if readErr != nil || string(data) != "original destination" {
						t.Fatalf("original destination changed: %q %v", data, readErr)
					}
				} else if !os.IsNotExist(readErr) {
					t.Fatalf("changed download published: %d bytes %v", len(data), readErr)
				}
				leftovers, err := filepath.Glob(filepath.Join(sh.LocalDir, ".nfs-download-*"))
				if err != nil || len(leftovers) != 0 {
					t.Fatalf("temporary download leaked: %v %v", leftovers, err)
				}
			})
		}
	}
}

// Real independent writer sessions change the selected object during a download.
// Reuse only explicitly configured loopback UNFS3/MIT-Ganesha fixtures.
func TestDownloadMutationServers(t *testing.T) {
	profiles := []struct{ version, transport, security string }{{"3", "tcp", "sys"}, {"3", "udp", "sys"}}
	for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			profiles = append(profiles, struct{ version, transport, security string }{version, "tcp", security})
		}
	}
	profiles = append(profiles, struct{ version, transport, security string }{"3", "udp", "krb5"})
	for _, profile := range profiles {
		t.Run(profile.version+"/"+profile.transport+"/"+profile.security, func(t *testing.T) {
			var cfg nfs.Config
			if profile.security == "sys" {
				cfg = unfsCLIConfig(t, profile.transport)
			} else {
				if os.Getenv("NFS_VIEWER_KRB5_PORT") == "" {
					t.Skip("requires disposable MIT/Ganesha fixture")
				}
				port := func(name string) int {
					t.Helper()
					n, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_" + name))
					if err != nil || n < 1 || n > 65535 {
						t.Fatalf("invalid fixture port %s", name)
					}
					return n
				}
				cfg = nfs.Config{Host: "127.0.0.1", Version: profile.version, Transport: profile.transport, Security: profile.security, Timeout: 3 * time.Second, NFSPort: port("PORT"), MountPort: port("MOUNT_PORT"), Kerberos: nfs.KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
				if profile.transport == "udp" {
					cfg.NFSPort = port("UDP_PORT")
					cfg.MountPort = port("UDP_MOUNT_PORT")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			connect := func() *session.Session {
				t.Helper()
				c, err := nfs.Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				s := session.New(c, cfg.Host, false, false, nil)
				if err := s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				return s
			}
			s, writer := connect(), connect()
			s.Client.ReadSize = 1024
			for _, overwrite := range []bool{false, true} {
				for _, atEnd := range []bool{false, true} {
					t.Run(fmt.Sprintf("overwrite=%t/at-end=%t", overwrite, atEnd), func(t *testing.T) {
						var token [12]byte
						if _, err := rand.Read(token[:]); err != nil {
							t.Fatal(err)
						}
						name := fmt.Sprintf("changing-%x", token)
						payload := bytes.Repeat([]byte("original"), 2048)
						changedPayload := bytes.Repeat([]byte("X"), len(payload))
						dir := t.TempDir()
						src := filepath.Join(dir, "source")
						dest := filepath.Join(dir, "dest")
						if err := os.WriteFile(src, payload, 0600); err != nil {
							t.Fatal(err)
						}
						if _, err := s.Put(ctx, src, name); err != nil {
							t.Fatal(err)
						}
						node, _, err := writer.Resolve(ctx, name, true)
						if err != nil {
							t.Fatal(err)
						}
						if overwrite {
							if err := os.WriteFile(dest, []byte("preserved"), 0600); err != nil {
								t.Fatal(err)
							}
						}
						changed := false
						_, err = s.GetWithOptions(ctx, name, dest, session.TransferOptions{Overwrite: overwrite, Progress: func(done, total uint64) {
							if changed || done == 0 || atEnd && done != total {
								return
							}
							changed = true
							if profile.security == "sys" && os.Getenv("NFS_VIEWER_UNFS_COARSE_TIME_DIAGNOSTIC") != "1" {
								// UNFS3 emits whole-second timestamps. Exercise observable
								// changes; the opt-in diagnostic retains the fast-write gap.
								timer := time.NewTimer(1100 * time.Millisecond)
								defer timer.Stop()
								select {
								case <-timer.C:
								case <-ctx.Done():
									t.Fatal(ctx.Err())
								}
							}
							if _, err := writer.Client.WriteFrom(ctx, node.Handle, bytes.NewReader(changedPayload)); err != nil {
								t.Fatal(err)
							}
						}})
						if !changed || !errors.Is(err, session.ErrDownloadSourceChanged) {
							t.Fatalf("changed object accepted: %v", err)
						}
						data, readErr := os.ReadFile(dest)
						if overwrite {
							if readErr != nil || string(data) != "preserved" {
								t.Fatalf("original changed: %q %v", data, readErr)
							}
						} else if !os.IsNotExist(readErr) {
							t.Fatalf("partial published: %v", readErr)
						}
						left, err := filepath.Glob(filepath.Join(dir, ".nfs-download-*"))
						if err != nil || len(left) != 0 {
							t.Fatalf("leaked temp: %v %v", left, err)
						}
						if _, err := s.GetWithOptions(ctx, name, dest, session.TransferOptions{Overwrite: overwrite}); err != nil {
							t.Fatalf("stable retry: %v", err)
						}
						data, err = os.ReadFile(dest)
						if err != nil || !bytes.Equal(data, changedPayload) {
							t.Fatalf("stable bytes differ: %v", err)
						}
						if s.Client.Security() != cfg.Security && !(cfg.Security == "" && s.Client.Security() == "sys") {
							t.Fatal("identity/security changed")
						}
					})
				}
			}
		})
	}
}

func TestV2DownloadSizeChangeIsNotPublished(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, overwrite := range []bool{false, true} {
			for _, grow := range []bool{false, true} {
				t.Run(fmt.Sprintf("udp=%t/overwrite=%t/grow=%t", udp, overwrite, grow), func(t *testing.T) {
					server := nfsv2.Start(t, nfsv2.Options{UDP: udp})
					original := bytes.Repeat([]byte("X"), 32768)
					server.Seed("source", original, 0600)
					s := v2Session(t, server)
					dir := t.TempDir()
					dest := filepath.Join(dir, "result")
					if overwrite {
						if err := os.WriteFile(dest, []byte("preserved"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					changed := false
					n, err := s.GetWithOptions(context.Background(), "source", dest, session.TransferOptions{Overwrite: overwrite, Progress: func(done, total uint64) {
						if changed || done == 0 {
							return
						}
						changed = true
						data := original[:1024]
						if grow {
							data = append(append([]byte(nil), original...), original...)
						}
						if err := server.UpdateFile("source", data); err != nil {
							t.Fatal(err)
						}
					}})
					if !changed || err == nil || n > int64(len(original)) {
						t.Fatalf("v2 changed source accepted: %d %v", n, err)
					}
					data, readErr := os.ReadFile(dest)
					if overwrite {
						if readErr != nil || string(data) != "preserved" {
							t.Fatalf("original changed: %q %v", data, readErr)
						}
					} else if !os.IsNotExist(readErr) {
						t.Fatalf("partial published: %v", readErr)
					}
					entries, err := os.ReadDir(dir)
					want := 0
					if overwrite {
						want = 1
					}
					if err != nil || len(entries) != want {
						t.Fatalf("download leftovers: %v %v", entries, err)
					}
				})
			}
		}
	}
}
