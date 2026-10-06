package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func TestReadFailoverSyntax(t *testing.T) {
	sh, _, _ := testShell(t)
	for _, line := range []string{"reget --failover", "reget --failover host:1 source", "reget --failover host:1,, --retries 2 source", "reget --failover host:1,, --reclaim-locks source", "reget --retries 1 --failover host:1,, source", "reget --failover host:1,, source local extra"} {
		if _, err := sh.Execute(context.Background(), line); err == nil {
			t.Fatal("accepted", line)
		}
	}
}

// Native Ganesha/MEM filesystem and MIT KDC. The relay forwards bytes unchanged
// and terminates only this test's connection after confirmed download progress.
func TestNativeReadFailover(t *testing.T) {
	if os.Getenv("NFS_VIEWER_READ_FAILOVER") != "1" {
		t.Skip("requires isolated tests/kerberos fixture")
	}
	port, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_PORT"))
	if err != nil || port == 0 {
		t.Fatal("missing NFS fixture port")
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5i", "krb5p"} {
			for _, mode := range []string{"recover", "fallback", "second-loss", "prefix", "source", "identity", "base-identity", "relock", "denied", "budget", "cancel", "default", "duplicate", "local", "cli"} {
				t.Run(version+"/"+security+"/"+mode, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
					defer cancel()
					first, second := newDownloadRelay(t, port), newDownloadRelay(t, port)
					cfg := nfs.Config{Host: "127.0.0.1", NFSPort: first.port(), Version: version, Transport: "tcp", Security: security, Timeout: 3 * time.Second,
						Kerberos: nfs.KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
					c, err := nfs.Connect(ctx, cfg)
					if err != nil {
						t.Fatal(err)
					}
					s := session.New(c, cfg.Host, false, false, io.Discard)
					t.Cleanup(func() { s.Client.Close() })
					if err := s.Use(ctx, "/data"); err != nil {
						t.Fatal(err)
					}
					payload := bytes.Repeat([]byte("protected-read-failover\x00"), 10000)
					local := filepath.Join(t.TempDir(), "input")
					if err := os.WriteFile(local, payload, 0600); err != nil {
						t.Fatal(err)
					}
					remote := fmt.Sprintf("failover-%s-%d", runtime.GOOS, time.Now().UnixNano())
					if _, err := s.Put(ctx, local, remote); err != nil {
						t.Fatal(err)
					}
					defer func() {
						cleanup, stop := context.WithTimeout(context.Background(), time.Second)
						defer stop()
						if s.Client != c {
							s.Remove(cleanup, remote)
						}
					}()
					dest := filepath.Join(t.TempDir(), "output")
					targets := []nfs.ReadReplica{{Address: fmt.Sprintf("127.0.0.1:%d", second.port()), SPN: cfg.Kerberos.SPN}}
					if mode == "denied" {
						targets[0].SPN = "nfs/unapproved.test"
					}
					if mode == "budget" {
						targets[0].Address = "127.0.0.1:1"
					}
					if mode == "fallback" {
						targets = append([]nfs.ReadReplica{{Address: "127.0.0.1:1", SPN: cfg.Kerberos.SPN}}, targets...)
					}
					if mode == "duplicate" {
						targets = append(targets, targets[0])
					}
					if mode == "local" {
						if err := os.WriteFile(dest, []byte("existing"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					cuts, starts := 0, 0
					progress := func(done, _ uint64) {
						if done == 0 {
							starts++
						}
						if done >= 32768 && cuts == 0 {
							cuts++
							if mode == "source" {
								if err := s.Chmod(ctx, remote, 0640); err != nil {
									t.Fatal(err)
								}
							}
							if mode == "relock" {
								if _, err := s.Lock(ctx, remote, false); err != nil {
									t.Fatal(err)
								}
							}
							if mode == "identity" {
								s.Client.Auth.Groups = []uint32{123}
							}
							if mode == "base-identity" {
								s.BaseAuth.Groups = []uint32{123}
							}
							if mode == "cancel" {
								cancel()
							}
							first.cut()
						} else if done >= 32768 && s.Client != c && cuts == 1 && mode == "second-loss" {
							cuts++
							second.cut()
						}
					}
					if mode == "prefix" {
						bad := bytes.Clone(payload[:32768])
						bad[0] ^= 1
						if err := os.WriteFile(dest+".nfs-part", bad, 0600); err != nil {
							t.Fatal(err)
						}
					}
					var count int64
					if mode == "default" {
						count, err = s.GetResume(ctx, remote, dest, progress)
					} else if mode == "cli" {
						// Exercise parser/routing; failure injection belongs to API cases.
						sh := &Shell{Session: s, Out: io.Discard, Err: io.Discard, LocalDir: filepath.Dir(dest)}
						_, err = sh.Execute(ctx, fmt.Sprintf("reget --failover %s,%s, %s %s", targets[0].Address, targets[0].SPN, remote, strconv.Quote(dest)))
					} else {
						count, err = s.GetResumeFailover(ctx, remote, dest, targets, progress)
					}
					if mode == "recover" || mode == "fallback" || mode == "cli" {
						if err != nil {
							t.Fatal(err)
						}
						assertRecoveryFile(t, dest, payload)
						if mode != "cli" && (count != int64(len(payload)) || s.Client == c || cuts != 1 || starts != 2) {
							t.Fatalf("count=%d cuts=%d starts=%d", count, cuts, starts)
						}
					} else {
						if err == nil {
							t.Fatal("unsafe case published")
						}
						if mode != "local" {
							if _, err := os.Stat(dest); !os.IsNotExist(err) {
								t.Fatal("destination published", err)
							}
						}
						if mode != "second-loss" && mode != "source" && s.Client != c {
							t.Fatal("unexpected connection switch", err)
						}
						if mode == "prefix" && !errors.Is(err, session.ErrResumePrefix) {
							t.Fatal(err)
						}
						if mode == "duplicate" || mode == "local" {
							if cuts != 0 || starts != 0 {
								t.Fatal("invalid input touched data")
							}
						}
						if mode == "second-loss" && cuts != 2 {
							t.Fatal("second loss not exercised")
						}
					}
					if _, err := os.Stat(dest + ".nfs-part.lock"); !os.IsNotExist(err) {
						t.Fatal("resume exclusion leaked", err)
					}
					t.Logf("NATIVE_READ_FAILOVER os=%s version=%s security=%s mode=%s cuts=%d starts=%d", runtime.GOOS, version, security, mode, cuts, starts)
				})
			}
		}
	}
}

func TestReadFailoverHelp(t *testing.T) {
	sh, _, out := testShell(t)
	if _, err := sh.Execute(context.Background(), "help"); err != nil || !strings.Contains(out.String(), "--failover HOST:PORT,SPN,TLS_NAME") {
		t.Fatal("missing failover help", err)
	}
}

func TestResumeRetrySessionGuard(t *testing.T) {
	for _, mode := range []string{"identity", "base-identity", "namespace"} {
		t.Run(mode, func(t *testing.T) {
			sh, root, _ := testShell(t)
			payload := bytes.Repeat([]byte("fixed-read-session"), 4096)
			if err := os.WriteFile(filepath.Join(root, "source"), payload, 0600); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(sh.LocalDir, "guarded")
			_, err := sh.Session.GetResumeRetry(context.Background(), "source", dest, 1, func(done, total uint64) {
				if done == total {
					switch mode {
					case "identity":
						sh.Session.Client.Auth.Groups = []uint32{123}
					case "base-identity":
						sh.Session.BaseAuth.Groups = []uint32{123}
					case "namespace":
						sh.Session.CWD = "/different"
					}
				}
			})
			if err == nil {
				t.Fatal("changed fixed session published a download")
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("destination published", err)
			}
		})
	}
}
