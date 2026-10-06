package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// Capability-refused replacement uses the session API. Independent CLI reads
// additionally use the release binary when NFS_VIEWER_TEST_BINARY is set.
// Ganesha 4.3 VFS advertises ALLOW only but returns DENY entries. Do not turn
// that concrete incompatibility into success-or-any-error acceptance.
func TestVFSReplacementACLCapabilityRefusal(t *testing.T) {
	if os.Getenv("NFS_VIEWER_VFS") != "1" || os.Getenv("NFS_VIEWER_VFS_POSIX_ACL") != "1" {
		t.Skip("requires disposable ACL-enabled tests/vfs fixture")
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					t.Parallel()
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					prefix, realm, spn, aliceField := "NFS_VIEWER_KRB5_", "NFS.TEST", "nfs/server.nfs.test", "ALICE_"
					if os.Getenv("NFS_VIEWER_VFS_AD") == "1" {
						prefix, realm, spn, aliceField = "NFS_VIEWER_AD_", "AD.NFS.TEST", "nfs/server.ad.nfs.test", ""
					}
					port, err := strconv.Atoi(os.Getenv(prefix + "PORT"))
					if err != nil || port < 1 || port > 65535 {
						t.Fatal("invalid fixture NFS port")
					}
					config := nfs.Config{Host: "127.0.0.1", Version: version, Transport: "tcp", Security: security, NFSPort: port, Timeout: 5 * time.Second}
					config.Kerberos = nfs.KerberosConfig{ConfigFile: os.Getenv(prefix + "CONFIG"), Principal: "alice@" + realm, SPN: spn}
					if credential == "ccache" {
						config.Kerberos.CCache = os.Getenv(prefix + aliceField + "CCACHE")
					} else {
						config.Kerberos.Keytab = os.Getenv(prefix + aliceField + "KEYTAB")
					}
					if config.Kerberos.CCache == "" && config.Kerberos.Keytab == "" {
						t.Fatal("missing explicit Alice fixture credential")
					}
					bobCfg := config
					bobCfg.Kerberos.Principal, bobCfg.Kerberos.CCache = "bob@"+realm, ""
					bobCfg.Kerberos.Keytab = os.Getenv(prefix + "BOB_KEYTAB")
					if bobCfg.Kerberos.Keytab == "" {
						t.Fatal("missing explicit Bob fixture keytab")
					}
					connect := func(cfg nfs.Config) *session.Session {
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
					alice, bob := connect(config), connect(bobCfg)
					cliArgs := func(cfg nfs.Config) []string {
						a := []string{cfg.Host, "--nfs-version", version, "--nfs-port", strconv.Itoa(port), "--export", "/data", "--sec", security, "--krb5-config", cfg.Kerberos.ConfigFile, "--principal", cfg.Kerberos.Principal, "--spn", spn, "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
						if cfg.Kerberos.CCache != "" {
							return append(a, "--ccache", cfg.Kerberos.CCache)
						}
						return append(a, "--keytab", cfg.Kerberos.Keytab)
					}
					read := func(t *testing.T, s *session.Session, path string, want []byte, allowed bool) {
						t.Helper()
						var out bytes.Buffer
						_, err := s.Cat(ctx, path, &out)
						if !allowed {
							if !errors.Is(err, nfs.Status(13)) || out.Len() != 0 {
								t.Fatalf("expected read denial without bytes: %v (%d bytes)", err, out.Len())
							}
						} else if err != nil || !bytes.Equal(out.Bytes(), want) {
							t.Fatalf("read %s: %v (%d bytes)", path, err, out.Len())
						}
					}
					cliRead := func(t *testing.T, cfg nfs.Config, path string, want []byte, allowed bool) {
						t.Helper()
						dir := t.TempDir()
						local := filepath.Join(dir, "download")
						a := append(cliArgs(cfg), "-c", "id", "-c", "get "+strconv.Quote(path)+" "+strconv.Quote(local))
						out, err := runKerberosCLI(t, a)
						if !strings.Contains(out, cfg.Kerberos.Principal+" ("+security+")") || strings.Contains(out, "AUTH_SYS") {
							t.Fatalf("CLI identity/security changed: %v %s", err, out)
						}
						if !allowed {
							entries, readErr := os.ReadDir(dir)
							if err == nil || !strings.Contains(out+err.Error(), "permission denied") || readErr != nil || len(entries) != 0 {
								t.Fatalf("CLI denial/publication: %v %s; entries=%v error=%v", err, out, entries, readErr)
							}
							return
						}
						got, readErr := os.ReadFile(local)
						if err != nil || readErr != nil || !bytes.Equal(got, want) {
							t.Fatalf("CLI download: %v %v %s", err, readErr, out)
						}
					}
					for _, grant := range []bool{true, false} {
						name := "retain-denial"
						if grant {
							name = "retain-grant"
						}
						t.Run(name, func(t *testing.T) {
							var nonce [12]byte
							if _, err := rand.Read(nonce[:]); err != nil {
								t.Fatal(err)
							}
							base := fmt.Sprintf("replace-%x", nonce)
							plain, inherited := base, "acl-inherit/"+base
							for _, parent := range []string{plain, inherited} {
								if err := alice.Mkdir(ctx, parent); err != nil {
									t.Fatal(err)
								}
								if err := alice.Chmod(ctx, parent, 0750); err != nil {
									t.Fatal(err)
								}
							}
							// The plain parent needs traversal for Bob without a default ACL.
							if err := alice.Chmod(ctx, plain, 0755); err != nil {
								t.Fatal(err)
							}
							from, to := plain, inherited
							if grant {
								from, to = inherited, plain
							}
							parent, _, err := alice.Resolve(ctx, from, true)
							if err != nil {
								t.Fatal(err)
							}
							original, err := alice.Client.Create(ctx, parent.Handle, "file", 0640, false)
							if err != nil {
								t.Fatal(err)
							}
							old := []byte("old ACL contents\n")
							if _, err := alice.Client.WriteFrom(ctx, original.Handle, bytes.NewReader(old)); err != nil {
								t.Fatal(err)
							}
							destParent, _, err := alice.Resolve(ctx, to, true)
							if err != nil {
								t.Fatal(err)
							}
							if err := alice.Client.Rename(ctx, parent.Handle, "file", destParent.Handle, "file"); err != nil {
								t.Fatal(err)
							}
							remote := to + "/file"
							before, _, err := alice.Resolve(ctx, remote, true)
							if err != nil {
								t.Fatal(err)
							}
							bobFile, _, err := bob.Resolve(ctx, remote, true)
							if err != nil {
								t.Fatalf("Bob must traverse and LOOKUP before testing file access: %v", err)
							}
							read(t, bob, remote, old, grant)
							cliRead(t, bobCfg, remote, old, grant)
							payload := bytes.Repeat([]byte{0, 255, 27, 'a', 'c', 'l'}, 18000)
							local := filepath.Join(t.TempDir(), "source")
							if err := os.WriteFile(local, payload, 0600); err != nil {
								t.Fatal(err)
							}
							observedBytes := false
							n, err := alice.PutWithOptions(ctx, local, remote, session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
								observedBytes = observedBytes || done > 0
							}})
							const refusal = "ACL entry type 1 is not advertised by ACL support flags 0x1"
							if n != 0 || observedBytes || err == nil || !strings.Contains(err.Error(), refusal) {
								t.Fatalf("expected specific capability refusal before payload: %d %v", n, err)
							}
							read(t, alice, remote, old, true)
							read(t, bob, remote, old, grant)
							after, _, err := alice.Resolve(ctx, remote, true)
							if err != nil || !bytes.Equal(after.Handle, before.Handle) || !reflect.DeepEqual(after.Attr, before.Attr) {
								t.Fatalf("refusal changed original handle/metadata: %v", err)
							}
							if _, err := bob.Client.WriteFrom(ctx, bobFile.Handle, strings.NewReader("forbidden")); !errors.Is(err, nfs.Status(13)) {
								t.Fatalf("Bob write must remain denied: %v", err)
							}
							for _, s := range []*session.Session{alice, bob} {
								want := config.Kerberos.Principal
								if s == bob {
									want = bobCfg.Kerberos.Principal
								}
								if s.Client.Identity() != want+" ("+security+")" || s.Client.Security() != security {
									t.Fatal("refusal switched session identity/security")
								}
							}
							cliRead(t, config, remote, old, true)
							cliRead(t, bobCfg, remote, old, grant)
							entries, err := alice.LS(ctx, to)
							if err != nil || len(entries) != 1 || entries[0].Name != "file" || entries[0].Attr.Mode&0777 != 0640 {
								t.Fatalf("replacement metadata/cleanup: %v %v", entries, err)
							}
							t.Logf("VFS_ACL_REFUSAL path=%s bob_before=%t bob_after=%t uploaded=0", remote, grant, grant)
						})
					}
				})
			}
		}
	}
}
