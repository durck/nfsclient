package cli

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Also runs through NFS_VIEWER_TEST_BINARY. A denied staged upload must leave
// neither a destination nor staging entries in the owner's directory.
func TestVFSUploadDeniedCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_VFS") != "1" {
		t.Skip("requires disposable tests/vfs fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			for _, credential := range []string{"keytab", "ccache"} {
				if version == "3-udp" && security != "krb5" {
					continue
				}
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					t.Parallel()
					prefix, realm, spn := "NFS_VIEWER_KRB5_", "NFS.TEST", "nfs/server.nfs.test"
					aliceField := "ALICE_"
					if os.Getenv("NFS_VIEWER_VFS_AD") == "1" {
						prefix, realm, spn, aliceField = "NFS_VIEWER_AD_", "AD.NFS.TEST", "nfs/server.ad.nfs.test", ""
					}
					base := []string{"127.0.0.1", "--nfs-version", version, "--nfs-port", os.Getenv(prefix + "PORT"), "--mount-port", os.Getenv(prefix + "MOUNT_PORT"), "--sec", security, "--krb5-config", os.Getenv(prefix + "CONFIG"), "--spn", spn, "--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
					if version == "3-udp" {
						base = append(base, "--nfs-version", "3", "--transport", "udp", "--nfs-port", os.Getenv(prefix+"UDP_PORT"), "--mount-port", os.Getenv(prefix+"UDP_MOUNT_PORT"))
					}
					alice := append(append([]string(nil), base...), "--principal", "alice@"+realm)
					if credential == "ccache" {
						alice = append(alice, "--ccache", os.Getenv(prefix+aliceField+"CCACHE"))
					} else {
						alice = append(alice, "--keytab", os.Getenv(prefix+aliceField+"KEYTAB"))
					}
					bob := append(append([]string(nil), base...), "--principal", "bob@"+realm, "--keytab", os.Getenv(prefix+"BOB_KEYTAB"))
					run := func(args []string, commands ...string) (string, error) {
						t.Helper()
						a := append([]string(nil), args...)
						for _, cmd := range commands {
							a = append(a, "-c", cmd)
						}
						return runKerberosCLI(t, a)
					}
					dir := t.TempDir()
					src, dst := filepath.Join(dir, "source.bin"), filepath.Join(dir, "returned.bin")
					payload := bytes.Repeat([]byte{0, 255, 27, 'v', 'f', 's'}, 1500)
					if err := os.WriteFile(src, payload, 0600); err != nil {
						t.Fatal(err)
					}
					var nonce [12]byte
					if _, err := rand.Read(nonce[:]); err != nil {
						t.Fatal(err)
					}
					remote := fmt.Sprintf("denied-upload-%x", nonce)
					out, err := run(alice, "mkdir "+remote, "chmod 755 "+remote, "put "+strconv.Quote(src)+" "+remote+"/original")
					if err != nil {
						t.Fatalf("owner setup: %v %s", err, out)
					}
					out, err = run(bob, "put "+strconv.Quote(src)+" "+remote+"/forbidden")
					if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
						t.Fatalf("upload should be denied: %v %s", err, out)
					}
					out, err = run(alice, "ls "+remote, "get "+remote+"/original "+strconv.Quote(dst), "id")
					if err != nil || !strings.Contains(out, "1 entries") || !strings.Contains(out, "alice@"+realm+" ("+security+")") || strings.Contains(out, "AUTH_SYS") {
						t.Fatalf("denied upload left remote entries or changed identity: %v %s", err, out)
					}
					got, err := os.ReadFile(dst)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("denied upload changed original: %v", err)
					}
					if os.Getenv("NFS_VIEWER_VFS_POSIX_ACL") == "1" {
						aclDest := filepath.Join(dir, "acl.txt")
						out, err = run(alice, "get acl/read.txt "+strconv.Quote(aclDest))
						if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
							t.Fatalf("ACL must deny Alice: %v %s", err, out)
						}
						entries, err := os.ReadDir(dir)
						if err != nil || len(entries) != 2 {
							t.Fatalf("ACL denial left local files: %v %v", entries, err)
						}
						out, err = run(bob, "get acl/read.txt "+strconv.Quote(aclDest), "id")
						if err != nil || !strings.Contains(out, "bob@"+realm+" ("+security+")") || strings.Contains(out, "AUTH_SYS") {
							t.Fatalf("ACL must grant Bob: %v %s", err, out)
						}
						got, err = os.ReadFile(aclDest)
						if err != nil || string(got) != "ACL fixture data\n" {
							t.Fatalf("ACL read content: %v", err)
						}
						out, err = run(bob, "mkdir acl/"+remote)
						if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
							t.Fatalf("read-only ACL granted create: %v %s", err, out)
						}
						inherited := "acl-inherit/" + remote
						out, err = run(alice, "mkdir "+inherited, "put "+strconv.Quote(src)+" "+inherited+"/file", "chmod 640 "+inherited+"/file")
						if err != nil {
							t.Fatalf("inherited ACL upload: %v %s", err, out)
						}
						for i, mode := range []string{"640", "600", "640"} {
							out, err = run(alice, "chmod "+mode+" "+inherited+"/file")
							if err != nil {
								t.Fatalf("ACL mask change: %v %s", err, out)
							}
							local := filepath.Join(t.TempDir(), "inherited.bin")
							out, err = run(bob, "get "+inherited+"/file "+strconv.Quote(local), "id")
							if mode == "600" {
								if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
									t.Fatalf("masked ACL download: %v %s", err, out)
								}
								entries, readErr := os.ReadDir(filepath.Dir(local))
								if readErr != nil || len(entries) != 0 {
									t.Fatalf("masked ACL left local files: %v %v", entries, readErr)
								}
								continue
							}
							if err != nil || !strings.Contains(out, "bob@"+realm+" ("+security+")") || strings.Contains(out, "AUTH_SYS") {
								t.Fatalf("inherited ACL download %d: %v %s", i, err, out)
							}
							got, err := os.ReadFile(local)
							if err != nil || !bytes.Equal(got, payload) {
								t.Fatalf("inherited ACL changed content: %v", err)
							}
						}
					}
				})
			}
		}
	}
}
