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
	"time"

	"nfsclient/internal/testutil/kerberosfixture"
)

// Samba AD is independent of the MIT fixture. Passing this does not certify
// Microsoft AD, NAS policy, PAC group mapping, trusts, or alternative UPNs.
func TestSambaADCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_AD_CONFIG") == "" {
		t.Skip("requires tests/samba-ad fixture")
	}
	for _, enctype := range []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"} {
		for _, network := range []string{"tcp", "udp"} {
			for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
				for _, security := range []string{"krb5", "krb5i", "krb5p"} {
					if version == "3-udp" && security != "krb5" {
						continue
					}
					for _, credential := range []string{"keytab", "ccache"} {
						t.Run(enctype+"/"+network+"/"+version+"/"+security+"/"+credential, func(t *testing.T) {
							t.Parallel()
							args := sambaADArgs(t, network, version, security, credential, enctype, false)
							dir := t.TempDir()
							source, dest := filepath.Join(dir, "source.bin"), filepath.Join(dir, "received.bin")
							payload := bytes.Repeat([]byte{0, 27, 128, 255, 'a', 'd'}, 3000)
							if err := os.WriteFile(source, payload, 0600); err != nil {
								t.Fatal(err)
							}
							var nonce [12]byte
							if _, err := rand.Read(nonce[:]); err != nil {
								t.Fatal(err)
							}
							name := fmt.Sprintf("ad-cli-%x", nonce)
							out, err := runKerberosCLI(t, append(args, "-c", "put "+strconv.Quote(source)+" "+name, "-c", "chmod 600 "+name, "-c", "get "+name+" "+strconv.Quote(dest), "-c", "stat "+name, "-c", "id"))
							if err != nil || !strings.Contains(out, "alice@AD.NFS.TEST ("+security+")") || strings.Contains(out, "AUTH_SYS") || !strings.Contains(out, "UID/GID off") {
								t.Fatalf("AD transfer/identity: %v\n%s", err, out)
							}
							owner, group := `"uid": 20001`, `"gid": 20001`
							if strings.HasPrefix(version, "4") {
								owner, group = `"owner": "alice@ad.nfs.test"`, `"group": "alice@ad.nfs.test"`
							}
							if !strings.Contains(out, owner) || !strings.Contains(out, group) {
								t.Fatalf("AD principal mapped to unexpected owner: %s", out)
							}
							got, err := os.ReadFile(dest)
							if err != nil || !bytes.Equal(got, payload) {
								t.Fatalf("AD transfer contents: %v", err)
							}
							if credential == "keytab" && security == "krb5p" && (version == "3" || version == "4.2") {
								bob := append(append([]string(nil), args...), "--principal", "bob@AD.NFS.TEST", "--keytab", os.Getenv("NFS_VIEWER_AD_BOB_KEYTAB"))
								denied := filepath.Join(dir, "denied.bin")
								out, err := runKerberosCLI(t, append(bob, "-c", "get "+name+" "+strconv.Quote(denied)))
								if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
									t.Fatalf("Bob must be denied: %v %s", err, out)
								}
								entries, err := os.ReadDir(dir)
								if err != nil || len(entries) != 2 {
									t.Fatalf("denied download left data: %v %v", entries, err)
								}
								out, err = runKerberosCLI(t, append(args, "-c", "chmod 644 "+name))
								if err != nil {
									t.Fatalf("grant read: %v %s", err, out)
								}
								out, err = runKerberosCLI(t, append(bob, "-c", "get "+name+" "+strconv.Quote(denied), "-c", "id"))
								if err != nil || !strings.Contains(out, "bob@AD.NFS.TEST (krb5p)") || strings.Contains(out, "AUTH_SYS") {
									t.Fatalf("Bob granted read: %v %s", err, out)
								}
								got, err = os.ReadFile(denied)
								if err != nil || !bytes.Equal(got, payload) {
									t.Fatalf("Bob contents: %v", err)
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestSambaADRenewalCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_AD_CONFIG") == "" {
		t.Skip("requires tests/samba-ad fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			if version == "3-udp" && security != "krb5" {
				continue
			}
			for _, credential := range []string{"keytab", "ccache"} {
				// Samba rejects TGTs with <=120s left (kpasswd-ticket defense).
				// Keep real keytab expiry coverage on representative v3/v4 paths.
				if credential == "keytab" && (security != "krb5p" || (version != "3" && version != "4.2")) {
					continue
				}
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					t.Parallel()
					args := append(sambaADArgs(t, "tcp", version, security, credential, "aes256-cts-hmac-sha1-96", true), "--batch")
					idle := 5 * time.Second
					if credential == "keytab" {
						idle = 131 * time.Second
					}
					testKerberosRenewalCLIWithIdle(t, args, "alice@AD.NFS.TEST ("+security+")", idle)
				})
			}
		}
	}
}

func TestSambaADAuthenticationFailure(t *testing.T) {
	if os.Getenv("NFS_VIEWER_AD_CONFIG") == "" {
		t.Skip("requires tests/samba-ad fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, credential := range []string{"keytab", "ccache"} {
			t.Run(network+"/unknown-spn/"+credential, func(t *testing.T) {
				t.Parallel()
				args := sambaADArgs(t, network, "4.2", "krb5p", credential, "aes256-cts-hmac-sha1-96", false)
				out, err := runKerberosCLI(t, append(args, "--spn", "nfs/absent.ad.nfs.test", "-c", "pwd"))
				if err == nil || !strings.Contains(out+err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN") {
					t.Fatalf("unknown AD SPN must fail: %v %s", err, out)
				}
			})
		}
		t.Run(network+"/disabled-account", func(t *testing.T) {
			t.Parallel()
			args := sambaADArgs(t, network, "4.2", "krb5p", "keytab", "aes256-cts-hmac-sha1-96", false)
			out, err := runKerberosCLI(t, append(args, "--principal", "disabled@AD.NFS.TEST", "--keytab", os.Getenv("NFS_VIEWER_AD_DISABLED_KEYTAB"), "-c", "pwd"))
			if err == nil || !strings.Contains(out+err.Error(), "KDC_ERR_CLIENT_REVOKED") {
				t.Fatalf("disabled AD account must fail: %v %s", err, out)
			}
		})
		t.Run(network+"/cache-principal-mismatch", func(t *testing.T) {
			t.Parallel()
			args := sambaADArgs(t, network, "4.2", "krb5p", "ccache", "aes256-cts-hmac-sha1-96", false)
			out, err := runKerberosCLI(t, append(args, "--principal", "bob@AD.NFS.TEST", "-c", "pwd"))
			if err == nil || !strings.Contains(out+err.Error(), "ccache principal does not match") {
				t.Fatalf("foreign AD cache must fail: %v %s", err, out)
			}
		})
	}
}

func sambaADArgs(t *testing.T, network, version, security, credential, enctype string, short bool) []string {
	t.Helper()
	lifetime := ""
	if short {
		lifetime = "4s"
		if credential == "keytab" {
			lifetime = "130s"
		}
	}
	path := kerberosfixture.ADConfig(t, network, enctype, lifetime)
	args := []string{"127.0.0.1", "--nfs-version", version, "--sec", security, "--nfs-port", os.Getenv("NFS_VIEWER_AD_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_AD_MOUNT_PORT"), "--krb5-config", path, "--principal", "alice@AD.NFS.TEST", "--spn", "nfs/server.ad.nfs.test", "--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never", "--timeout", "5s"}
	if version == "3-udp" {
		args = append(args, "--nfs-version", "3", "--transport", "udp", "--nfs-port", os.Getenv("NFS_VIEWER_AD_UDP_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_AD_UDP_MOUNT_PORT"))
	}
	if credential == "ccache" {
		args = append(args, "--ccache", os.Getenv("NFS_VIEWER_AD_CCACHE"))
	} else {
		args = append(args, "--keytab", os.Getenv("NFS_VIEWER_AD_KEYTAB"))
	}
	return args
}
