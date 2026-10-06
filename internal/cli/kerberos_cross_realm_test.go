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

	"nfsclient/internal/testutil/kerberosfixture"
)

// CLIENT.TEST owns the user/TGT; NFS.TEST owns only the service and incoming
// trust key. A successful AP exchange therefore requires the actual trust path.
func TestKerberosCrossRealmCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_CROSS_CONFIG") == "" {
		t.Skip("requires the disposable two-realm MIT fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				if version == "3-udp" && security != "krb5" {
					continue
				}
				for _, credential := range []string{"keytab", "ccache"} {
					t.Run(network+"/"+version+"/"+security+"/"+credential, func(t *testing.T) {
						t.Parallel()
						args := crossRealmArgs(t, network, version, security, credential, "NFS.TEST")
						dir := t.TempDir()
						source, dest := filepath.Join(dir, "source.bin"), filepath.Join(dir, "received.bin")
						payload := bytes.Repeat([]byte{0, 27, 128, 255, 'c', 'r', 'o', 's', 's'}, 2100)
						if err := os.WriteFile(source, payload, 0600); err != nil {
							t.Fatal(err)
						}
						var nonce [12]byte
						if _, err := rand.Read(nonce[:]); err != nil {
							t.Fatal(err)
						}
						name := fmt.Sprintf("cross-cli-%x", nonce)
						out, err := runKerberosCLI(t, append(args, "-c", "put "+strconv.Quote(source)+" "+name, "-c", "chmod 600 "+name, "-c", "get "+name+" "+strconv.Quote(dest), "-c", "stat "+name, "-c", "id"))
						if err != nil || !strings.Contains(out, "alice@CLIENT.TEST ("+security+")") || strings.Contains(out, "AUTH_SYS") || !strings.Contains(out, "UID/GID off") {
							t.Fatalf("cross-realm upload/identity: %v\n%s", err, out)
						}
						owner, group := `"uid": 20001`, `"gid": 20001`
						if strings.HasPrefix(version, "4") {
							owner, group = `"owner": "alice@nfs.test"`, `"group": "alice@nfs.test"`
						}
						if !strings.Contains(out, owner) || !strings.Contains(out, group) {
							t.Fatalf("foreign principal did not map to Alice's ownership: %s", out)
						}
						got, err := os.ReadFile(dest)
						if err != nil || !bytes.Equal(got, payload) {
							t.Fatalf("cross-realm content: %v", err)
						}
						// The foreign user maps to unprivileged Alice, not to root or Bob.
						// Verify denied file access on representative v3/v4 TCP cases.
						if network == "tcp" && credential == "keytab" && security == "krb5p" && (version == "3" || version == "4.2") {
							bob := append(append([]string(nil), args...), "--principal", "bob@NFS.TEST", "--keytab", os.Getenv("NFS_VIEWER_KRB5_BOB_KEYTAB"))
							denied := filepath.Join(dir, "denied.bin")
							out, err := runKerberosCLI(t, append(bob, "-c", "get "+name+" "+strconv.Quote(denied)))
							if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
								t.Fatalf("Bob should be denied: %v %s", err, out)
							}
							entries, err := os.ReadDir(dir)
							if err != nil || len(entries) != 2 {
								t.Fatalf("denied download left data: %v %v", entries, err)
							}
						}
					})
				}
			}
		}
		for _, credential := range []string{"keytab", "ccache"} {
			t.Run(network+"/no-trust/"+credential, func(t *testing.T) {
				t.Parallel()
				args := crossRealmArgs(t, network, "4.2", "krb5p", credential, "MISSING.TEST")
				out, err := runKerberosCLI(t, append(args, "-c", "pwd"))
				if err == nil || !strings.Contains(out+err.Error(), "KDC_ERR_S_PRINCIPAL_UNKNOWN") {
					t.Fatalf("absent trust must fail: %v %s", err, out)
				}
			})
		}
	}
}

func crossRealmArgs(t *testing.T, network, version, security, credential, targetRealm string) []string {
	t.Helper()
	path := kerberosfixture.CrossRealmConfig(t, network, targetRealm)
	args := []string{"127.0.0.1", "--nfs-version", version, "--sec", security, "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"), "--krb5-config", path, "--principal", "alice@CLIENT.TEST", "--spn", "nfs/server.nfs.test", "--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never", "--timeout", "5s"}
	if version == "3-udp" {
		args = append(args, "--nfs-version", "3", "--transport", "udp", "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
	}
	if credential == "ccache" {
		args = append(args, "--ccache", os.Getenv("NFS_VIEWER_KRB5_CROSS_CCACHE"))
	} else {
		args = append(args, "--keytab", os.Getenv("NFS_VIEWER_KRB5_CROSS_KEYTAB"))
	}
	return args
}

func TestKerberosCrossRealmRenewalCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_CROSS_CONFIG") == "" || os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires direct-trust MIT fixture with four-second service tickets")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				if version == "3-udp" && security != "krb5" {
					continue
				}
				for _, credential := range []string{"keytab", "ccache"} {
					t.Run(network+"/"+version+"/"+security+"/"+credential, func(t *testing.T) {
						t.Parallel()
						args := append(crossRealmArgs(t, network, version, security, credential, "NFS.TEST"), "--batch")
						testKerberosRenewalCLI(t, args, "alice@CLIENT.TEST ("+security+")")
					})
				}
			}
		}
	}
}
