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

// Exercises the actual transfer publication and identity display, optionally
// through each release binary, against distinct non-root GSS principals.
func TestKerberosUserCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_ALICE_KEYTAB") == "" {
		t.Skip("requires tests/kerberos ordinary-user credentials")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			if version == "3-udp" && security != "krb5" {
				continue
			}
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					if credential == "ccache" && os.Getenv("NFS_VIEWER_KRB5_ALICE_CCACHE") == "" {
						t.Skip("requires explicit Alice FILE cache")
					}
					args := []string{"127.0.0.1", "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"),
						"--nfs-version", version, "--sec", security, "--krb5-config", os.Getenv("NFS_VIEWER_KRB5_CONFIG"), "--spn", "nfs/server.nfs.test",
						"--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
					if version == "3-udp" {
						args = append(args, "--nfs-version", "3", "--transport", "udp", "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
					}
					alice := append(append([]string(nil), args...), "--principal", "alice@NFS.TEST")
					if credential == "ccache" {
						alice = append(alice, "--ccache", os.Getenv("NFS_VIEWER_KRB5_ALICE_CCACHE"))
					} else {
						alice = append(alice, "--keytab", os.Getenv("NFS_VIEWER_KRB5_ALICE_KEYTAB"))
					}
					bob := append(append([]string(nil), args...), "--principal", "bob@NFS.TEST", "--keytab", os.Getenv("NFS_VIEWER_KRB5_BOB_KEYTAB"))
					run := func(base []string, commands ...string) (string, error) {
						a := append([]string(nil), base...)
						for _, command := range commands {
							a = append(a, "-c", command)
						}
						return runKerberosCLI(t, a)
					}
					dir := t.TempDir()
					source, dest := filepath.Join(dir, "source.bin"), filepath.Join(dir, "received.bin")
					payload := bytes.Repeat([]byte{0, 27, 128, 255, 'u', 's', 'e', 'r'}, 2100)
					if err := os.WriteFile(source, payload, 0600); err != nil {
						t.Fatal(err)
					}
					var nonce [12]byte
					if _, err := rand.Read(nonce[:]); err != nil {
						t.Fatal(err)
					}
					name := fmt.Sprintf("user-cli-%x", nonce)
					out, err := run(alice, "put "+strconv.Quote(source)+" "+name, "chmod 600 "+name, "id", "root verify")
					if err != nil || !strings.Contains(out, "alice@NFS.TEST ("+security+")") || strings.Contains(out, "AUTH_SYS") || !strings.Contains(out, "UID/GID off") {
						t.Fatalf("Alice upload/identity: %v\n%s", err, out)
					}
					out, err = run(bob, "get "+name+" "+strconv.Quote(dest))
					// ExecuteContext returns errors; the main entry point prints them.
					if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
						t.Fatalf("Bob download should be denied: %v\n%s", err, out)
					}
					entries, err := os.ReadDir(dir)
					if err != nil || len(entries) != 1 || entries[0].Name() != "source.bin" {
						t.Fatalf("denied download published a destination or left staging data: %v, %v", entries, err)
					}
					out, err = run(alice, "chmod 644 "+name)
					if err != nil {
						t.Fatalf("grant read: %v\n%s", err, out)
					}
					out, err = run(bob, "get "+name+" "+strconv.Quote(dest), "id")
					if err != nil || !strings.Contains(out, "bob@NFS.TEST ("+security+")") || strings.Contains(out, "AUTH_SYS") {
						t.Fatalf("Bob granted download: %v\n%s", err, out)
					}
					got, err := os.ReadFile(dest)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("granted download contents: %v", err)
					}
				})
			}
		}
	}
}
