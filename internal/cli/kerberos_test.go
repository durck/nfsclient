package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicitly opt in to tests/kerberos's loopback-only MIT KDC/Ganesha fixture.
func TestKerberosGanesha(t *testing.T) {
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) { testKerberosGanesha(t, security) })
	}
}

func TestKerberosGaneshaUDP(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_UDP_PORT") == "" {
		t.Skip("requires UDP Kerberos fixture")
	}
	t.Run("krb5", func(t *testing.T) { testKerberosGanesha(t, "krb5") })
	if os.Getenv("NFS_VIEWER_KRB5_CCACHE") != "" {
		t.Run("ccache", func(t *testing.T) { testKerberosGanesha(t, "krb5") })
	}
	if os.Getenv("NFS_VIEWER_KRB5_UDP_REPAIRED") == "1" {
		for _, security := range []string{"krb5i", "krb5p"} {
			t.Run(security, func(t *testing.T) { testKerberosGanesha(t, security) })
		}
	}
}

func TestKerberosCCache(t *testing.T) {
	cache := os.Getenv("NFS_VIEWER_KRB5_CCACHE")
	if cache == "" {
		t.Skip("requires explicit MIT FILE cache fixture")
	}
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) { testKerberosGanesha(t, security) })
	}
}

func TestKerberosGaneshaV4(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_V4") != "1" {
		t.Skip("requires v4-enabled Kerberos fixture")
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				testKerberosGanesha(t, security, "--nfs-version", version)
			})
		}
	}
}

func TestKerberosCCacheV4(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_V4") != "1" || os.Getenv("NFS_VIEWER_KRB5_CCACHE") == "" {
		t.Skip("requires v4-enabled Kerberos FILE cache fixture")
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				testKerberosGanesha(t, security, "--nfs-version", version)
			})
		}
	}
}

func testKerberosGanesha(t *testing.T, security string, extra ...string) {
	port := os.Getenv("NFS_VIEWER_KRB5_PORT")
	if port == "" {
		t.Skip("start tests/kerberos and provide fixture credentials/ports")
	}
	args := []string{"127.0.0.1", "--nfs-port", port, "--mount-port", os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT"),
		"--sec", security, "--krb5-config", os.Getenv("NFS_VIEWER_KRB5_CONFIG"),
		"--keytab", os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), "--principal", "root@NFS.TEST", "--spn", "nfs/server.nfs.test",
		"--export", "/data", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
	if strings.HasPrefix(t.Name(), "TestKerberosCCache") || t.Name() == "TestKerberosGaneshaUDP/ccache" {
		args = append(args, "--keytab=", "--ccache", os.Getenv("NFS_VIEWER_KRB5_CCACHE"))
	}
	if strings.HasPrefix(t.Name(), "TestKerberosGaneshaUDP/") {
		args = append(args, "--transport", "udp", "--nfs-port", os.Getenv("NFS_VIEWER_KRB5_UDP_PORT"), "--mount-port", os.Getenv("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"))
	}
	if security == "krb5i" {
		args = append(args, "--export", "/integrity")
	}
	if security == "krb5p" {
		args = append(args, "--export", "/private")
	}
	args = append(args, extra...)
	run := func(args []string) (string, error) { return runKerberosCLI(t, args) }
	t.Run("roundtrip", func(t *testing.T) {
		dir := t.TempDir()
		source, dest := filepath.Join(dir, "source.bin"), filepath.Join(dir, "result.bin")
		emptySource, emptyDest := filepath.Join(dir, "empty.bin"), filepath.Join(dir, "empty-result.bin")
		if err := os.WriteFile(emptySource, nil, 0600); err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{0, 27, 255, 128, 'K', 'R', 'B', 10}, 17000)
		if err := os.WriteFile(source, payload, 0600); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("krb5-%d", time.Now().UnixNano())
		a := append([]string(nil), args...)
		for _, command := range []string{"id", "root verify", "put " + strconv.Quote(source) + " " + name, "ls", "get " + name + " " + strconv.Quote(dest), "put " + strconv.Quote(emptySource) + " " + name + "-empty", "get " + name + "-empty " + strconv.Quote(emptyDest)} {
			a = append(a, "-c", command)
		}
		out, err := run(a)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !strings.Contains(out, "root@NFS.TEST ("+security+")") || strings.Contains(out, "AUTH_SYS") || !strings.Contains(out, "UID/GID off") {
			t.Fatal(out)
		}
		if !strings.Contains(out, "Ticket ends") {
			t.Fatal("missing authenticated ticket lifetime: " + out)
		}
		if security == "krb5i" && !strings.Contains(out, "Integrity: NFS arguments and results signed") {
			t.Fatal(out)
		}
		if security == "krb5p" && !strings.Contains(out, "Privacy: NFS arguments and results encrypted") {
			t.Fatal(out)
		}
		actual, err := os.ReadFile(dest)
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("binary round trip failed: %v", err)
		}
		actual, err = os.ReadFile(emptyDest)
		if err != nil || len(actual) != 0 {
			t.Fatalf("empty round trip failed: %v", err)
		}
	})
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"wrong-service", []string{"--spn", "nfs/missing.nfs.test"}},
		{"wrong-client", []string{"--principal", "missing@NFS.TEST"}},
		{"auth-sys-rejected", []string{"--sec", "sys", "--krb5-config=", "--keytab=", "--ccache=", "--principal=", "--spn="}},
		{"uid-flag", []string{"--uid", "0"}},
		{"uid-command", []string{"-c", "uid 123"}},
		{"auto-uid-command", []string{"-c", "auto-uid on"}},
		{"privacy-required", []string{"--sec", "krb5i", "--export", "/private"}},
		{"weak-export-mode", []string{"--sec", "krb5", "--export", "/integrity"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := append(append([]string(nil), args...), "-c", "pwd")
			a = append(a, tc.extra...)
			if out, err := run(a); err == nil {
				t.Fatalf("unexpected success: %s", out)
			}
		})
	}
}

func runKerberosCLI(t *testing.T, args []string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if binary := os.Getenv("NFS_VIEWER_TEST_BINARY"); binary != "" {
		b, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		return string(b), err
	}
	var out bytes.Buffer
	cmd := NewCommand(strings.NewReader(""), &out, &out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}
