package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/scan"
)

// Opt-in tests use only the disposable tests/kerberos loopback NFS/KDC fixture.
func TestScanKerberosProtectedFixture(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_V4") != "1" || os.Getenv("NFS_VIEWER_KRB5_PORT") == "" {
		t.Skip("requires tests/kerberos v4 loopback fixture")
	}
	port := os.Getenv("NFS_VIEWER_KRB5_PORT")
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		t.Fatal("invalid loopback fixture NFS port")
	}
	base := []string{"--nfs-version", "4.1", "--nfs-port", port, "--portmap-port", "0", "--sec", "krb5p", "--principal", "root", "--domain", "NFS.TEST", "--krb5-config", os.Getenv("NFS_VIEWER_KRB5_CONFIG"), "--path", "/data", "--no-squash-check", "--no-escape-check", "--output", "json", "--timeout", "5s"}
	run := func(t *testing.T, args ...string) scan.Result {
		t.Helper()
		var out bytes.Buffer
		cmd := newScanCommand(&out)
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(append(append([]string(nil), base...), args...))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := cmd.ExecuteContext(ctx); err != nil {
			t.Fatal(err)
		}
		var result scan.Result
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, credential := range []struct{ flag, env string }{{"--keytab", "NFS_VIEWER_KRB5_KEYTAB"}, {"--ccache", "NFS_VIEWER_KRB5_CCACHE"}, {"--password", "NFS_VIEWER_KRB5_PASSWORD"}} {
		t.Run(credential.flag, func(t *testing.T) {
			value := os.Getenv(credential.env)
			if value == "" {
				t.Skip("fixture credential not configured")
			}
			principal := "root"
			if credential.flag == "--password" && os.Getenv("NFS_VIEWER_KRB5_PASSWORD_PRINCIPAL") != "" {
				principal = os.Getenv("NFS_VIEWER_KRB5_PASSWORD_PRINCIPAL")
			}
			for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
				for _, mode := range []string{"spn", "target-spn"} {
					t.Run(version+"/"+mode, func(t *testing.T) {
						spn := "nfs/server.nfs.test"
						if mode == "target-spn" {
							spn = "127.0.0.1:" + port + "=" + spn
						}
						args := []string{credential.flag, value, "--principal", principal, "--nfs-version", version, "--" + mode, spn, "127.0.0.1"}
						if version == "3" {
							mount := os.Getenv("NFS_VIEWER_KRB5_MOUNT_PORT")
							if mount == "" {
								t.Skip("fixture MOUNT port not configured")
							}
							args = append(args, "--mount-port", mount)
						}
						result := run(t, args...)
						if len(result.Hosts) != 1 || !result.Hosts[0].Reachable || result.Hosts[0].Identity != principal+"@NFS.TEST (krb5p)" {
							t.Fatalf("protected scan failed: %+v", result)
						}
						found := false
						for _, exp := range result.Hosts[0].Exports {
							found = found || exp.Path == "/data" && exp.Access == scan.AccessOK
						}
						if !found {
							t.Fatalf("protected /data discovery failed: %+v", result)
						}
					})
				}
			}
		})
	}
	t.Run("per-target-SPN-no-downgrade", func(t *testing.T) {
		keytab := os.Getenv("NFS_VIEWER_KRB5_KEYTAB")
		if keytab == "" {
			t.Skip("fixture keytab not configured")
		}
		// Two ports on one host must retain separate SPN assignments. A wrong
		// service identity must fail even though both endpoints serve real NFS.
		second := scanFixtureRelay(t, net.JoinHostPort("127.0.0.1", port))
		// The API retains SRV endpoint ports; command-line host inputs use one
		// global port. Exercise both mappings at that API boundary here.
		opts := scan.DefaultOptions()
		opts.NFSVersion, opts.NFSPort, opts.PortmapPort = "4.1", 0, 0
		opts.Security, opts.Output = "krb5p", "json"
		opts.CheckSquash, opts.CheckEscape = false, false
		opts.Kerberos = qualifyKerberos(nfs.KerberosConfig{Principal: "root", ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: keytab}, "NFS.TEST", "")
		opts.Discovery.Paths = []string{"/data"}
		first, _ := strconv.Atoi(port)
		opts.TargetSPNs = []string{fmt.Sprintf("127.0.0.1:%d=nfs/server.nfs.test", first), fmt.Sprintf("127.0.0.1:%d=nfs/wrong.nfs.test", second)}
		var out bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := scan.RunTargets(ctx, []scan.Target{{Host: "127.0.0.1", NFSPort: first}, {Host: "127.0.0.1", NFSPort: second}}, opts, &out); err != nil {
			t.Fatal(err)
		}
		var result scan.Result
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Hosts) != 2 || !result.Hosts[0].Reachable || result.Hosts[0].Identity != "root@NFS.TEST (krb5p)" || result.Hosts[1].Reachable || result.Hosts[1].Error == "" || strings.Contains(result.Hosts[1].Identity, "AUTH_SYS") {
			t.Fatalf("incorrect SPN binding/downgrade: %+v", result)
		}
	})
	t.Run("wrong-password-no-downgrade", func(t *testing.T) {
		result := run(t, "--password", "fixture-deliberately-wrong-password", "--spn", "nfs/server.nfs.test", "127.0.0.1")
		if len(result.Hosts) != 1 || result.Hosts[0].Reachable || result.Hosts[0].Error == "" || len(result.Hosts[0].Exports) != 0 {
			t.Fatalf("wrong credentials accepted: %+v", result)
		}
	})
}

func scanFixtureRelay(t *testing.T, endpoint string) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			down, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer down.Close()
				up, err := net.DialTimeout("tcp", endpoint, time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				_ = down.SetDeadline(time.Now().Add(30 * time.Second))
				_ = up.SetDeadline(time.Now().Add(30 * time.Second))
				go func() { _, _ = io.Copy(up, down); _ = up.Close() }()
				_, _ = io.Copy(down, up)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
