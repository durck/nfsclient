package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func kernelTLSFixture(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("NFS_VIEWER_KERNEL_TLS") != "1" {
		t.Skip("requires isolated tests/microsoft-ad/run-tls-nfs.py fixture")
	}
	host, ca := os.Getenv("NFS_VIEWER_TLS_HOST"), os.Getenv("NFS_VIEWER_TLS_CA")
	if (host != "127.0.0.1" && host != "192.0.2.20") || ca == "" {
		t.Fatal("explicit isolated TLS host and public certificate required")
	}
	return host, ca
}

func TestKernelTLS(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, policy := range []string{"trusted-ip", "trusted-dns", "insecure"} {
			t.Run(version+"/"+policy, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				tls := nfs.TLSConfig{Enabled: true, CAFile: ca}
				if policy == "trusted-dns" {
					tls.ServerName = "nfs-tls.test"
				}
				if policy == "insecure" {
					tls.CAFile = ""
					tls.ServerName = "wrong.test"
					tls.InsecureSkipVerify = true
				}
				relay := newDownloadRelayTarget(t, net.JoinHostPort(host, "2049"))
				cfg := nfs.Config{Host: "127.0.0.1", NFSPort: relay.port(), Version: version, Timeout: 15 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000, Groups: []uint32{25003}}, TLS: tls}
				c, err := nfs.Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				s := session.New(c, cfg.Host, false, false, nil)
				t.Cleanup(func() { s.Client.Close() })
				if err := s.Use(ctx, "/data"); err != nil {
					t.Fatal(err)
				}
				if !c.TLSActive() || c.TLSCertificateVerified() != (policy != "insecure") {
					t.Fatal("incorrect negotiated TLS policy")
				}
				c.ReadSize = 32768
				dir := t.TempDir()
				src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "download")
				payload := bytes.Repeat([]byte("real-kernel-tls\x00"), 65536)
				if err := os.WriteFile(src, payload, 0600); err != nil {
					t.Fatal(err)
				}
				remote := fmt.Sprintf("tls-api-%s-%s-%s-%d", runtime.GOOS, version, policy, time.Now().UnixNano())
				if _, err := s.Put(ctx, src, remote); err != nil {
					t.Fatal(err)
				}
				old := s.Client
				cut, attempts := false, 0
				_, err = s.GetResumeRetry(ctx, remote, dst, 2, func(done, total uint64) {
					if done == 0 {
						attempts++
					}
					if done >= 32768 && done < total && !cut {
						cut = true
						relay.cut()
					}
				})
				if err != nil || !cut || attempts != 2 || old == s.Client {
					t.Fatalf("recovery cut=%v attempts=%d: %v", cut, attempts, err)
				}
				assertRecoveryFile(t, dst, payload)
				if !s.Client.TLSActive() || s.Client.TLSCertificateVerified() != (policy != "insecure") {
					t.Fatal("TLS policy changed after recovery")
				}
				id, err := s.Lock(ctx, remote, false)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				t.Logf("KERNEL_TLS platform=%s version=%s policy=%s bytes=%d encrypted_tcp_cut attempts=2 locks_passed", runtime.GOOS, version, policy, len(payload))
			})
		}
	}
}

func TestKernelTLSCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			base := []string{host, "--nfs-version", version, "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--groups", "25003", "--timeout", "15s", "--no-banner", "--color", "never", "--progress", "never"}
			run := func(options []string, commands ...string) (string, error) {
				args := append(append([]string(nil), base...), options...)
				for _, c := range commands {
					args = append(args, "-c", c)
				}
				return runKerberosCLI(t, args)
			}
			for _, bad := range []struct {
				name     string
				options  []string
				expected string
			}{
				{"unknown-ca", []string{"--tls"}, "unknown authority"},
				{"wrong-name", []string{"--tls", "--tls-ca", ca, "--tls-server-name", "wrong.test"}, "not wrong.test"},
				{"plaintext", nil, "requested security flavor not allowed"},
			} {
				t.Run(bad.name, func(t *testing.T) {
					out, err := run(bad.options, "cat seed")
					if err == nil || !strings.Contains(out+err.Error(), bad.expected) || strings.Contains(out, "kernel RPC-with-TLS fixture") {
						t.Fatalf("wrong rejection: %v %s", err, out)
					}
				})
			}
			for _, policy := range []string{"trusted", "insecure"} {
				t.Run(policy, func(t *testing.T) {
					options := []string{"--tls", "--tls-ca", ca, "--tls-server-name", "nfs-tls.test"}
					if policy == "insecure" {
						options = []string{"--tls", "--tls-insecure", "--tls-server-name", "wrong.test"}
					}
					local := t.TempDir()
					src, dst := filepath.Join(local, "source"), filepath.Join(local, "download")
					payload := bytes.Repeat([]byte("tls-shell\x00"), 65536)
					if err := os.WriteFile(src, payload, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(dst+".nfs-part", payload[:32768], 0600); err != nil {
						t.Fatal(err)
					}
					remote := fmt.Sprintf("tls-cli-%s-%s-%s-%d", runtime.GOOS, version, policy, time.Now().UnixNano())
					tree := filepath.Join(local, "tree")
					out, err := run(options, "id", "cat seed", "mkdir "+remote, "put "+strconv.Quote(src)+" "+remote+"/binary", "reconnect", "id", "reget --retries 2 "+remote+"/binary "+strconv.Quote(dst), "gettree "+remote+" "+strconv.Quote(tree))
					if err != nil || !strings.Contains(out, "kernel RPC-with-TLS fixture") {
						t.Fatalf("TLS CLI: %v %s", err, out)
					}
					assertRecoveryFile(t, dst, payload)
					got, err := os.ReadFile(filepath.Join(tree, "binary"))
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("TLS tree differs", err)
					}
					t.Logf("KERNEL_TLS_CLI platform=%s version=%s policy=%s bytes=%d reconnect resume recursive", runtime.GOOS, version, policy, len(payload))
				})
			}
		})
	}
}
