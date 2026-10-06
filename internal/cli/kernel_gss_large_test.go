package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// The fixture augments an actual MIT-issued home TGT, not a cached service
// ticket. The unchanged client still requests a fresh authenticated TGS reply.
func TestKernelNFSGSSLargeToken(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KERNEL_GSS_LARGE") != "1" {
		t.Skip("requires explicit kernel GSS large-TGT fixture")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing explicit large-token fixture setting %s", name)
		}
		return value
	}
	cache := required("NFS_VIEWER_KERNEL_GSS_LARGE_CCACHE")
	config := required("NFS_VIEWER_KERNEL_KRB5_CONFIG")
	spn := required("NFS_VIEWER_KERNEL_KRB5_SPN")
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				base := kernelConfig(t, version, "tcp")
				base.Auth, base.Security = nfs.Auth{}, security
				base.Kerberos = nfs.KerberosConfig{ConfigFile: config, CCache: cache, Principal: "alice@NFS.TEST", SPN: spn}
				payload := make([]byte, 8193)
				for i := range payload {
					payload[i] = byte(i * 31)
				}
				checkObserved := func(t *testing.T, observer *kernelGSSObserver) {
					t.Helper()
					count, size := observer.initCount.Load(), observer.minInitLen.Load()
					if count < 1 || size <= 2048 {
						t.Fatalf("expected actual GSS INIT above 2 KiB: count=%d min_bytes=%d", count, size)
					}
					t.Logf("GSS_LARGE_INIT count=%d min_bytes=%d", count, size)
				}
				t.Run("api-large-token", func(t *testing.T) {
					observer := startKernelGSSObserver(t, base.NFSPort)
					cfg := base
					cfg.NFSPort = observer.port
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					c, err := nfs.Connect(ctx, cfg)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(c.Close)
					s := session.New(c, cfg.Host, false, false, nil)
					if err := s.Use(ctx, "/data"); err != nil {
						t.Fatal(err)
					}
					local := t.TempDir()
					source := filepath.Join(local, "source")
					if err := os.WriteFile(source, payload, 0600); err != nil {
						t.Fatal(err)
					}
					remote := fmt.Sprintf("gss-groups/gss-large-api-%d", time.Now().UnixNano())
					if n, err := s.Put(ctx, source, remote); err != nil || n != int64(len(payload)) {
						t.Fatalf("large-ticket upload: %d %v", n, err)
					}
					download := filepath.Join(local, "download")
					if n, err := s.Get(ctx, remote, download); err != nil || n != int64(len(payload)) {
						t.Fatalf("large-ticket download: %d %v", n, err)
					}
					got, err := os.ReadFile(download)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("large-ticket byte mismatch: %v", err)
					}
					if c.Identity() != "alice@NFS.TEST ("+security+")" || c.Security() != security {
						t.Fatal("large-ticket transfer changed identity/protection")
					}
					checkObserved(t, observer)
				})
				t.Run("cli-large-token", func(t *testing.T) {
					observer := startKernelGSSObserver(t, base.NFSPort)
					local := t.TempDir()
					source, download := filepath.Join(local, "source"), filepath.Join(local, "download")
					if err := os.WriteFile(source, payload, 0600); err != nil {
						t.Fatal(err)
					}
					remote := fmt.Sprintf("gss-groups/gss-large-cli-%d", time.Now().UnixNano())
					args := []string{"127.0.0.1", "--nfs-version", version, "--transport", "tcp",
						"--nfs-port", strconv.Itoa(observer.port), "--export", "/data", "--auto-uid=false",
						"--auto-escape=false", "--color", "never", "--progress", "never", "--no-banner"}
					args = append(args, kernelKerberosArgs(base)...)
					args = append(args, "-c", "put "+strconv.Quote(source)+" "+remote,
						"-c", "get "+remote+" "+strconv.Quote(download), "-c", "id")
					out, err := runKerberosCLI(t, args)
					if err != nil || !strings.Contains(out, "alice@NFS.TEST ("+security+")") || strings.Contains(out, "AUTH_SYS") {
						t.Fatalf("large-ticket CLI: %v %s", err, out)
					}
					got, err := os.ReadFile(download)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("large-ticket CLI bytes: %v", err)
					}
					checkObserved(t, observer)
				})
			})
		}
	}
}
