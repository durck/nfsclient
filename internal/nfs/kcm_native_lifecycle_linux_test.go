//go:build linux

package nfs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestKCMNativeReplacementMutationBoundary(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KCM_DAEMON_NATIVE") != "1" {
		t.Skip("requires isolated native SSSD/MIT/Ganesha fixture")
	}
	for _, path := range []string{"/.dockerenv", "/run/nfs-test/kcm.ready"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("missing disposable native fixture marker", err)
		}
	}
	for _, mode := range []string{"same-principal-refresh", "principal-change", "destroyed", "expired-tgt", "missing-socket"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			name := fmt.Sprintf("KCM:0:nfs-lifecycle-%d", time.Now().UnixNano())
			run := func(command string, args ...string) {
				t.Helper()
				if err := exec.CommandContext(ctx, command, args...).Run(); err != nil {
					t.Fatalf("native fixture %s failed: %v", command, err)
				}
			}
			args := []string{"-k", "-t", "/run/nfs-test/client.keytab", "-c", name}
			if mode == "expired-tgt" {
				args = append(args, "-l", "2s")
			}
			run("kinit", append(args, "root@NFS.TEST")...)
			t.Cleanup(func() { _ = exec.Command("kdestroy", "-c", name).Run() })
			cfg := renewalFixtureConfig(t, "3", "krb5p", "keytab")
			cfg.Kerberos.Keytab = ""
			cfg.Kerberos.CCache, cfg.Kerberos.KCMSocket = name, "/var/run/.heim_org.h5l.kcm-socket"
			c, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			root, err := c.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			filename := fmt.Sprintf("kcm-boundary-%s-%d", mode, time.Now().UnixNano())
			file, err := c.Create(ctx, root.Handle, filename, 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				// Cleanup uses a new explicit keytab connection; never the failed
				// session or an automatic credential fallback.
				cfg.Kerberos.CCache, cfg.Kerberos.KCMSocket = "", ""
				cfg.Kerberos.Keytab = "/run/nfs-test/client.keytab"
				verify, err := Connect(ctx, cfg)
				if err != nil {
					t.Error(err)
					return
				}
				defer verify.Close()
				r, err := verify.Mount(ctx, "/data")
				if err != nil {
					t.Error(err)
					return
				}
				f, err := verify.Lookup(ctx, r.Handle, filename)
				if err != nil {
					t.Error(err)
					return
				}
				var out bytes.Buffer
				if _, err = verify.ReadTo(ctx, f.Handle, &out); err != nil {
					t.Error(err)
					return
				}
				want := []byte(nil)
				if mode == "same-principal-refresh" {
					want = []byte("confirmed mutation")
				}
				if !bytes.Equal(out.Bytes(), want) {
					t.Error("native file changed after refused credential replacement")
				}
				if err = verify.Remove(ctx, r.Handle, filename); err != nil {
					t.Error(err)
				}
			}()
			switch mode {
			case "same-principal-refresh":
				run("kinit", "-k", "-t", "/run/nfs-test/client.keytab", "-c", name, "root@NFS.TEST")
			case "principal-change":
				run("kinit", "-k", "-t", "/run/nfs-test/alice.keytab", "-c", name, "alice@NFS.TEST")
			case "destroyed":
				run("kdestroy", "-c", name)
			case "expired-tgt":
				until := c.KerberosExpiry().Add(100 * time.Millisecond)
				if delay := time.Until(until); delay <= 0 || delay > 3*time.Second {
					t.Fatal("fixture TGT not short-lived")
				}
				timer := time.NewTimer(time.Until(until))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			case "missing-socket":
				socket := cfg.Kerberos.KCMSocket
				if err := os.Rename(socket, socket+"-unavailable"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Rename(socket+"-unavailable", socket); err != nil {
						t.Error(err)
					}
				}()
			}
			c.nfs.mu.Lock()
			c.nfs.gss.renewAt = time.Now().Add(-time.Second)
			c.nfs.mu.Unlock()
			n, err := c.WriteFrom(ctx, file.Handle, strings.NewReader("confirmed mutation"))
			if mode == "same-principal-refresh" {
				if err != nil || n != 18 {
					t.Fatalf("authoritative refresh mutation: %d %v", n, err)
				}
			} else if err == nil || n != 0 || !c.nfs.closed {
				t.Fatalf("unsafe replacement accepted or session reusable: %d %v", n, err)
			}
		})
	}
}
