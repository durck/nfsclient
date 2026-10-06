package nfs

import (
	"bytes"
	"context"
	"fmt"
	bgss "nfs-viewer/internal/krbgss"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This requires the disposable MIT PKINIT KDC and real kernel NFS service.
// It intentionally leaves ASHelper empty on both Windows and CGO-free Linux.
func TestPureGoASNativeInterop(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PUREGO_AS_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT/native kernel fixture")
	}
	required := func(key string) string {
		t.Helper()
		value := os.Getenv("NFS_VIEWER_PUREGO_AS_" + key)
		if value == "" {
			t.Fatalf("missing explicit native fixture %s", key)
		}
		return value
	}
	port := func(key string) int {
		t.Helper()
		v, err := strconv.Atoi(required(key))
		if err != nil || v < 1 || v > 65535 {
			t.Fatalf("invalid port %s", key)
		}
		return v
	}
	base := Config{Host: required("HOST"), NFSPort: port("PORT"), MountPort: port("MOUNT_PORT"), Timeout: 5 * time.Second, Kerberos: KerberosConfig{ConfigFile: required("CONFIG"), SPN: "nfs/server.nfs.test"}}
	dir := required("FILES")
	payload := bytes.Repeat([]byte{0, 255, 128, 'P', 'K', 'F'}, 1500)
	for _, mechanism := range []string{"fast", "pkinit"} {
		for _, version := range []string{"2", "3", "4.0", "4.1", "4.2"} {
			for _, transport := range []string{"tcp", "udp"} {
				if transport == "udp" && strings.HasPrefix(version, "4") {
					continue
				}
				for _, security := range []string{"krb5", "krb5i", "krb5p"} {
					t.Run(mechanism+"/"+version+"/"+transport+"/"+security, func(t *testing.T) {
						cfg := base
						cfg.Version, cfg.Transport, cfg.Security = version, transport, security
						uid := uint32(0)
						if mechanism == "fast" {
							uid = 20001
							cfg.Kerberos.Principal = "alice@NFS.TEST"
							cfg.Kerberos.Keytab = filepath.Join(dir, "alice.keytab")
							cfg.Kerberos.RequireFAST = true
							cfg.Kerberos.FASTArmor = filepath.Join(dir, "alice.ccache")
						} else {
							cfg.Kerberos.Principal = "root@NFS.TEST"
							cfg.Kerberos.PKINIT = bgss.PKINITFiles{Cert: filepath.Join(dir, "client.crt"), Key: filepath.Join(dir, "client.key"), CA: filepath.Join(dir, "ca.crt"), CRL: filepath.Join(dir, "clean.crl")}
						}
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()
						c, err := Connect(ctx, cfg)
						if err != nil {
							t.Fatal("pure-Go AS/native RPCSEC_GSS", err)
						}
						defer c.Close()
						root, err := c.Mount(ctx, "/data")
						if err != nil {
							t.Fatal(err)
						}
						if c.Version() != version || c.Security() != security || c.Transport() != transport || c.KerberosExpiry().IsZero() {
							t.Fatal("selected/authenticated profile changed")
						}
						name := fmt.Sprintf("purego-%s-%s-%s-%s-%s-%d", runtime.GOOS, mechanism, version, transport, security, time.Now().UnixNano())
						if version == "2" {
							if n, err := c.UploadV2(ctx, root.Handle, name, 0600, bytes.NewReader(payload), int64(len(payload)), false, nil); err != nil || n != int64(len(payload)) {
								t.Fatal("protected staged v2 WRITE", n, err)
							}
						} else {
							file, err := c.Create(ctx, root.Handle, name, 0600, false)
							if err != nil {
								t.Fatal(err)
							}
							if n, err := c.WriteFrom(ctx, file.Handle, bytes.NewReader(payload)); err != nil || n != int64(len(payload)) {
								t.Fatal("protected WRITE", n, err)
							}
						}
						file, err := c.Lookup(ctx, root.Handle, name)
						if err != nil {
							t.Fatal(err)
						}
						// Service tickets live four seconds. Exercise real context renewal
						// once per mechanism/OS after the old ticket actually expires.
						if version == "3" && transport == "tcp" && security == "krb5p" {
							expires := c.KerberosExpiry()
							delay := time.Until(expires.Add(100 * time.Millisecond))
							if delay <= 0 || delay > 6*time.Second {
								t.Fatal("fixture requires short service tickets", delay)
							}
							select {
							case <-time.After(delay):
							case <-ctx.Done():
								t.Fatal(ctx.Err())
							}
						}
						var out bytes.Buffer
						if n, err := c.ReadTo(ctx, file.Handle, &out); err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
							t.Fatal("protected READ", n, err)
						}
						got, err := c.Lookup(ctx, root.Handle, name)
						if err != nil || got.Attr.UID != uid {
							t.Fatal("native principal mapping", got.Attr.UID, err)
						}
						if version == "3" && transport == "tcp" && security == "krb5p" && !time.Now().Before(c.KerberosExpiry()) {
							t.Fatal("expired context was not renewed")
						}
						t.Logf("native file=%s uid=%d bytes=%d", name, uid, len(payload))
					})
				}
			}
		}
	}
}
