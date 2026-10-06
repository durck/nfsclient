package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A native kernel NFSv2 server and MIT KDC are mandatory here. The independent
// envelope unit peers cannot satisfy this gate. Credentials/runtime are explicit
// and belong exclusively to the disposable tests/nfsv2/gss fixture.
func TestV2GSSNativeInterop(t *testing.T) {
	if os.Getenv("NFS_VIEWER_V2_GSS_NATIVE") != "1" {
		t.Skip("requires explicit disposable native NFSv2/MIT fixture")
	}
	required := func(key string) string {
		t.Helper()
		value := os.Getenv("NFS_VIEWER_V2_GSS_" + key)
		if value == "" {
			t.Fatalf("missing explicit native fixture %s", key)
		}
		return value
	}
	port := func(key string) int {
		t.Helper()
		n, err := strconv.Atoi(required(key))
		if err != nil || n <= 0 || n > 65535 {
			t.Fatalf("invalid fixture port %s", key)
		}
		return n
	}
	base := Config{Host: "127.0.0.1", Version: "2", NFSPort: port("PORT"), MountPort: port("MOUNT_PORT"), Timeout: 5 * time.Second,
		Kerberos: KerberosConfig{ConfigFile: required("CONFIG"), Principal: "alice@NFS.TEST", SPN: "nfs/server.nfs.test"}}
	if host := os.Getenv("NFS_VIEWER_V2_GSS_HOST"); host != "" {
		base.Host = host // Explicit test-owned container address for Linux/slirp.
	}
	keytab, cache, bobKeytab := required("ALICE_KEYTAB"), required("ALICE_CCACHE"), required("BOB_KEYTAB")
	payload := make([]byte, 9001)
	for i := range payload {
		payload[i] = byte(i*31 + i/257)
	}
	for _, transport := range []string{"tcp", "udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(transport+"/"+security+"/"+credential, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					cfg := base
					cfg.Transport, cfg.Security = transport, security
					if credential == "keytab" {
						cfg.Kerberos.Keytab = keytab
					} else {
						cfg.Kerberos.CCache = cache
					}
					c, err := Connect(ctx, cfg)
					if err != nil {
						t.Fatal("native GSS establishment/NULL", err)
					}
					defer c.Close()
					root, err := c.Mount(ctx, "/data")
					if err != nil {
						t.Fatal("native MOUNTv1/protected GETATTR", err)
					}
					if c.Version() != "2" || c.Security() != security || c.Transport() != transport || c.KerberosExpiry().IsZero() {
						t.Fatal("native profile changed or unauthenticated")
					}
					if err := c.Tune(ctx, root.Handle); err != nil {
						t.Fatal("native protected STATFS", err)
					}
					name := fmt.Sprintf("%s-%s-%s-%s", runtime.GOOS, transport, security, credential)
					dir, err := c.Create(ctx, root.Handle, name, 0700, true)
					if err != nil {
						t.Fatal("native protected MKDIR", err)
					}
					if n, err := c.UploadV2(ctx, dir.Handle, "payload", 0600, bytes.NewReader(payload), int64(len(payload)), false, nil); err != nil || n != int64(len(payload)) {
						t.Fatal("native staged upload", n, err)
					}
					file, err := c.Lookup(ctx, dir.Handle, "payload")
					if err != nil || file.Attr.UID != 20001 || file.Attr.GID != 20001 {
						t.Fatal("native principal mapping/LOOKUP", file.Attr.UID, file.Attr.GID, err)
					}
					var out bytes.Buffer
					if n, err := c.ReadTo(ctx, file.Handle, &out); err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
						t.Fatal("native protected READ bytes", n, err)
					}
					acl, err := c.getLegacyACL(ctx, file.Handle)
					if err != nil {
						t.Fatal("native protected NFSACLv2 GETACL", err)
					}
					if err := c.setLegacyACL(ctx, file.Handle, acl); err != nil {
						t.Fatal("native protected NFSACLv2 SETACL/readback", err)
					}
					if entries, err := c.ReadDir(ctx, dir.Handle); err != nil || len(entries) != 1 || entries[0].Name != "payload" {
						t.Fatal("native protected READDIR", err)
					}
					bobCfg := cfg
					bobCfg.Kerberos.Principal, bobCfg.Kerberos.Keytab, bobCfg.Kerberos.CCache = "bob@NFS.TEST", bobKeytab, ""
					bob, err := Connect(ctx, bobCfg)
					if err != nil {
						t.Fatal("native second principal", err)
					}
					defer bob.Close()
					out.Reset()
					if n, err := bob.ReadTo(ctx, file.Handle, &out); !errors.Is(err, Status(13)) || n != 0 || out.Len() != 0 {
						t.Fatal("native unauthorized principal read", n, err)
					}
					// Preserve payloads for the fixture's independent native SHA-256
					// and UID/GID/mode/ACL audit before destroying the guest.
				})
			}
		}
	}
}

func TestV2GSSNativeUDPReplies(t *testing.T) {
	if os.Getenv("NFS_VIEWER_V2_GSS_NATIVE") != "1" {
		t.Skip("requires explicit disposable native NFSv2/MIT fixture")
	}
	nfsPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_V2_GSS_PORT"))
	if err != nil || nfsPort < 1 || nfsPort > 65535 {
		t.Fatal("missing/invalid explicit native NFS port")
	}
	mountPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_V2_GSS_MOUNT_PORT"))
	if err != nil || mountPort < 1 || mountPort > 65535 {
		t.Fatal("missing/invalid explicit native MOUNT port")
	}
	base := Config{Host: "127.0.0.1", Version: "2", Transport: "udp", NFSPort: nfsPort, MountPort: mountPort, Timeout: 5 * time.Second,
		Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_V2_GSS_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_V2_GSS_ALICE_KEYTAB"), Principal: "alice@NFS.TEST", SPN: "nfs/server.nfs.test"}}
	if host := os.Getenv("NFS_VIEWER_V2_GSS_HOST"); host != "" {
		base.Host = host
	}
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		modes := []string{"loss-reorder", "replayed-reply", "altered-verifier", "lost-write"}
		if security != "krb5" {
			modes = append(modes, "altered-body")
		}
		for _, mode := range modes {
			t.Run(security+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				relay := startKernelGSSUDPRelayAt(t, base.Host, nfsPort, 2)
				cfg := base
				cfg.Host, cfg.Security, cfg.NFSPort = "127.0.0.1", security, relay.port
				c, err := Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if base.Host != cfg.Host {
					// Only NFS goes through the local fault relay. Route the
					// separate MOUNT service to the explicit fixture endpoint.
					c.mount.conn.Close()
					c.mount, err = dialRPCTransport(ctx, base.Host, mountPort, cfg.Timeout, false, "udp")
					if err != nil {
						t.Fatal(err)
					}
				}
				root, err := c.Mount(ctx, "/data")
				if err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("fault-%s-%s-%d", security, mode, time.Now().UnixNano())
				if _, err := c.UploadV2(ctx, root.Handle, name, 0600, bytes.NewBufferString("before"), 6, false, nil); err != nil {
					t.Fatal(err)
				}
				file, err := c.Lookup(ctx, root.Handle, name)
				if err != nil {
					t.Fatal(err)
				}
				c.nfs.timeout, c.nfs.udpRetryDelay = 300*time.Millisecond, 30*time.Millisecond
				if mode == "lost-write" {
					relay.arm("lost-create", 8) // Drop an already processed WRITE reply.
					n, err := c.WriteFrom(ctx, file.Handle, bytes.NewBufferString("after!"))
					if err == nil || n != 0 || !strings.Contains(err.Error(), "outcome unknown") {
						t.Fatal("unacknowledged native WRITE", n, err)
					}
					observerCfg := base
					observerCfg.Security = security
					observer, err := Connect(ctx, observerCfg)
					if err != nil {
						t.Fatal(err)
					}
					defer observer.Close()
					var out bytes.Buffer
					if _, err := observer.ReadTo(ctx, file.Handle, &out); err != nil || out.String() != "after!" {
						t.Fatal("native mutation did not reach server", err)
					}
				} else {
					relay.arm(mode, 6)
					var out bytes.Buffer
					n, err := c.ReadTo(ctx, file.Handle, &out)
					if mode == "loss-reorder" {
						if err != nil || n != 6 || out.String() != "before" {
							t.Fatal("native read retry", n, err)
						}
					} else if err == nil || n != 0 || out.Len() != 0 || !c.nfs.closed {
						t.Fatal("native unverified data exposed/session reused", n, err)
					}
				}
				count, fresh, err := relay.snapshot()
				want := 1
				if mode == "loss-reorder" || mode == "replayed-reply" {
					want = 2
					if !fresh {
						t.Fatal("native retry reused GSS sequence/XID")
					}
				}
				if err != nil || count != want {
					t.Fatal("native relay request count", count, err)
				}
			})
		}
	}
}
