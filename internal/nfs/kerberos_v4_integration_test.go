package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestKerberosV4LeaseAndSecurity(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_V4") != "1" {
		t.Skip("requires v4 Kerberos fixture with six-second lease")
	}
	port, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KRB5_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cfg := Config{Host: "127.0.0.1", Version: version, Transport: "tcp", Security: security, NFSPort: port, Timeout: 3 * time.Second,
					Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
				c, err := Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if c.Version() != version || c.Security() != security || c.nfs.gss.nfsVersion != 4 || c.KerberosExpiry().IsZero() {
					t.Fatal("wrong v4 authenticated session state")
				}
				if security != "krb5p" {
					_, err := c.Mount(ctx, "/private")
					if !errors.Is(err, Status(10016)) || !strings.Contains(err.Error(), "server advertises krb5p") || c.Security() != security {
						t.Fatalf("missing SECINFO diagnostic or security changed: %v", err)
					}
				}
				root, err := c.Mount(ctx, "/data")
				if err != nil {
					t.Fatal(err)
				}
				// Longer than the fixture's six-second lease; renewal must use GSS.
				select {
				case <-time.After(8 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				file, err := c.Create(ctx, root.Handle, fmt.Sprintf("lease-%s-%s-%d", version, security, time.Now().UnixNano()), 0600, false)
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte("authenticated transfer after idle lease renewal")
				if _, err := c.WriteFrom(ctx, file.Handle, bytes.NewReader(payload)); err != nil {
					t.Fatal(err)
				}
				var got bytes.Buffer
				if _, err := c.ReadTo(ctx, file.Handle, &got); err != nil || !bytes.Equal(got.Bytes(), payload) {
					t.Fatalf("lease transfer: %v", err)
				}
			})
		}
	}
}
