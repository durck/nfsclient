package nfs

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/sspi"
)

// This opt-in test contacts only the explicitly selected NFS export. It uses
// the real Windows current-logon Kerberos package, with no injected provider,
// keytab, credential cache, or key export. The export must support all three
// RPCSEC_GSS services. Run separately for each selected NFS version/transport.
func TestSSPINativeCurrentLogonRPC(t *testing.T) {
	if os.Getenv("NFS_VIEWER_SSPI") != "1" {
		t.Skip("set NFS_VIEWER_SSPI=1 and explicit HOST, PRINCIPAL, SPN, EXPORT, VERSION variables with the same prefix for a current-logon Kerberos NFS fixture")
	}
	if runtime.GOOS != "windows" {
		t.Fatal("the native SSPI fixture requires Windows")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv("NFS_VIEWER_SSPI_" + name)
		if value == "" {
			t.Fatalf("NFS_VIEWER_SSPI_%s must be explicitly selected", name)
		}
		return value
	}
	port := func(name string) int {
		t.Helper()
		value := os.Getenv("NFS_VIEWER_SSPI_" + name)
		if value == "" {
			return 0
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid NFS_VIEWER_SSPI_%s", name)
		}
		return n
	}
	cfg := Config{Host: required("HOST"), Version: required("VERSION"),
		Transport: os.Getenv("NFS_VIEWER_SSPI_TRANSPORT"), Timeout: 15 * time.Second,
		NFSPort: port("NFS_PORT"), MountPort: port("MOUNT_PORT"), PortmapPort: port("PORTMAP_PORT"),
		Kerberos: KerberosConfig{Provider: "sspi", Principal: required("PRINCIPAL"), SPN: required("SPN")}}
	path := required("EXPORT")
	switch cfg.Version {
	case "2", "3", "4.0", "4.1", "4.2":
	default:
		t.Fatal("the native fixture requires an explicit numeric NFS version")
	}
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			profile := cfg
			profile.Security = security
			c, err := Connect(ctx, profile)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.security != security || c.principal != cfg.Kerberos.Principal || c.Version() != cfg.Version {
				t.Fatal("the established NFS identity or profile changed")
			}
			if _, ok := c.nfs.gss.context.(*sspi.Initiator); !ok {
				t.Fatal("the established mechanism is not the native SSPI provider")
			}
			node, err := c.Mount(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.GetAttr(ctx, node.Handle); err != nil {
				t.Fatal(err)
			}
			c.Close()
		})
	}
}
