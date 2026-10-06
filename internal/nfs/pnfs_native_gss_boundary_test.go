package nfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Ganesha 4.3 accepts native GSS forechannels but cannot create a v4.1 GSS
// backchannel. This is a native refusal test, not protected pNFS I/O evidence.
func TestLizardProtectedPNFSNativeBoundary(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PNFS_GSS_NATIVE_BOUNDARY") != "1" {
		t.Skip("requires disposable native LizardFS/Ganesha Kerberos overlay")
	}
	port, err := strconv.Atoi(os.Getenv("NFS_VIEWER_PNFS_GSS_NATIVE_PORT"))
	if err != nil || port < 1 || port > 65535 {
		t.Fatal("explicit native NFS port required")
	}
	base := Config{Host: "127.0.0.1", NFSPort: port, Transport: "tcp", Timeout: 5 * time.Second,
		Kerberos: KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_PNFS_GSS_NATIVE_CONFIG"), Keytab: os.Getenv("NFS_VIEWER_PNFS_GSS_NATIVE_KEYTAB"), Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
	if !filepath.IsAbs(base.Kerberos.ConfigFile) || !filepath.IsAbs(base.Kerberos.Keytab) {
		t.Fatal("explicit absolute fixture configuration and keytab paths required")
	}
	for _, version := range []string{"4.1", "4.2"} {
		for _, security := range []string{"krb5i", "krb5p"} {
			t.Run(fmt.Sprintf("%s/%s", version, security), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cfg := base
				cfg.Version, cfg.Security = version, security
				ordinary, err := Connect(ctx, cfg)
				if err != nil {
					t.Fatal("native protected forechannel control failed", err)
				}
				root, mountErr := ordinary.Mount(ctx, "/data")
				if mountErr != nil {
					ordinary.Close()
					t.Fatal("native protected MDS export control failed", mountErr)
				}
				_, attrErr := ordinary.GetAttr(ctx, root.Handle)
				ordinary.Close()
				if attrErr != nil {
					t.Fatal("native protected MDS metadata control failed", attrErr)
				}
				cfg.PNFS = true
				protected, err := Connect(ctx, cfg)
				if protected != nil {
					protected.Close()
				}
				if err == nil || !strings.Contains(err.Error(), "server declined NFSv4 backchannel") {
					t.Fatal("expected explicit native protected-backchannel refusal", err)
				}
				t.Logf("NATIVE_PNFS_GSS_BOUNDARY os=%s version=%s security=%s protected_mds_metadata=pass protected_pnfs=refused no_ds_io error=%q", runtime.GOOS, version, security, err.Error())
			})
		}
	}
}
