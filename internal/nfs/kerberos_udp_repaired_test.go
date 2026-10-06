package nfs

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// Reuse the kernel lane's independent loss/replay/tamper relay against the
// separately rebuilt ntirpc fixture. No production or packaged server is patched.
func TestKerberosUDPProtectedMatrix(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_UDP_REPAIRED") != "1" {
		t.Skip("requires the separately named tests/kerberos/udp-repair fixture")
	}
	required := func(name string) string {
		t.Helper()
		value := os.Getenv(name)
		if value == "" {
			t.Fatal("missing fixture setting", name)
		}
		return value
	}
	port := func(name string) int {
		t.Helper()
		p, err := strconv.Atoi(required(name))
		if err != nil || p < 1 || p > 65535 {
			t.Fatal("invalid port", name)
		}
		return p
	}
	base := Config{Host: "127.0.0.1", Version: "3", Transport: "udp", Timeout: 4 * time.Second,
		NFSPort: port("NFS_VIEWER_KRB5_UDP_PORT"), MountPort: port("NFS_VIEWER_KRB5_UDP_MOUNT_PORT"),
		Kerberos: KerberosConfig{ConfigFile: required("NFS_VIEWER_KRB5_CONFIG"), SPN: "nfs/server.nfs.test", Principal: "alice@NFS.TEST"}}
	keytab, cache, bobKeytab := required("NFS_VIEWER_KRB5_ALICE_KEYTAB"), required("NFS_VIEWER_KRB5_ALICE_CCACHE"), required("NFS_VIEWER_KRB5_BOB_KEYTAB")
	for _, security := range []string{"krb5i", "krb5p"} {
		for _, credential := range []string{"keytab", "ccache"} {
			t.Run(security+"/"+credential, func(t *testing.T) {
				cfg := base
				cfg.Security = security
				if credential == "keytab" {
					cfg.Kerberos.Keytab = keytab
				} else {
					cfg.Kerberos.CCache = cache
				}
				t.Run("transfer-policy", func(t *testing.T) { kernelGSS3UDPTransfer(t, cfg, bobKeytab, "/data") })
				for _, mode := range []string{"loss-reorder", "replayed-reply", "altered-verifier", "altered-body", "lost-create"} {
					t.Run(mode, func(t *testing.T) { kernelGSS3UDPFault(t, cfg, mode, "/data") })
				}
			})
		}
	}
}
