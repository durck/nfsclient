package nfs

import (
	"os"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/testutil/kerberosfixture"
)

func TestSambaADRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_AD_CONFIG") == "" {
		t.Skip("requires tests/samba-ad fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			if version == "3-udp" && security != "krb5" {
				continue
			}
			for _, credential := range []string{"keytab", "ccache"} {
				if credential == "keytab" && (security != "krb5p" || (version != "3" && version != "4.2")) {
					continue
				}
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					t.Parallel()
					port, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_AD_PORT"))
					mount, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_AD_MOUNT_PORT"))
					lifetime, maxLife := "4s", 5*time.Second
					if credential == "keytab" {
						lifetime, maxLife = "130s", 131*time.Second
					}
					cfg := Config{Host: "127.0.0.1", Version: version, Transport: "tcp", Security: security, Timeout: 3 * time.Second, NFSPort: port, MountPort: mount,
						Kerberos: KerberosConfig{ConfigFile: kerberosfixture.ADConfig(t, "tcp", "aes256-cts-hmac-sha1-96", lifetime), Principal: "alice@AD.NFS.TEST", SPN: "nfs/server.ad.nfs.test"}}
					if version == "3-udp" {
						cfg.Version, cfg.Transport = "3", "udp"
						cfg.NFSPort, _ = strconv.Atoi(os.Getenv("NFS_VIEWER_AD_UDP_PORT"))
						cfg.MountPort, _ = strconv.Atoi(os.Getenv("NFS_VIEWER_AD_UDP_MOUNT_PORT"))
					}
					if credential == "ccache" {
						cfg.Kerberos.CCache = os.Getenv("NFS_VIEWER_AD_CCACHE")
					} else {
						cfg.Kerberos.Keytab = os.Getenv("NFS_VIEWER_AD_KEYTAB")
					}
					testKerberosRenewalTransferWithLifetime(t, cfg, maxLife)
				})
			}
		}
	}
}
