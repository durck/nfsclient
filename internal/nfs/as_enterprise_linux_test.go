//go:build linux

package nfs

import (
	"nfsclient/internal/testutil/kdcfixture"
	"os"
	"testing"
)

func TestEnterpriseASNativeRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_AS_ENTERPRISE_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT EnterpriseAS/KDC/Ganesha fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				t.Run(network+"/"+version+"/"+security, func(t *testing.T) {
					cfg := renewalFixtureConfig(t, version, security, "keytab")
					cfg.Kerberos.Keytab = os.Getenv("NFS_VIEWER_KRB5_KEYTAB")
					cfg.Kerberos.EnterpriseUPN = "root-alias@NFS.TEST"
					cfg.Kerberos.ASStartRealm = "MAP.TEST"
					cfg.Kerberos.ASReferralRealms = []string{"MAP.TEST", "NFS.TEST"}
					conf, peer := kdcfixture.EnterpriseMappingConfig(t, cfg.Kerberos.ConfigFile, cfg.Kerberos.EnterpriseUPN, network)
					cfg.Kerberos.ConfigFile = conf

					testKerberosRenewalTransfer(t, cfg)
					if peer.TCP.Load()+peer.UDP.Load() < 2 {
						t.Fatal("renewal did not repeat enterprise mapping")
					}
				})
			}
		}
	}
}
