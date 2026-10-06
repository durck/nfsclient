package cli

import (
	"os"
	"testing"

	"nfs-viewer/internal/nfs"
)

// This gate is separate from the AUTH_SYS suite. A local MIT realm with
// explicit NSS identities must never be presented as Microsoft AD evidence.
func kernelKerberosProfiles(t *testing.T, run func(*testing.T, nfs.Config)) {
	t.Helper()
	if os.Getenv("NFS_VIEWER_KERNEL_KRB5") != "1" {
		t.Skip("requires isolated kernel NFS and MIT KDC fixture")
	}
	required := func(key string) string {
		t.Helper()
		v := os.Getenv("NFS_VIEWER_KERNEL_KRB5_" + key)
		if v == "" {
			t.Fatalf("missing explicit kernel Kerberos fixture setting %s", key)
		}
		return v
	}
	configFile, spn := required("CONFIG"), required("SPN")
	keytab, cache := required("ALICE_KEYTAB"), required("ALICE_CCACHE")
	required("BOB_KEYTAB")
	required("STRANGER_KEYTAB")
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					cfg := kernelConfig(t, version, "tcp")
					cfg.Auth, cfg.Security = nfs.Auth{}, security
					cfg.Kerberos = nfs.KerberosConfig{ConfigFile: configFile, SPN: spn, Principal: "alice@NFS.TEST"}
					if credential == "ccache" {
						cfg.Kerberos.CCache = cache
					} else {
						cfg.Kerberos.Keytab = keytab
					}
					run(t, cfg)
				})
			}
		}
	}
}

func kernelACLIdentity(t *testing.T, cfg nfs.Config, uid uint32) nfs.Config {
	t.Helper()
	if cfg.Security == "" || cfg.Security == "sys" {
		cfg.Auth = nfs.Auth{UID: uid, GID: uid}
		return cfg
	}
	cfg.Auth = nfs.Auth{}
	var user, field string
	switch uid {
	case 20001:
		return cfg // Keep Alice's selected keytab or FILE credential.
	case 20002:
		user, field = "bob", "BOB_KEYTAB"
	case 20004:
		user, field = "stranger", "STRANGER_KEYTAB"
	default:
		t.Fatalf("unknown fixed kernel Kerberos fixture identity %d", uid)
	}
	cfg.Kerberos.Principal = user + "@NFS.TEST"
	cfg.Kerberos.CCache = ""
	cfg.Kerberos.Keytab = os.Getenv("NFS_VIEWER_KERNEL_KRB5_" + field)
	if cfg.Kerberos.Keytab == "" {
		t.Fatalf("missing explicit kernel Kerberos fixture keytab %s", field)
	}
	return cfg
}

func kernelKerberosArgs(cfg nfs.Config) []string {
	args := []string{"--sec", cfg.Security, "--krb5-config", cfg.Kerberos.ConfigFile,
		"--principal", cfg.Kerberos.Principal, "--spn", cfg.Kerberos.SPN}
	if cfg.Kerberos.CCache != "" {
		return append(args, "--ccache", cfg.Kerberos.CCache)
	}
	return append(args, "--keytab", cfg.Kerberos.Keytab)
}

func TestKernelNFSGSSACL(t *testing.T) {
	kernelKerberosProfiles(t, kernelACLBehavior)
}

func TestKernelNFSGSSACLCLI(t *testing.T) {
	kernelKerberosProfiles(t, kernelACLCLI)
}
