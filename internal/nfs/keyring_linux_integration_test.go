//go:build linux

package nfs

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestKEYRINGNativeRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KEYRING_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT KEYRING/KDC/Ganesha fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				cfg := renewalFixtureConfig(t, version, security, "keytab")
				cfg.Kerberos.Keytab = ""
				cfg.Kerberos.CCache = os.Getenv("NFS_VIEWER_KEYRING_NAME")
				if cfg.Kerberos.CCache == "" {
					t.Fatal("missing explicit KEYRING name")
				}
				testKerberosRenewalTransfer(t, cfg)
			})
		}
	}
}

func TestKEYRINGPrincipalMismatch(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KEYRING_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT KEYRING/KDC/Ganesha fixture")
	}
	cfg := renewalFixtureConfig(t, "4.2", "krb5p", "keytab")
	cfg.Kerberos.Keytab = ""
	cfg.Kerberos.CCache = os.Getenv("NFS_VIEWER_KEYRING_NAME")
	cfg.Kerberos.Principal = "bob@NFS.TEST"
	c, err := Connect(context.Background(), cfg)
	if err == nil {
		c.Close()
		t.Fatal("cache principal silently replaced configured principal")
	}
	if !strings.Contains(err.Error(), "ccache principal does not match") {
		t.Fatal("wrong mismatch refusal", err)
	}
}
