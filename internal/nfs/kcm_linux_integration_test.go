//go:build linux

package nfs

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestKCMNativeRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KCM_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT KCM/KDC/Ganesha fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				cfg := renewalFixtureConfig(t, version, security, "keytab")
				cfg.Kerberos.Keytab = ""
				cfg.Kerberos.CCache = os.Getenv("NFS_VIEWER_KCM_NAME")
				cfg.Kerberos.KCMSocket = os.Getenv("NFS_VIEWER_KCM_SOCKET")
				if cfg.Kerberos.CCache == "" || cfg.Kerberos.KCMSocket == "" {
					t.Fatal("missing explicit KCM name/socket")
				}
				testKerberosRenewalTransfer(t, cfg)
			})
		}
	}
}

func TestKCMPrincipalMismatch(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KCM_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT KCM/KDC/Ganesha fixture")
	}
	cfg := renewalFixtureConfig(t, "4.2", "krb5p", "keytab")
	cfg.Kerberos.Keytab = ""
	cfg.Kerberos.CCache = os.Getenv("NFS_VIEWER_KCM_NAME")
	cfg.Kerberos.KCMSocket = os.Getenv("NFS_VIEWER_KCM_SOCKET")
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
