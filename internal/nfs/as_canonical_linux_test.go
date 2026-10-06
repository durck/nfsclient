//go:build linux

package nfs

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestProtectedASNativeRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_AS_CANON_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT ProtectedAS/KDC/Ganesha fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			t.Run(version+"/"+security, func(t *testing.T) {
				cfg := renewalFixtureConfig(t, version, security, "keytab")
				cfg.Kerberos.Keytab = os.Getenv("NFS_VIEWER_KRB5_KEYTAB")
				cfg.Kerberos.ASAlias = os.Getenv("NFS_VIEWER_AS_ALIAS")
				if cfg.Kerberos.ASAlias == "" {
					t.Fatal("missing explicit AS alias")
				}
				testKerberosRenewalTransfer(t, cfg)
			})
		}
	}
}

func TestProtectedASMissingCanonicalKey(t *testing.T) {
	if os.Getenv("NFS_VIEWER_AS_CANON_NATIVE") != "1" {
		t.Skip("requires explicit disposable MIT ProtectedAS/KDC/Ganesha fixture")
	}
	cfg := renewalFixtureConfig(t, "4.2", "krb5p", "keytab")
	cfg.Kerberos.Keytab = os.Getenv("NFS_VIEWER_KRB5_KEYTAB")
	cfg.Kerberos.ASAlias = os.Getenv("NFS_VIEWER_AS_ALIAS")
	cfg.Kerberos.Principal = "bob@NFS.TEST"
	c, err := Connect(context.Background(), cfg)
	if err == nil {
		c.Close()
		t.Fatal("AS alias replaced pinned canonical principal")
	}
	if !strings.Contains(err.Error(), "matching key not found in keytab") {
		t.Fatal("wrong mismatch refusal", err)
	}
}
