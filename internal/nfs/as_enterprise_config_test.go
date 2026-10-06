package nfs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestEnterpriseConfigBeforeNetwork(t *testing.T) {
	for _, mode := range []string{"no-upn", "no-start", "no-list", "home-not-approved", "duplicate-realm", "cache", "alias", "sys"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Host: "must-not-resolve.invalid", Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{ConfigFile: "missing.conf", Keytab: "missing.keytab", Principal: "alice@NFS.TEST", EnterpriseUPN: "alias@users.test", ASStartRealm: "MAP.TEST", ASReferralRealms: []string{"MAP.TEST", "NFS.TEST"}, SPN: "nfs/server.nfs.test"}}
			want := "enterprise AS"
			switch mode {
			case "no-upn":
				cfg.Kerberos.EnterpriseUPN = ""
			case "no-start":
				cfg.Kerberos.ASStartRealm = ""
			case "no-list":
				cfg.Kerberos.ASReferralRealms = nil
			case "home-not-approved":
				cfg.Kerberos.ASReferralRealms = []string{"MAP.TEST"}
			case "duplicate-realm":
				cfg.Kerberos.ASReferralRealms = []string{"MAP.TEST", "NFS.TEST", "NFS.TEST"}
			case "cache":
				cfg.Kerberos.Keytab = ""
				cfg.Kerberos.CCache = "missing.cache"
			case "alias":
				cfg.Kerberos.ASAlias = "alias@NFS.TEST"
			case "sys":
				cfg.Security = "sys"
				want = "kerberos options require"
			}
			c, err := Connect(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("invalid enterprise configuration reached network")
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
		})
	}
}

func TestEnterpriseSelectionPinned(t *testing.T) {
	realms := []string{"MAP.TEST", "NFS.TEST"}
	cfg := Config{Version: "4.2", Security: "krb5p", Kerberos: KerberosConfig{ConfigFile: "explicit.conf", Keytab: "explicit.keytab", Principal: "alice@NFS.TEST", SPN: "nfs/server.nfs.test", EnterpriseUPN: "alias@users.test", ASStartRealm: "MAP.TEST", ASReferralRealms: realms}}
	if err := validateSecurity(&cfg); err != nil {
		t.Fatal(err)
	}
	realms[0] = "EVIL.TEST"
	if cfg.Kerberos.ASReferralRealms[0] != "MAP.TEST" {
		t.Fatal("caller mutation changed approved realm selection")
	}
}
