package nfs

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFASTConfigBeforeNetwork(t *testing.T) {
	for _, mode := range []string{"helper-without-policy", "armor-without-policy", "relative-helper", "relative-armor", "cache", "alias", "enterprise", "sys"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Host: "must-not-resolve.invalid", Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{ConfigFile: "explicit.conf", Keytab: "explicit.keytab", Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test", RequireFAST: true, ASHelper: filepath.Join(t.TempDir(), "helper"), FASTArmor: filepath.Join(t.TempDir(), "armor")}}
			want := "FAST"
			switch mode {
			case "helper-without-policy":
				cfg.Kerberos.RequireFAST = false
				cfg.Kerberos.FASTArmor = ""
				want = "require-fast"
			case "armor-without-policy":
				cfg.Kerberos.RequireFAST = false
				cfg.Kerberos.ASHelper = ""
				want = "require-fast"
			case "relative-helper":
				cfg.Kerberos.ASHelper = "relative"
			case "relative-armor":
				cfg.Kerberos.FASTArmor = "relative"
			case "cache":
				cfg.Kerberos.Keytab = ""
				cfg.Kerberos.CCache = "explicit.cache"
			case "alias":
				cfg.Kerberos.ASAlias = "root-alias@NFS.TEST"
			case "enterprise":
				cfg.Kerberos.EnterpriseUPN = "root@users.test"
				cfg.Kerberos.ASStartRealm = "NFS.TEST"
				cfg.Kerberos.ASReferralRealms = []string{"NFS.TEST"}
			case "sys":
				cfg.Security = "sys"
				want = "kerberos options require"
			}
			c, err := Connect(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("invalid FAST configuration reached network")
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
		})
	}
}
