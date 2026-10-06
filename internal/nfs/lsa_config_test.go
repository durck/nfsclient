package nfs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLSAConfigBeforeNetwork(t *testing.T) {
	for _, mode := range []string{"default", "other-logon", "socket", "keytab", "alias", "enterprise", "sys"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Host: "must-not-resolve.invalid", Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{ConfigFile: "explicit.conf", CCache: "MSLSA:CURRENT", Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			switch mode {
			case "default":
				cfg.Kerberos.CCache = "MSLSA:"
			case "other-logon":
				cfg.Kerberos.CCache = "MSLSA:123"
			case "socket":
				cfg.Kerberos.KCMSocket = "socket"
			case "keytab":
				cfg.Kerberos.Keytab = "explicit.keytab"
			case "alias":
				cfg.Kerberos.ASAlias = "alias@NFS.TEST"
			case "enterprise":
				cfg.Kerberos.EnterpriseUPN = "root@users.test"
				cfg.Kerberos.ASStartRealm = "NFS.TEST"
				cfg.Kerberos.ASReferralRealms = []string{"NFS.TEST"}
			case "sys":
				cfg.Security = "sys"
			}
			c, err := Connect(context.Background(), cfg)
			if c != nil {
				c.Close()
			}
			if err == nil || strings.Contains(err.Error(), "resolve") || strings.Contains(err.Error(), "dial") {
				t.Fatal("invalid LSA reached network", err)
			}
		})
	}
}
