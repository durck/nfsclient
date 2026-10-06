package nfs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestASAliasConfigBeforeNetwork(t *testing.T) {
	for _, mode := range []string{"realm", "cache", "sys", "empty-name"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Host: "must-not-resolve.invalid", Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{ConfigFile: "missing.conf", Keytab: "missing.keytab", Principal: "alice@NFS.TEST", ASAlias: "alias@NFS.TEST", SPN: "nfs/server.nfs.test"}}
			want := "--as-alias"
			switch mode {
			case "realm":
				cfg.Kerberos.ASAlias = "alias@OTHER.TEST"
			case "cache":
				cfg.Kerberos.Keytab = ""
				cfg.Kerberos.CCache = "missing.cache"
			case "sys":
				cfg.Security = "sys"
				want = "kerberos options require"
			case "empty-name":
				cfg.Kerberos.ASAlias = "@NFS.TEST"
			}
			c, err := Connect(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("invalid alias reached network")
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
		})
	}
}
