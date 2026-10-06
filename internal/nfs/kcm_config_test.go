package nfs

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestKCMConfigBeforeNetwork(t *testing.T) {
	base := Config{Host: "must-not-resolve.invalid", Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{ConfigFile: "missing.conf", CCache: "KCM:fixture", Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test"}}
	for _, tc := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"no-socket", func(c *Config) {}, "absolute --kcm-socket"},
		{"empty-name", func(c *Config) { c.Kerberos.CCache = "KCM:" }, "nonempty explicit"},
		{"relative-socket", func(c *Config) { c.Kerberos.KCMSocket = "relative" }, "absolute --kcm-socket"},
		{"file-socket", func(c *Config) { c.Kerberos.CCache = "FILE:cache"; c.Kerberos.KCMSocket = "relative" }, "explicit KCM"},
		{"keytab-socket", func(c *Config) {
			c.Kerberos.CCache = ""
			c.Kerberos.Keytab = "missing.keytab"
			c.Kerberos.KCMSocket = "relative"
		}, "explicit KCM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.change(&cfg)
			c, err := Connect(context.Background(), cfg)
			if err == nil {
				c.Close()
				t.Fatal("invalid source reached network")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatal(err)
			}
		})
	}
}
