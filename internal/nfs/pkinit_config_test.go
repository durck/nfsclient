package nfs

import (
	"context"
	bgss "nfsclient/internal/krbgss"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPKINITConfigBeforeNetwork(t *testing.T) {
	for _, mode := range []string{"relative-helper", "missing-cert", "missing-key", "missing-ca", "relative-key", "relative-crl", "keytab", "cache", "fast", "armor", "alias", "enterprise", "sys"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cfg := Config{Host: "must-not-resolve.invalid", Version: "4.2", Transport: "tcp", Security: "krb5p", Timeout: time.Second, Kerberos: KerberosConfig{ConfigFile: "explicit.conf", Principal: "root@NFS.TEST", SPN: "nfs/server.nfs.test", ASHelper: filepath.Join(dir, "helper"), PKINIT: bgss.PKINITFiles{Cert: filepath.Join(dir, "cert"), Key: filepath.Join(dir, "key"), CA: filepath.Join(dir, "ca")}}}
			switch mode {
			case "relative-helper":
				cfg.Kerberos.ASHelper = "relative"
			case "missing-cert":
				cfg.Kerberos.PKINIT.Cert = ""
			case "missing-key":
				cfg.Kerberos.PKINIT.Key = ""
			case "missing-ca":
				cfg.Kerberos.PKINIT.CA = ""
			case "relative-key":
				cfg.Kerberos.PKINIT.Key = "relative"
			case "relative-crl":
				cfg.Kerberos.PKINIT.CRL = "relative"
			case "keytab":
				cfg.Kerberos.Keytab = "explicit.keytab"
			case "cache":
				cfg.Kerberos.CCache = "explicit.cache"
			case "fast":
				cfg.Kerberos.RequireFAST = true
			case "armor":
				cfg.Kerberos.FASTArmor = filepath.Join(dir, "armor")
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
				t.Fatal("invalid PKINIT reached network", err)
			}
		})
	}
}
