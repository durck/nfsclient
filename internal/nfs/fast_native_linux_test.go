//go:build linux

package nfs

import (
	"context"
	"nfsclient/internal/testutil/kdcfixture"
	"os"
	"testing"
)

func TestFASTNativeRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_FAST_NATIVE") != "1" {
		t.Skip("requires disposable MIT FAST/KDC/Ganesha fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				t.Run(network+"/"+version+"/"+security, func(t *testing.T) {
					cfg := renewalFixtureConfig(t, version, security, "keytab")
					cfg.Kerberos.RequireFAST = true
					cfg.Kerberos.ASHelper = os.Getenv("NFS_VIEWER_AS_HELPER")
					cfg.Kerberos.FASTArmor = os.Getenv("NFS_VIEWER_FAST_ARMOR")
					conf, o := kdcfixture.FASTConfig(t, cfg.Kerberos.ConfigFile, network, false)
					cfg.Kerberos.ConfigFile = conf
					testKerberosRenewalTransfer(t, cfg)
					if o.Armored.Load() < 2 || o.PlainTimestamp.Load() != 0 {
						t.Fatalf("FAST renewal wire: armored=%d plain=%d", o.Armored.Load(), o.PlainTimestamp.Load())
					}
				})
			}
		}
	}
}

func TestFASTNativeRejectsDowngrade(t *testing.T) {
	if os.Getenv("NFS_VIEWER_FAST_NATIVE") != "1" {
		t.Skip("requires disposable MIT FAST fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			cfg := renewalFixtureConfig(t, "3", "krb5p", "keytab")
			cfg.Kerberos.RequireFAST = true
			cfg.Kerberos.ASHelper = os.Getenv("NFS_VIEWER_AS_HELPER")
			cfg.Kerberos.FASTArmor = os.Getenv("NFS_VIEWER_FAST_ARMOR")
			conf, o := kdcfixture.FASTConfig(t, cfg.Kerberos.ConfigFile, network, true)
			cfg.Kerberos.ConfigFile = conf
			c, err := Connect(context.Background(), cfg)
			if c != nil {
				c.Close()
			}
			if err == nil || o.Armored.Load() == 0 || o.Removed.Load() == 0 || o.PlainTimestamp.Load() != 0 {
				t.Fatalf("downgrade: err=%v armored=%d removed=%d plain=%d", err, o.Armored.Load(), o.Removed.Load(), o.PlainTimestamp.Load())
			}
		})
	}
}
