//go:build linux

package nfs

import (
	"context"
	bgss "nfs-viewer/internal/krbgss"
	"nfs-viewer/internal/testutil/kdcfixture"
	"os"
	"testing"
)

func TestPKINITNativeRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PKINIT_NATIVE") != "1" {
		t.Skip("requires disposable MIT PKINIT/KDC/Ganesha fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				t.Run(network+"/"+version+"/"+security, func(t *testing.T) {
					cfg := renewalFixtureConfig(t, version, security, "keytab")
					cfg.Kerberos.Keytab = ""
					cfg.Kerberos.PKINIT = bgss.PKINITFiles{Cert: "/run/nfs-test/client.crt", Key: "/run/nfs-test/client.key", CA: "/run/nfs-test/ca.crt", CRL: "/run/nfs-test/clean.crl"}
					cfg.Kerberos.ASHelper = os.Getenv("NFS_VIEWER_AS_HELPER")

					conf, o := kdcfixture.PKINITConfig(t, cfg.Kerberos.ConfigFile, network, false)
					cfg.Kerberos.ConfigFile = conf
					testKerberosRenewalTransfer(t, cfg)
					if o.PKINIT.Load() < 2 || o.PlainTimestamp.Load() != 0 {
						t.Fatalf("PKINIT renewal wire: armored=%d plain=%d", o.PKINIT.Load(), o.PlainTimestamp.Load())
					}
				})
			}
		}
	}
}

func TestPKINITNativeRejectsDowngrade(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PKINIT_NATIVE") != "1" {
		t.Skip("requires disposable MIT PKINIT fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			cfg := renewalFixtureConfig(t, "3", "krb5p", "keytab")
			cfg.Kerberos.Keytab = ""
			cfg.Kerberos.PKINIT = bgss.PKINITFiles{Cert: "/run/nfs-test/client.crt", Key: "/run/nfs-test/client.key", CA: "/run/nfs-test/ca.crt", CRL: "/run/nfs-test/clean.crl"}
			cfg.Kerberos.ASHelper = os.Getenv("NFS_VIEWER_AS_HELPER")

			conf, o := kdcfixture.PKINITConfig(t, cfg.Kerberos.ConfigFile, network, true)
			cfg.Kerberos.ConfigFile = conf
			c, err := Connect(context.Background(), cfg)
			if c != nil {
				c.Close()
			}
			if err == nil || o.Removed.Load() == 0 || o.PlainTimestamp.Load() != 0 {
				t.Fatalf("downgrade: err=%v armored=%d removed=%d plain=%d", err, o.PKINIT.Load(), o.Removed.Load(), o.PlainTimestamp.Load())
			}
		})
	}
}

func TestPKINITNativeRejectsCertificates(t *testing.T) {
	if os.Getenv("NFS_VIEWER_PKINIT_NATIVE") != "1" {
		t.Skip("requires disposable MIT PKINIT fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, mode := range []string{"wrong-ca", "foreign-san", "key-mismatch", "expired", "revoked-kdc", "malformed-crl"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				cfg := renewalFixtureConfig(t, "3", "krb5p", "keytab")
				cfg.Kerberos.Keytab = ""
				cfg.Kerberos.ASHelper = os.Getenv("NFS_VIEWER_AS_HELPER")
				p := bgss.PKINITFiles{Cert: "/run/nfs-test/client.crt", Key: "/run/nfs-test/client.key", CA: "/run/nfs-test/ca.crt", CRL: "/run/nfs-test/clean.crl"}
				switch mode {
				case "wrong-ca":
					p.CA = "/run/nfs-test/other-ca.crt"
				case "foreign-san":
					p.Cert = "/run/nfs-test/foreign.crt"
					p.Key = "/run/nfs-test/foreign.key"
				case "key-mismatch":
					p.Key = "/run/nfs-test/foreign.key"
				case "expired":
					p.Cert = "/run/nfs-test/expired.crt"
					p.Key = "/run/nfs-test/expired.key"
				case "revoked-kdc":
					p.CRL = "/run/nfs-test/revoked.crl"
				case "malformed-crl":
					p.CRL = "/run/nfs-test/client.crt"
				}
				cfg.Kerberos.PKINIT = p
				conf, o := kdcfixture.PKINITConfig(t, cfg.Kerberos.ConfigFile, network, false)
				cfg.Kerberos.ConfigFile = conf
				c, err := Connect(context.Background(), cfg)
				if c != nil {
					c.Close()
				}
				if err == nil || o.PlainTimestamp.Load() != 0 {
					t.Fatalf("unsafe certificate accepted or timestamp fallback: err=%v plain=%d", err, o.PlainTimestamp.Load())
				}
			})
		}
	}
}
