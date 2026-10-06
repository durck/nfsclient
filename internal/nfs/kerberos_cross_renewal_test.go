package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"nfsclient/internal/testutil/kdcfixture"
	"nfsclient/internal/testutil/kerberosfixture"
)

func TestKerberosCrossRealmRenewalTransfer(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_CROSS_CONFIG") == "" || os.Getenv("NFS_VIEWER_KRB5_SHORT") != "1" {
		t.Skip("requires direct-trust MIT fixture with four-second service tickets")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
			for _, security := range []string{"krb5", "krb5i", "krb5p"} {
				if version == "3-udp" && security != "krb5" {
					continue
				}
				for _, credential := range []string{"keytab", "ccache"} {
					t.Run(network+"/"+version+"/"+security+"/"+credential, func(t *testing.T) {
						t.Parallel()
						testKerberosRenewalTransfer(t, crossRenewalFixtureConfig(t, network, version, security, credential))
					})
				}
			}
		}
	}
}

func crossRenewalFixtureConfig(t *testing.T, network, version, security, credential string) Config {
	t.Helper()
	cfg := renewalFixtureConfig(t, version, security, "keytab")
	cfg.Kerberos = KerberosConfig{ConfigFile: kerberosfixture.CrossRealmConfig(t, network, "NFS.TEST"), Principal: "alice@CLIENT.TEST", SPN: "nfs/server.nfs.test"}
	if credential == "ccache" {
		cfg.Kerberos.CCache = os.Getenv("NFS_VIEWER_KRB5_CROSS_CCACHE")
	} else {
		cfg.Kerberos.Keytab = os.Getenv("NFS_VIEWER_KRB5_CROSS_KEYTAB")
	}
	return cfg
}

func TestKerberosCrossRealmRenewalFailure(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_CROSS_CONFIG") == "" {
		t.Skip("requires direct-trust MIT fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.2"} {
			for _, credential := range []string{"keytab", "ccache"} {
				failedRealms := []string{"CLIENT.TEST", "NFS.TEST"}
				if os.Getenv("NFS_VIEWER_KRB5_MULTIHOP") == "1" {
					failedRealms = append(failedRealms, "MID.TEST")
				}
				for _, failedRealm := range failedRealms {
					t.Run(network+"/"+version+"/"+credential+"/"+failedRealm, func(t *testing.T) {
						t.Parallel()
						cfg := crossRenewalFixtureConfig(t, network, version, "krb5p", credential)
						observerCfg := crossRenewalFixtureConfig(t, network, version, "krb5p", credential)
						ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
						defer cancel()
						c, err := Connect(ctx, cfg)
						if err != nil {
							t.Fatal(err)
						}
						defer c.Close()
						root, err := c.Mount(ctx, "/data")
						if err != nil {
							t.Fatal(err)
						}
						var nonce [12]byte
						if _, err := rand.Read(nonce[:]); err != nil {
							t.Fatal(err)
						}
						file, err := c.Create(ctx, root.Handle, fmt.Sprintf("cross-failure-%x", nonce), 0600, false)
						if err != nil {
							t.Fatal(err)
						}
						confBytes, err := os.ReadFile(cfg.Kerberos.ConfigFile)
						if err != nil {
							t.Fatal(err)
						}
						conf, err := config.NewFromString(string(confBytes))
						if err != nil {
							t.Fatal(err)
						}
						silent := kdcfixture.Start(t, func(actual string, _ []byte) []byte {
							if actual != network {
								t.Errorf("renewal changed KDC transport to %s", actual)
							}
							return nil
						})
						broken := string(confBytes)
						for _, realm := range conf.Realms {
							if realm.Realm == failedRealm {
								broken = strings.ReplaceAll(broken, realm.KDC[0], silent.Address)
							}
						}
						if broken == string(confBytes) {
							t.Fatal("failed realm was not configured")
						}
						// Serialize config replacement against the lease's possible renewal.
						c.nfs.mu.Lock()
						err = os.WriteFile(cfg.Kerberos.ConfigFile, []byte(broken), 0600)
						c.nfs.gss.renewAt = time.Now()
						c.nfs.mu.Unlock()
						if err != nil {
							t.Fatal(err)
						}
						requestCtx, requestCancel := context.WithTimeout(ctx, 500*time.Millisecond)
						defer requestCancel()
						_, err = c.WriteFrom(requestCtx, file.Handle, bytes.NewReader([]byte("must not arrive")))
						if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "pending NFS request not sent") {
							t.Fatalf("cross-realm renewal must stop before mutation: %v", err)
						}
						calls := silent.TCP.Load() + silent.UDP.Load()
						if calls == 0 {
							t.Fatal("renewal did not contact the failed realm")
						}
						if _, err := c.GetAttr(ctx, file.Handle); err == nil || !strings.Contains(err.Error(), "session closed") {
							t.Fatalf("failed session revived: %v", err)
						}
						if silent.TCP.Load()+silent.UDP.Load() != calls || c.KerberosRenewals() != 0 || c.Identity() != "alice@CLIENT.TEST (krb5p)" {
							t.Fatal("failed renewal retried or changed identity")
						}
						observer, err := Connect(ctx, observerCfg)
						if err != nil {
							t.Fatal(err)
						}
						defer observer.Close()
						attr, err := observer.GetAttr(ctx, file.Handle)
						if err != nil || attr.Size != 0 {
							t.Fatalf("mutation reached server: size=%d err=%v", attr.Size, err)
						}
					})
				}
			}
		}
	}
}
