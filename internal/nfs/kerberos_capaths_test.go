package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestKerberosCAPathsReplacementFailure(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_MULTIHOP") != "1" || os.Getenv("NFS_VIEWER_KRB5_CAPATHS") != "1" {
		t.Skip("requires explicit three-realm policy fixture")
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "4.2"} {
			for _, credential := range []string{"keytab", "ccache"} {
				for _, scenario := range []string{"direct", "missing", "invalid"} {
					t.Run(network+"/"+version+"/"+credential+"/"+scenario, func(t *testing.T) {
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
						if _, err = rand.Read(nonce[:]); err != nil {
							t.Fatal(err)
						}
						file, err := c.Create(ctx, root.Handle, fmt.Sprintf("policy-failure-%x", nonce), 0600, false)
						if err != nil {
							t.Fatal(err)
						}
						data, err := os.ReadFile(cfg.Kerberos.ConfigFile)
						if err != nil {
							t.Fatal(err)
						}
						replacement := "."
						if scenario == "invalid" {
							replacement = "CLIENT.TEST"
						}
						text := strings.ReplaceAll(string(data), "NFS.TEST = MID.TEST", "NFS.TEST = "+replacement)
						if scenario == "missing" {
							text = strings.ReplaceAll(string(data), "NFS.TEST = MID.TEST", "OTHER.TEST = .")
						}
						c.nfs.mu.Lock()
						err = os.WriteFile(cfg.Kerberos.ConfigFile, []byte(text), 0600)
						c.nfs.gss.renewAt = time.Now()
						c.nfs.mu.Unlock()
						if err != nil {
							t.Fatal(err)
						}
						_, err = c.WriteFrom(ctx, file.Handle, bytes.NewReader([]byte("must not arrive")))
						if err == nil || !strings.Contains(err.Error(), "capaths") || !strings.Contains(err.Error(), "pending NFS request not sent") {
							t.Fatalf("policy did not stop mutation: %v", err)
						}
						if _, err = c.GetAttr(ctx, file.Handle); err == nil || !strings.Contains(err.Error(), "session closed") {
							t.Fatalf("failed session revived: %v", err)
						}
						if c.KerberosRenewals() != 0 || c.Identity() != "alice@CLIENT.TEST (krb5p)" {
							t.Fatal("failed replacement changed identity or was counted as successful")
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
