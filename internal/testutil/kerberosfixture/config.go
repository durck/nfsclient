// Package kerberosfixture configures only explicit disposable loopback realms.
package kerberosfixture

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
)

func CrossRealmConfig(t *testing.T, network, targetRealm string) string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("NFS_VIEWER_KRB5_CROSS_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewFromString(string(data))
	wantRealms := 2
	if os.Getenv("NFS_VIEWER_KRB5_MULTIHOP") == "1" {
		wantRealms = 3
	}
	if err != nil || len(cfg.Realms) != wantRealms {
		t.Fatalf("invalid cross-realm fixture configuration: %v", err)
	}
	text := string(data)
	for _, realm := range cfg.Realms {
		if len(realm.KDC) != 1 {
			t.Fatal("fixture requires exactly one KDC per realm")
		}
		host, _, err := net.SplitHostPort(realm.KDC[0])
		if err != nil || !net.ParseIP(host).IsLoopback() {
			t.Fatal("fixture KDC must be loopback")
		}
		if network == "udp" {
			port := os.Getenv("NFS_VIEWER_KRB5_KDC_UDP_PORT")
			if realm.Realm == "CLIENT.TEST" {
				port = os.Getenv("NFS_VIEWER_KRB5_CROSS_UDP_PORT")
			} else if realm.Realm == "MID.TEST" {
				port = os.Getenv("NFS_VIEWER_KRB5_MID_UDP_PORT")
			}
			if port == "" {
				t.Fatal("missing KDC UDP fixture port")
			}
			text = strings.ReplaceAll(text, realm.KDC[0], net.JoinHostPort(host, port))
		}
	}
	if network == "udp" {
		text = strings.ReplaceAll(text, "udp_preference_limit = 1", "udp_preference_limit = 32700")
	}
	if targetRealm != "NFS.TEST" {
		text = strings.ReplaceAll(text, "NFS.TEST", targetRealm)
	}
	if os.Getenv("NFS_VIEWER_KRB5_CAPATHS") == "1" {
		via := "."
		if wantRealms == 3 {
			via = "MID.TEST"
		}
		text += "\n[capaths]\n CLIENT.TEST = {\n  " + targetRealm + " = " + via + "\n }\n"
	}
	path := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
