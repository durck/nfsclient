package kerberosfixture

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
)

// ADConfig only accepts the explicitly opted-in, disposable Samba AD fixture.
// It must not turn an ordinary test run into access to a production directory.
func ADConfig(t *testing.T, network, enctype, lifetime string) string {
	t.Helper()
	path := os.Getenv("NFS_VIEWER_AD_CONFIG")
	if path == "" {
		t.Skip("requires tests/samba-ad fixture")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewFromString(string(data))
	if err != nil || len(cfg.Realms) != 1 || cfg.Realms[0].Realm != "AD.NFS.TEST" || len(cfg.Realms[0].KDC) != 1 {
		t.Fatalf("invalid Samba AD fixture configuration: %v", err)
	}
	endpoint := cfg.Realms[0].KDC[0]
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("Samba AD fixture KDC must be loopback")
	}
	text := string(data)
	if network == "udp" {
		port := os.Getenv("NFS_VIEWER_AD_KDC_UDP_PORT")
		if port == "" {
			t.Fatal("missing Samba AD KDC UDP port")
		}
		text = strings.ReplaceAll(text, endpoint, net.JoinHostPort(host, port))
		text = strings.ReplaceAll(text, "udp_preference_limit = 1", "udp_preference_limit = 32700")
	}
	text = strings.ReplaceAll(text, "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96", enctype)
	if lifetime != "" {
		text = strings.Replace(text, "[libdefaults]", "[libdefaults]\n ticket_lifetime = "+lifetime, 1)
	}
	path = filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
