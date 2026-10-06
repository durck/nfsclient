package gssapi

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
)

func TestFASTSelectionBounds(t *testing.T) {
	if err := ValidateNativeAS("", filepath.Join(t.TempDir(), "armor"), true); err != nil {
		t.Fatal("pure-Go FAST must be available without a helper", err)
	}
	for _, tc := range []struct {
		helper, armor string
		required      bool
	}{{"helper", "", false}, {"", "armor", false}, {"relative", "relative", true}, {"", "", true}, {filepath.Join(t.TempDir(), "h"), "relative", true}} {
		if ValidateNativeAS(tc.helper, tc.armor, tc.required) == nil {
			t.Fatal("invalid FAST selection accepted")
		}
	}
}
func TestFASTNumericConfiguration(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:88", "127.0.0.1", "[::1]:88", "::1", "kdc.example.test:88", "127.0.0.1:bad", "127.0.0.1:0", "127.0.0.1:65536"} {
		t.Run(endpoint, func(t *testing.T) {
			cfg := config.New()
			cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{endpoint}}}
			text, err := nativeASConfiguration(cfg, "NFS.TEST")
			valid := endpoint == "127.0.0.1:88" || endpoint == "127.0.0.1" || endpoint == "[::1]:88" || endpoint == "::1"
			if (err == nil) != valid {
				t.Fatal("incorrect endpoint selection", err)
			}
			if valid {
				if !strings.Contains(text, "kdc_timesync = 0") {
					t.Fatal("native AS must not write KDC clock-offset metadata")
				}
				if _, err := config.NewFromString(text); err != nil {
					t.Fatal("generated numeric configuration", err)
				}
			}
		})
	}
	for i, mode := range []string{"dns", "empty", "missing-kdc", "realm-syntax", "home-syntax", "udp"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			cfg := config.New()
			cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{"127.0.0.1:88"}}}
			home := "NFS.TEST"
			switch mode {
			case "dns":
				cfg.LibDefaults.DNSLookupKDC = true
			case "empty":
				cfg.Realms = nil
			case "missing-kdc":
				cfg.Realms[0].KDC = nil
			case "realm-syntax":
				cfg.Realms[0].Realm = "bad\nrealm"
			case "home-syntax":
				home = "bad\nrealm"
			case "udp":
				cfg.LibDefaults.UDPPreferenceLimit = 65535
			}
			if _, err := nativeASConfiguration(cfg, home); err == nil {
				t.Fatal("unsafe native configuration accepted")
			}
		})
	}
}
