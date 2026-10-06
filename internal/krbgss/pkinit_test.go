package gssapi

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPKINITSelectionBounds(t *testing.T) {
	for _, mode := range []string{"helper", "certificate", "key", "ca", "relative", "crl", "newline", "platform"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			helper := filepath.Join(dir, "helper")
			p := PKINITFiles{Cert: filepath.Join(dir, "cert"), Key: filepath.Join(dir, "key"), CA: filepath.Join(dir, "ca")}
			switch mode {
			case "helper":
				helper = ""
			case "certificate":
				p.Cert = ""
			case "key":
				p.Key = ""
			case "ca":
				p.CA = ""
			case "relative":
				p.Key = "relative"
			case "crl":
				p.CRL = "relative"
			case "newline":
				p.Cert += "\n"
			}
			err := ValidatePKINIT(helper, p)
			if mode == "helper" || mode == "platform" && nativeASPlatform() == nil {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe PKINIT selection accepted")
			}
			if mode == "platform" && nativeASPlatform() != nil && !strings.Contains(err.Error(), "only on Linux") {
				t.Fatal(err)
			}
		})
	}
}
