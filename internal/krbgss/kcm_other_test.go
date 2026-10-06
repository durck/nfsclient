//go:build !linux

package gssapi

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestKCMPlatformRefusal(t *testing.T) {
	if err := ValidateCCacheSelection("KCM:fixture", filepath.Join(t.TempDir(), "kcm")); err == nil || !strings.Contains(err.Error(), "only on Linux") {
		t.Fatal("non-Linux source accepted", err)
	}
}
