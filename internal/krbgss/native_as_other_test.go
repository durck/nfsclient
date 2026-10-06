//go:build !linux

package gssapi

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFASTPlatformRefusal(t *testing.T) {
	root := t.TempDir()
	err := ValidateNativeAS(filepath.Join(root, "helper"), filepath.Join(root, "armor"), true)
	if err == nil || !strings.Contains(err.Error(), "only on Linux") {
		t.Fatal(err)
	}
}
