//go:build !linux

package gssapi

import "testing"

func TestKEYRINGPlatformRefusal(t *testing.T) {
	for _, name := range []string{"KEYRING:session:c:s", "KEYRING:persistent:1000:cache"} {
		if ValidateCCacheSelection(name, "") == nil {
			t.Fatal("non-Linux accepted KEYRING")
		}
	}
}
