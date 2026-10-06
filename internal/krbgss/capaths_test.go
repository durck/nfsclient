package gssapi

import (
	"strings"
	"testing"
)

func TestInitiatorPolicyBeforeCredentials(t *testing.T) {
	for _, text := range []string{"", "[capaths]\n HOME = {\n TARGET = HOME\n }", "include /unavailable/config"} {
		_, err := NewInitiator(WithConfig[Initiator](text), WithRealm[Initiator]("HOME"), WithUsername[Initiator]("alice"), WithCCache("missing-credential-file"))
		if err == nil || strings.Contains(err.Error(), "missing-credential-file") {
			t.Fatalf("configuration did not fail before credential use: %v", err)
		}
	}
}
