package nfs

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestV4OnlyAutoNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name, target, mode string
		wantVersions       []uint32
		wantErr            bool
	}{
		{"minor-fallback", "4.0", "", []uint32{4, 4, 4}, false},
		{"no-legacy-fallback", "3", "", []uint32{4, 4, 4}, true},
		{"denied", "4.2", "denied", []uint32{4}, true},
		{"late-mismatch", "4.2", "late-mismatch", []uint32{4}, true},
		{"rpc-unavailable", "4.2", "rpc-unavailable", []uint32{4}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, key := autoCredentials(t)
			p := &autoPeer{t: t, keytab: key, target: tc.target, mode: tc.mode}
			port, stop := p.listen()
			defer stop()
			c, err := Connect(context.Background(), Config{Host: "127.0.0.1", Version: "auto", V4Only: true, Security: "krb5p", Kerberos: k, NFSPort: port, MountPort: port, Timeout: time.Second})
			if c != nil {
				defer c.Close()
				if c.Version() != tc.target || !c.config.V4Only {
					t.Error("negotiation changed selected profile")
				}
				c.Close()
			}
			stop()
			if (err != nil) != tc.wantErr {
				t.Fatalf("connection error = %v, want error %v", err, tc.wantErr)
			}
			if tc.mode == "denied" && !errors.Is(err, Status(13)) {
				t.Fatalf("lost authorization refusal: %v", err)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if !reflect.DeepEqual(p.versions, tc.wantVersions) || p.accepted != p.closed {
				t.Fatalf("unsafe retry or leaked connection: versions=%v want=%v accepted=%d closed=%d", p.versions, tc.wantVersions, p.accepted, p.closed)
			}
			if tc.target == "4.0" && !reflect.DeepEqual(p.probes, []string{"4.2", "4.1", "4.0"}) {
				t.Fatalf("missing safe empty COMPOUND probes: %v", p.probes)
			}
			if (tc.mode == "denied" || tc.mode == "late-mismatch") && p.state != 1 {
				t.Fatalf("initialization replayed: %d", p.state)
			}
		})
	}
}

func TestV4OnlyRejectsLegacyProfiles(t *testing.T) {
	for _, cfg := range []Config{{Version: "2"}, {Version: "3"}, {Version: "auto", Transport: "udp"}} {
		cfg.V4Only, cfg.Timeout = true, time.Second
		// Missing host ensures a profile validation error must precede dialing.
		_, err := Connect(context.Background(), cfg)
		if err == nil || err.Error() != "NFSv4-only connections require a v4 version and TCP or iWARP" {
			t.Fatalf("accepted invalid v4-only profile or reached network: %v", err)
		}
	}
}
