package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfsclient/internal/testutil/kdcfixture"
)

func TestKDCFailover(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, scenario := range []string{"silent", "unavailable", "denied", "preauth", "unknown-user", "all-unavailable"} {
			t.Run(transport+"/"+scenario, func(t *testing.T) {
				code := errorcode.KDC_ERR_SVC_UNAVAILABLE
				switch scenario {
				case "denied":
					code = errorcode.KDC_ERR_PREAUTH_FAILED
				case "preauth":
					code = errorcode.KDC_ERR_PREAUTH_REQUIRED
				case "unknown-user":
					code = errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN
				}
				e := messages.NewKRBError(types.PrincipalName{NameString: []string{"krbtgt", "NFS.TEST"}}, "NFS.TEST", code, "synthetic failure")
				wire, err := e.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				first := kdcfixture.Start(t, func(_ string, _ []byte) []byte {
					if scenario == "silent" {
						return nil
					}
					return wire
				})
				second := kdcfixture.Start(t, func(_ string, _ []byte) []byte {
					if scenario == "all-unavailable" {
						return wire
					}
					return []byte("transport reply")
				})
				cfg := config.New()
				cfg.LibDefaults.UDPPreferenceLimit = 1
				if transport == "udp" {
					cfg.LibDefaults.UDPPreferenceLimit = 32700
				}
				cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{first.Address, second.Address}}}
				ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
				defer cancel()
				cl := &Client{Config: cfg, settings: NewSettings(NetworkContext(ctx))}
				b, err := cl.sendToKDC([]byte("request"), "NFS.TEST")
				terminal := scenario == "denied" || scenario == "preauth" || scenario == "unknown-user" || scenario == "all-unavailable"
				if terminal {
					var got messages.KRBError
					if !errors.As(err, &got) || got.ErrorCode != code {
						t.Fatalf("terminal error lost: %v", err)
					}
					if scenario != "all-unavailable" && second.TCP.Load()+second.UDP.Load() != 0 {
						t.Fatal("authentication denial/challenge tried another KDC")
					}
					return
				}
				if err != nil || string(b) != "transport reply" {
					t.Fatalf("did not fail over inside budget: %q %v", b, err)
				}
				// The following AS preauth/TGS exchange must not spend its remaining
				// setup budget retrying the endpoint just found to be unavailable.
				if _, err := cl.sendToKDC([]byte("next exchange"), "NFS.TEST"); err != nil {
					t.Fatal(err)
				}
				if first.TCP.Load()+first.UDP.Load() != 1 || second.TCP.Load()+second.UDP.Load() != 2 {
					t.Fatalf("failed endpoint retried: first=%d second=%d", first.TCP.Load()+first.UDP.Load(), second.TCP.Load()+second.UDP.Load())
				}
				if transport == "udp" && (first.TCP.Load()+second.TCP.Load() != 0) {
					t.Fatal("UDP endpoint failover changed transport")
				}
			})
		}
	}
}

func TestKDCFailoverRecovery(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			e := messages.NewKRBError(types.PrincipalName{NameString: []string{"krbtgt", "NFS.TEST"}}, "NFS.TEST", errorcode.KDC_ERR_SVC_UNAVAILABLE, "synthetic failure")
			wire, err := e.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			var recovered atomic.Bool
			first := kdcfixture.Start(t, func(_ string, _ []byte) []byte {
				if recovered.Load() {
					return []byte("first")
				}
				return wire
			})
			second := kdcfixture.Start(t, func(_ string, _ []byte) []byte {
				if recovered.Load() {
					return wire
				}
				return []byte("second")
			})
			cfg := config.New()
			cfg.LibDefaults.DefaultRealm = "NFS.TEST"
			cfg.LibDefaults.UDPPreferenceLimit = 1
			if transport == "udp" {
				cfg.LibDefaults.UDPPreferenceLimit = 32700
			}
			cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{first.Address, second.Address}}}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			newClient := func() *Client { return &Client{Config: cfg, settings: NewSettings(NetworkContext(ctx))} }
			cl := newClient()
			check := func(c *Client, want string) {
				t.Helper()
				b, err := c.sendToKDC([]byte("request"), "")
				if err != nil || string(b) != want {
					t.Fatalf("want %s, got %q: %v", want, b, err)
				}
			}
			check(cl, "second")
			check(newClient(), "second")
			if first.TCP.Load()+first.UDP.Load() != 2 {
				t.Fatal("new client inherited another login's failure history")
			}
			recovered.Store(true)
			check(cl, "first")
			check(cl, "first")
			if first.TCP.Load()+first.UDP.Load() != 4 || second.TCP.Load()+second.UDP.Load() != 3 {
				t.Fatal("failed candidates were excluded permanently or recovery did not restore priority")
			}
		})
	}
}
