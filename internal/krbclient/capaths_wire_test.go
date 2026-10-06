package client

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfsclient/internal/testutil/kdcfixture"
)

func TestCAPathsWire(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, scenario := range []string{"ordered", "direct", "referral", "final-referral", "missing", "local-referral"} {
			t.Run(network+"/"+scenario, func(t *testing.T) {
				key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}
				var mu sync.Mutex
				var calls []string
				peer := kdcfixture.Start(t, func(_ string, b []byte) []byte {
					var req messages.TGSReq
					if err := req.Unmarshal(b); err != nil {
						t.Error(err)
						return nil
					}
					mu.Lock()
					calls = append(calls, req.ReqBody.Realm+":"+req.ReqBody.SName.PrincipalNameString())
					mu.Unlock()
					now := time.Now().UTC()
					part := messages.EncKDCRepPart{Key: key, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), SRealm: req.ReqBody.Realm, SName: req.ReqBody.SName}
					if scenario == "referral" || scenario == "local-referral" || scenario == "final-referral" && req.ReqBody.Realm == "TARGET" {
						part.SName = types.NewPrincipalName(2, "krbtgt/UNEXPECTED")
					}
					rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 13, CRealm: "HOME", CName: req.ReqBody.CName, Ticket: messages.Ticket{TktVNO: 5, Realm: req.ReqBody.Realm, SName: part.SName, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic ticket")}}}}
					plain, err := part.Marshal()
					if err != nil {
						t.Error(err)
						return nil
					}
					rep.EncPart, err = crypto.GetEncryptedData(plain, key, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
					if err != nil {
						t.Error(err)
						return nil
					}
					wire, err := rep.Marshal()
					if err != nil {
						t.Error(err)
						return nil
					}
					return wire
				})
				cfg := config.New()
				cfg.LibDefaults.UDPPreferenceLimit = 1
				if network == "udp" {
					cfg.LibDefaults.UDPPreferenceLimit = 32700
				}
				for _, r := range []string{"HOME", "FIRST", "SECOND", "TARGET", "UNEXPECTED"} {
					cfg.Realms = append(cfg.Realms, config.Realm{Realm: r, KDC: []string{peer.Address}})
				}
				target := "TARGET"
				if scenario == "local-referral" {
					target = "HOME"
				}
				cfg.DomainRealm["server.test"] = target
				text := "[capaths]\n HOME = {\n TARGET = FIRST SECOND\n }"
				if scenario == "direct" || scenario == "referral" {
					text = "[capaths]\n HOME = {\n TARGET = .\n }"
				}
				if scenario == "missing" || scenario == "local-referral" {
					text = "[capaths]"
				}
				policy, err := ParseCAPaths(text)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				cl := NewWithPassword("alice", "HOME", "synthetic-test-only", cfg, NetworkContext(ctx), TrustPaths(policy))
				defer cl.Destroy()
				now := time.Now().Add(-time.Second)
				home := messages.Ticket{TktVNO: 5, Realm: "HOME", SName: types.NewPrincipalName(2, "krbtgt/HOME"), EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic home TGT")}}
				cl.addSession(home, messages.EncKDCRepPart{Key: key, AuthTime: now, EndTime: now.Add(time.Hour)})
				// A session obtained on a different path must not shortcut the explicit route.
				other := home
				other.Realm = "WRONG-PATH"
				other.SName = types.NewPrincipalName(2, "krbtgt/TARGET")
				cl.addSession(other, messages.EncKDCRepPart{Key: key, AuthTime: now, EndTime: now.Add(time.Hour)})
				if scenario == "missing" {
					cached := other
					cached.Realm = "TARGET"
					cached.SName = types.NewPrincipalName(2, "nfs/server.test")
					cl.cache.addEntry(cached, now, now, now.Add(time.Hour), time.Time{}, key)
				}
				_, _, err = cl.GetServiceTicket("nfs/server.test")
				success := scenario == "ordered" || scenario == "direct"
				if success && err != nil {
					t.Fatal(err)
				}
				if !success && (err == nil || !strings.Contains(err.Error(), "capaths policy")) {
					t.Fatalf("policy not enforced: %v", err)
				}
				want := []string{"HOME:krbtgt/FIRST", "FIRST:krbtgt/SECOND", "SECOND:krbtgt/TARGET", "TARGET:nfs/server.test"}
				switch scenario {
				case "direct":
					want = []string{"HOME:krbtgt/TARGET", "TARGET:nfs/server.test"}
				case "referral":
					want = []string{"HOME:krbtgt/TARGET"}
				case "local-referral":
					want = []string{"HOME:nfs/server.test"}
				case "missing":
					want = nil
				}
				if success {
					if _, _, err = cl.GetServiceTicket("nfs/server.test"); err != nil {
						t.Fatal(err)
					}
				} // Valid service ticket reuse: no KDC calls.
				mu.Lock()
				got := append([]string(nil), calls...)
				mu.Unlock()
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("calls=%v want=%v", got, want)
				}
				if _, ok := cl.sessions.get("UNEXPECTED"); ok {
					t.Fatal("rejected referral entered sessions")
				}
				if _, ok := cl.cache.getEntry("krbtgt/UNEXPECTED"); ok {
					t.Fatal("rejected referral entered cache")
				}
			})
		}
	}
}
