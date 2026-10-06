package client

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfsclient/internal/testutil/kdcfixture"
)

func asIdentityKeytab(t *testing.T) (*keytab.Keytab, types.EncryptionKey) {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry("alice", "NFS.TEST", "synthetic-AS-test-only", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	key, _, err := kt.GetEncryptionKey(types.NewPrincipalName(1, "alice"), "NFS.TEST", 1, 18)
	if err != nil {
		t.Fatal(err)
	}
	return kt, key
}

func asIdentityClient(t *testing.T, kt *keytab.Keytab, network string, endpoints ...string) *Client {
	t.Helper()
	cfg := config.New()
	cfg.LibDefaults.UDPPreferenceLimit = 1
	if network == "udp" {
		cfg.LibDefaults.UDPPreferenceLimit = 32700
	}
	cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: endpoints[:1]}}
	if len(endpoints) > 1 {
		cfg.Realms = append(cfg.Realms, config.Realm{Realm: "OTHER.TEST", KDC: endpoints[1:]})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	cl := NewWithKeytab("alice", "NFS.TEST", kt, cfg, NetworkContext(ctx), DisablePAFXFAST(true))
	t.Cleanup(cl.Destroy)
	return cl
}

// Real AS wire decoding and authenticated EncASRepPart, with opaque synthetic
// ticket ciphertext. The client cannot decrypt the TGT; it must bind its clear
// routing metadata to the authenticated reply before session insertion/use.
func TestASReplyIdentity(t *testing.T) {
	kt, key := asIdentityKeytab(t)
	for _, network := range []string{"tcp", "udp"} {
		for _, scenario := range []string{"valid", "ticket-realm", "ticket-service", "empty-ticket-name", "empty-component", "client-name", "client-realm", "encrypted-realm", "encrypted-name", "nonce", "ciphertext"} {
			t.Run(network+"/"+scenario, func(t *testing.T) {
				server := kdcfixture.Start(t, func(_ string, b []byte) []byte {
					var req messages.ASReq
					if err := req.Unmarshal(b); err != nil {
						t.Error(err)
						return nil
					}
					now := time.Now().UTC()
					part := messages.EncKDCRepPart{Key: key, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), SRealm: "NFS.TEST", SName: req.ReqBody.SName}
					rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 11, CRealm: "NFS.TEST", CName: req.ReqBody.CName, Ticket: messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: req.ReqBody.SName, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("opaque synthetic TGT")}}}}
					switch scenario {
					case "ticket-realm":
						rep.Ticket.Realm = "OTHER.TEST"
					case "ticket-service":
						rep.Ticket.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
					case "empty-ticket-name":
						rep.Ticket.SName = types.PrincipalName{}
					case "empty-component":
						rep.Ticket.SName = types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", ""}}
					case "client-name":
						rep.CName = types.NewPrincipalName(1, "bob")
					case "client-realm":
						rep.CRealm = "OTHER.TEST"
					case "encrypted-realm":
						part.SRealm = "OTHER.TEST"
					case "encrypted-name":
						part.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
					case "nonce":
						part.Nonce++
					}
					plain, err := part.Marshal()
					if err != nil {
						t.Error(err)
						return nil
					}
					rep.EncPart, err = crypto.GetEncryptedData(plain, key, keyusage.AS_REP_ENCPART, 1)
					if err != nil {
						t.Error(err)
						return nil
					}
					if scenario == "ciphertext" {
						rep.EncPart.Cipher[len(rep.EncPart.Cipher)-1] ^= 1
					}
					wire, err := rep.Marshal()
					if err != nil {
						t.Error(err)
						return nil
					}
					return wire
				})
				cl := asIdentityClient(t, kt, network, server.Address)
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("AS reply panicked: %v", p)
					}
				}()
				err := cl.Login()
				if scenario == "valid" {
					if err != nil {
						t.Fatal(err)
					}
					if s, ok := cl.sessions.get("NFS.TEST"); !ok || s.tgt.Realm != "NFS.TEST" {
						t.Fatal("valid home TGT not saved")
					}
				} else {
					if err == nil {
						t.Fatal("invalid AS reply accepted")
					}
					if len(cl.sessions.Entries) != 0 || len(cl.cache.Entries) != 0 {
						t.Fatal("invalid AS reply entered credential state")
					}
				}
				if server.TCP.Load()+server.UDP.Load() != 1 {
					t.Fatal("unexpected request after AS reply")
				}
			})
		}
	}
}

func TestASClientReferralRejected(t *testing.T) {
	kt, _ := asIdentityKeytab(t)
	for _, network := range []string{"tcp", "udp"} {
		for _, target := range []string{"OTHER.TEST", "NFS.TEST", "", "UNCONFIGURED.TEST"} {
			t.Run(network+"/"+target, func(t *testing.T) {
				e := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/NFS.TEST"), "NFS.TEST", errorcode.KDC_ERR_WRONG_REALM, "synthetic referral")
				e.CRealm, e.CName = target, types.NewPrincipalName(1, "must-not-replace-alice")
				wire, err := e.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				first := kdcfixture.Start(t, func(string, []byte) []byte { return wire })
				other := kdcfixture.Start(t, func(string, []byte) []byte { return wire })
				cl := asIdentityClient(t, kt, network, first.Address, other.Address)
				err = cl.Login()
				if err == nil || !strings.Contains(err.Error(), "AS client referral") || !strings.Contains(err.Error(), "canonical") {
					t.Fatalf("missing explicit referral diagnostic: %v", err)
				}
				if first.TCP.Load()+first.UDP.Load() != 1 || other.TCP.Load()+other.UDP.Load() != 0 {
					t.Fatal("AS client referral triggered another request")
				}
				if cl.Credentials.UserName() != "alice" || cl.Credentials.Realm() != "NFS.TEST" || len(cl.sessions.Entries) != 0 {
					t.Fatal("AS client referral changed identity/state")
				}
			})
		}
	}
}

func TestASMalformedPreauth(t *testing.T) {
	kt, _ := asIdentityKeytab(t)
	for _, network := range []string{"tcp", "udp"} {
		for _, paType := range []int32{patype.PA_ETYPE_INFO, patype.PA_ETYPE_INFO2} {
			t.Run(network+"/"+fmt.Sprint(paType), func(t *testing.T) {
				e := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/NFS.TEST"), "NFS.TEST", errorcode.KDC_ERR_PREAUTH_REQUIRED, "synthetic empty etype list")
				var err error
				e.EData, err = asn1.Marshal(types.PADataSequence{{PADataType: paType, PADataValue: []byte{0x30, 0}}})
				if err != nil {
					t.Fatal(err)
				}
				wire, err := e.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				server := kdcfixture.Start(t, func(string, []byte) []byte { return wire })
				cl := asIdentityClient(t, kt, network, server.Address)
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("malformed preauth panicked: %v", p)
					}
				}()
				if err := cl.Login(); err == nil || !strings.Contains(err.Error(), "empty ETYPE-INFO") {
					t.Fatalf("malformed preauth diagnostic: %v", err)
				}
				if server.TCP.Load()+server.UDP.Load() != 1 || len(cl.sessions.Entries) != 0 {
					t.Fatal("malformed preauth sent another request or saved state")
				}
			})
		}
	}
}

func TestASClientReferralAfterPreauthRejected(t *testing.T) {
	kt, _ := asIdentityKeytab(t)
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			challenge := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/NFS.TEST"), "NFS.TEST", errorcode.KDC_ERR_PREAUTH_REQUIRED, "synthetic preauth challenge")
			info, err := asn1.Marshal(types.ETypeInfo2{{EType: 18}})
			if err != nil {
				t.Fatal(err)
			}
			challenge.EData, err = asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
			if err != nil {
				t.Fatal(err)
			}
			challengeWire, err := challenge.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			referral := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/NFS.TEST"), "NFS.TEST", errorcode.KDC_ERR_WRONG_REALM, "synthetic referral after challenge")
			referral.CRealm = "OTHER.TEST"
			referralWire, err := referral.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			first := kdcfixture.Start(t, func(_ string, wire []byte) []byte {
				if calls.Add(1) == 1 {
					return challengeWire
				}
				var req messages.ASReq
				if err := req.Unmarshal(wire); err != nil {
					t.Error(err)
					return nil
				}
				found := false
				for _, pa := range req.PAData {
					found = found || pa.PADataType == patype.PA_ENC_TIMESTAMP
				}
				if !found {
					t.Error("retry omitted encrypted preauthentication timestamp")
				}
				return referralWire
			})
			other := kdcfixture.Start(t, func(string, []byte) []byte { return referralWire })
			cl := asIdentityClient(t, kt, network, first.Address, other.Address)
			if err := cl.Login(); err == nil || !strings.Contains(err.Error(), "AS client referral") {
				t.Fatalf("missing explicit post-preauth referral diagnostic: %v", err)
			}
			if calls.Load() != 2 || other.TCP.Load()+other.UDP.Load() != 0 {
				t.Fatal("post-preauth referral contacted another realm or retried")
			}
			if cl.Credentials.Realm() != "NFS.TEST" || cl.Credentials.UserName() != "alice" || len(cl.sessions.Entries) != 0 || len(cl.cache.Entries) != 0 {
				t.Fatal("post-preauth referral changed identity/state")
			}
		})
	}
}
