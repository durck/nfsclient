package client

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfsclient/internal/testutil/kdcfixture"
)

// Encrypt the KDC reply with an explicitly synthetic session key. This exercises
// the real decoding/verification path; it does not model a production KDC.
func TestTGSReplyIdentity(t *testing.T) {
	for _, scenario := range []string{"valid-cross-realm", "valid-referral", "different-service", "ticket-name", "ticket-realm", "client-realm", "empty-name", "empty-component", "malformed-referral", "self-referral", "referral-loop"} {
		t.Run(scenario, func(t *testing.T) {
			key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}
			server := kdcfixture.Start(t, func(_ string, b []byte) []byte {
				var req messages.TGSReq
				if err := req.Unmarshal(b); err != nil {
					t.Error(err)
					return nil
				}
				authenticators := 0
				for _, pa := range req.PAData {
					if pa.PADataType != patype.PA_TGS_REQ {
						continue
					}
					authenticators++
					var ap messages.APReq
					if err := ap.Unmarshal(pa.PADataValue); err != nil {
						t.Error(err)
						return nil
					}
					if err := ap.DecryptAuthenticator(key); err != nil {
						t.Error(err)
						return nil
					}
					if ap.Authenticator.CRealm != "CLIENT.TEST" || !ap.Authenticator.CName.Equal(types.NewPrincipalName(1, "alice")) {
						t.Errorf("authenticator identity changed at %s: %s@%s", req.ReqBody.Realm, ap.Authenticator.CName.PrincipalNameString(), ap.Authenticator.CRealm)
					}
					body, err := req.ReqBody.Marshal()
					if err != nil {
						t.Error(err)
						return nil
					}
					et, err := crypto.GetChksumEtype(ap.Authenticator.Cksum.CksumType)
					if err != nil || !et.VerifyChecksum(key.KeyValue, body, ap.Authenticator.Cksum.Checksum, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM) {
						t.Errorf("invalid request-body checksum: %v", err)
					}
				}
				if authenticators != 1 {
					t.Errorf("PA-TGS-REQ count = %d, want one", authenticators)
				}
				now := time.Now().UTC()
				part := messages.EncKDCRepPart{Key: key, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), SRealm: "NFS.TEST", SName: req.ReqBody.SName}
				rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 13, CRealm: "CLIENT.TEST", CName: req.ReqBody.CName, Ticket: messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: req.ReqBody.SName, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("opaque synthetic service ticket")}}}}
				part.SRealm, rep.Ticket.Realm = req.ReqBody.Realm, req.ReqBody.Realm
				switch scenario {
				case "valid-referral", "referral-loop":
					if scenario == "referral-loop" || req.ReqBody.Realm == "NFS.TEST" {
						next := "NEXT.TEST"
						if req.ReqBody.Realm == next {
							next = "NFS.TEST"
						}
						part.SName = types.NewPrincipalName(2, "krbtgt/"+next)
						rep.Ticket.SName = part.SName
					}
				case "different-service":
					part.SName = types.NewPrincipalName(2, "nfs/other.nfs.test")
					rep.Ticket.SName = part.SName
				case "ticket-name":
					rep.Ticket.SName = types.NewPrincipalName(2, "nfs/other.nfs.test")
				case "client-realm":
					rep.CRealm = "IMPOSTOR.TEST"
				case "ticket-realm":
					rep.Ticket.Realm = "IMPOSTOR.TEST"
				case "empty-name":
					part.SName = types.PrincipalName{}
					rep.Ticket.SName = part.SName
				case "empty-component":
					part.SName = types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", ""}}
					rep.Ticket.SName = part.SName
				case "malformed-referral":
					part.SName = types.NewPrincipalName(2, "krbtgt")
					rep.Ticket.SName = part.SName
				case "self-referral":
					part.SName = types.NewPrincipalName(2, "krbtgt/NFS.TEST")
					rep.Ticket.SName = part.SName
				}
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
			cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{server.Address}}, {Realm: "NEXT.TEST", KDC: []string{server.Address}}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			cl := NewWithPassword("alice", "CLIENT.TEST", "synthetic-test-only", cfg, NetworkContext(ctx))
			defer cl.Destroy()
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("malformed reply panicked: %v", p)
				}
			}()
			spn := types.NewPrincipalName(2, "nfs/server.nfs.test")
			tgt := messages.Ticket{TktVNO: 5, Realm: "CLIENT.TEST", SName: types.NewPrincipalName(2, "krbtgt/NFS.TEST"), EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic TGT")}}
			_, _, err := cl.TGSREQGenerateAndExchange(spn, "NFS.TEST", tgt, key, false)
			if scenario == "valid-cross-realm" || scenario == "valid-referral" {
				if err != nil {
					t.Fatal(err)
				}
				if _, _, ok := cl.GetCachedTicket("nfs/server.nfs.test"); !ok {
					t.Fatal("valid ticket was not cached")
				}
				return
			}
			if scenario == "referral-loop" {
				if err == nil || !strings.Contains(err.Error(), "maximum number of referrals") || server.TCP.Load() != 6 {
					t.Fatalf("referral loop was not bounded at five followed referrals: %v (%d calls)", err, server.TCP.Load())
				}
				return
			}
			if err == nil || !(strings.Contains(err.Error(), "TGS reply identity") || scenario == "ticket-realm" && strings.Contains(err.Error(), "realm in response ticket")) {
				t.Fatalf("unbound identity accepted or rejected too late: %v", err)
			}
			if server.TCP.Load() != 1 {
				t.Fatal("invalid identity followed as a referral")
			}
			if len(cl.cache.Entries) != 0 {
				t.Fatal("invalid identity entered service cache")
			}
		})
	}
}
