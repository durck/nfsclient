package client

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfs-viewer/internal/testutil/kdcfixture"
)

func enterpriseTestReply(t *testing.T, wire []byte, key types.EncryptionKey, mode string) []byte {
	t.Helper()
	var req messages.ASReq
	if err := req.Unmarshal(wire); err != nil {
		t.Error(err)
		return nil
	}
	now := time.Now().UTC()
	part := messages.EncKDCRepPart{Key: key, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), SRealm: "NFS.TEST", SName: types.NewPrincipalName(2, "krbtgt/NFS.TEST")}
	types.SetFlag(&part.Flags, flags.EncPARep)
	et, _ := crypto.GetEtype(key.KeyType)
	sum, _ := et.GetChecksumHash(key.KeyValue, wire, keyusage.KEY_USAGE_AS_REQ)
	if mode == "checksum" {
		sum[0] ^= 1
	}
	b, _ := asn1.Marshal(types.PAReqEncPARep{ChksumType: et.GetHashID(), Chksum: sum})
	part.EncPAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: b}}
	if mode == "missing-protection" {
		part.EncPAData = nil
		part.Flags = types.NewKrbFlags()
	}
	rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 11, CRealm: "NFS.TEST", CName: types.NewPrincipalName(1, "alice"), Ticket: messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: part.SName, EncPart: types.EncryptedData{EType: key.KeyType, Cipher: []byte("opaque synthetic enterprise TGT")}}}}
	if mode == "principal" {
		rep.CName = types.NewPrincipalName(1, "bob")
	}
	if mode == "nonce" {
		part.Nonce++
	}
	plain, err := part.Marshal()
	if err != nil {
		t.Error(err)
		return nil
	}
	rep.EncPart, err = crypto.GetEncryptedData(plain, key, keyusage.AS_REP_ENCPART, 1)
	clear(plain)
	if err != nil {
		t.Error(err)
		return nil
	}
	b, err = rep.Marshal()
	if err != nil {
		t.Error(err)
		return nil
	}
	return b
}

func TestEnterpriseASRouting(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, etid := range []int32{17, 18} {
			for _, mode := range []string{"direct", "one-hop", "two-hop", "five-hops", "poison-name", "preauth", "unapproved", "cycle", "empty-referral", "intermediate-preauth", "intermediate-reply", "home-redirect", "checksum", "missing-protection", "principal", "nonce", "denied", "missing-kdc"} {
				t.Run(network+"/"+fmt.Sprint(etid)+"/"+mode, func(t *testing.T) {
					kt := keytab.New()
					if err := kt.AddEntry("alice", "NFS.TEST", "synthetic-enterprise-test-only", time.Now(), 1, etid); err != nil {
						t.Fatal(err)
					}
					key, _, err := kt.GetEncryptionKey(types.NewPrincipalName(1, "alice"), "NFS.TEST", 1, etid)
					if err != nil {
						t.Fatal(err)
					}
					path := []string{"MAP0.TEST", "NFS.TEST"}
					if mode == "direct" {
						path = path[1:]
					}
					if mode == "two-hop" || mode == "cycle" {
						path = []string{"MAP0.TEST", "MAP1.TEST", "NFS.TEST"}
					}
					if mode == "five-hops" {
						path = []string{"MAP0.TEST", "MAP1.TEST", "MAP2.TEST", "MAP3.TEST", "MAP4.TEST", "NFS.TEST"}
					}
					cfg := config.New()
					cfg.LibDefaults.UDPPreferenceLimit = 1
					if network == "udp" {
						cfg.LibDefaults.UDPPreferenceLimit = 65535
					}
					counts := make([]atomic.Int32, len(path))
					peers := make([]*kdcfixture.Server, 0)
					for i, realm := range path {
						index := i
						selected := realm
						peer := kdcfixture.Start(t, func(_ string, wire []byte) []byte {
							call := counts[index].Add(1)
							var req messages.ASReq
							if err := req.Unmarshal(wire); err != nil {
								t.Error(err)
								return nil
							}
							if req.ReqBody.Realm != selected || req.ReqBody.CName.NameType != nametype.KRB_NT_ENTERPRISE || len(req.ReqBody.CName.NameString) != 1 || req.ReqBody.CName.NameString[0] != "alias@users.test" || !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Canonicalize) {
								t.Error("enterprise request identity/realm changed")
								return nil
							}
							if selected != "NFS.TEST" && req.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
								t.Error("credentials sent to intermediate realm")
								return nil
							}
							if mode == "intermediate-reply" && selected != "NFS.TEST" {
								return enterpriseTestReply(t, wire, key, "valid")
							}
							if selected == "NFS.TEST" && mode != "home-redirect" && mode != "denied" && !(mode == "preauth" && call == 1) {
								return enterpriseTestReply(t, wire, key, mode)
							}
							code := int32(errorcode.KDC_ERR_WRONG_REALM)
							next := "NFS.TEST"
							if index+1 < len(path) {
								next = path[index+1]
							}
							if mode == "unapproved" {
								next = "EVIL.TEST"
							}
							if mode == "cycle" && index == 1 {
								next = path[0]
							}
							if mode == "empty-referral" {
								next = ""
							}
							if mode == "home-redirect" && selected == "NFS.TEST" {
								next = path[0]
							}
							if mode == "denied" {
								code = errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN
							}
							if mode == "intermediate-preauth" || mode == "preauth" && selected == "NFS.TEST" {
								code = errorcode.KDC_ERR_PREAUTH_REQUIRED
							}
							ke := messages.NewKRBError(req.ReqBody.SName, selected, code, "synthetic routing response")
							ke.CRealm = next
							ke.CName = types.NewPrincipalName(1, "poisoned-name")
							if code == errorcode.KDC_ERR_PREAUTH_REQUIRED {
								info, _ := asn1.Marshal(types.ETypeInfo2{{EType: etid}})
								ke.EData, _ = asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
							}
							b, err := ke.Marshal()
							if err != nil {
								t.Error(err)
								return nil
							}
							return b
						})
						cfg.Realms = append(cfg.Realms, config.Realm{Realm: realm, KDC: []string{peer.Address}})
					}
					_ = peers
					if mode == "missing-kdc" {
						cfg.Realms = cfg.Realms[:len(cfg.Realms)-1]
					}
					cl := NewWithKeytab("alice", "NFS.TEST", kt, cfg, DisablePAFXFAST(true), EnterpriseAS("alias@users.test", path[0], path))
					// Renewal has already negotiated preauth, but mapping KDCs must still
					// receive only lookup data. The explicit preauth case starts cold.
					cl.settings.assumePreAuthentication = mode != "preauth"
					cl.settings.preAuthEType = etid
					err = cl.Login()
					valid := mode == "direct" || mode == "one-hop" || mode == "two-hop" || mode == "five-hops" || mode == "poison-name" || mode == "preauth"
					if (err == nil) != valid {
						t.Fatal("incorrect enterprise routing result", err)
					}
					if cl.Credentials.UserName() != "alice" || cl.Credentials.Realm() != "NFS.TEST" {
						t.Fatal("routing mutated credentials")
					}
					if valid {
						if len(cl.sessions.Entries) != 1 {
							t.Fatal("verified home TGT missing")
						}
					} else if len(cl.sessions.Entries) != 0 || len(cl.cache.Entries) != 0 {
						t.Fatal("invalid routing entered state")
					}
					if mode == "missing-kdc" {
						for i := range counts {
							if counts[i].Load() != 0 {
								t.Fatal("unconfigured realm reached network")
							}
						}
					}
					if mode == "intermediate-preauth" || mode == "intermediate-reply" || mode == "unapproved" || mode == "empty-referral" || mode == "denied" {
						if counts[len(counts)-1].Load() != 0 {
							t.Fatal("unsafe routing reached home KDC")
						}
					}
					if valid {
						for i := range counts {
							want := int32(1)
							if mode == "preauth" && i == len(counts)-1 {
								want = 2
							}
							if counts[i].Load() != want {
								t.Fatal("unexpected AS retry", i, counts[i].Load())
							}
						}
					}
				})
			}
		}
	}
}

func TestEnterpriseASBounds(t *testing.T) {
	for _, tc := range []struct {
		upn, start, home string
		realms           []string
	}{
		{"", "NFS.TEST", "NFS.TEST", []string{"NFS.TEST"}}, {"a@b", "", "NFS.TEST", []string{"NFS.TEST"}}, {"a@b", "M.TEST", "NFS.TEST", []string{"M.TEST"}}, {"a@b", "NFS.TEST", "NFS.TEST", []string{"NFS.TEST", "NFS.TEST"}}, {"a@@b", "NFS.TEST", "NFS.TEST", []string{"NFS.TEST"}}, {"a@b", "NFS.TEST", "NFS.TEST", nil}, {strings.Repeat("a", 513) + "@b", "NFS.TEST", "NFS.TEST", []string{"NFS.TEST"}}, {"a@b", "A", "A", []string{"A", "B", "C", "D", "E", "F", "G"}},
	} {
		if err := ValidateEnterpriseAS(tc.upn, tc.start, tc.home, tc.realms); err == nil {
			t.Fatal("invalid enterprise selection accepted")
		}
	}
}
