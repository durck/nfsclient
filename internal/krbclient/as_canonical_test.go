package client

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfsclient/internal/testutil/kdcfixture"
)

func TestProtectedASCanonicalization(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, etid := range []int32{17, 18} {
			for _, mode := range []string{"valid", "no-fast", "preauth", "missing-flag", "missing-checksum", "duplicate-checksum", "malformed", "trailing", "wrong-usage", "wrong-checksum", "wrong-type", "client", "realm", "nonce", "ticket-realm", "ticket-name", "encrypted-name", "ciphertext", "expired", "future-start", "too-long", "request-modified"} {
				t.Run(network+"/"+fmt.Sprint(etid)+"/"+mode, func(t *testing.T) {
					kt := keytab.New()
					if err := kt.AddEntry("alice", "NFS.TEST", "synthetic-canonical-test-only", time.Now(), 1, etid); err != nil {
						t.Fatal(err)
					}
					key, _, err := kt.GetEncryptionKey(types.NewPrincipalName(1, "alice"), "NFS.TEST", 1, etid)
					if err != nil {
						t.Fatal(err)
					}
					var calls atomic.Int32
					server := kdcfixture.Start(t, func(_ string, wire []byte) []byte {
						call := calls.Add(1)
						var req messages.ASReq
						if err := req.Unmarshal(wire); err != nil {
							t.Error(err)
							return nil
						}
						if req.ReqBody.CName.PrincipalNameString() != "alias" || req.ReqBody.Realm != "NFS.TEST" || !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Canonicalize) {
							t.Error("alias/options/realm not emitted")
							return nil
						}
						count := 0
						for _, pa := range req.PAData {
							if pa.PADataType == patype.PA_REQ_ENC_PA_REP {
								count++
								if len(pa.PADataValue) != 0 {
									t.Error("nonempty protection request")
								}
							}
						}
						if count != 1 {
							t.Error("duplicate/missing protection request")
							return nil
						}
						if mode == "preauth" && call == 1 {
							challenge := messages.NewKRBError(req.ReqBody.SName, "NFS.TEST", errorcode.KDC_ERR_PREAUTH_REQUIRED, "synthetic challenge")
							info, _ := asn1.Marshal(types.ETypeInfo2{{EType: etid}})
							challenge.EData, _ = asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
							b, _ := challenge.Marshal()
							return b
						}
						if mode == "preauth" && !req.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
							t.Error("retry omitted preauthentication")
							return nil
						}
						now := time.Now().UTC()
						part := messages.EncKDCRepPart{Key: key, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), SRealm: "NFS.TEST", SName: req.ReqBody.SName}
						types.SetFlag(&part.Flags, flags.EncPARep)
						et, _ := crypto.GetEtype(etid)
						usage := uint32(keyusage.KEY_USAGE_AS_REQ)
						if mode == "wrong-usage" {
							usage++
						}
						input := bytes.Clone(wire)
						if mode == "request-modified" {
							input[len(input)-1] ^= 1
						}
						checksum, _ := et.GetChecksumHash(key.KeyValue, input, usage)
						clear(input)
						cs := types.PAReqEncPARep{ChksumType: et.GetHashID(), Chksum: checksum}
						if mode == "wrong-type" {
							cs.ChksumType = 7
						}
						if mode == "wrong-checksum" {
							cs.Chksum[0] ^= 1
						}
						checksumWire, _ := asn1.Marshal(cs)
						if mode == "malformed" {
							checksumWire = []byte{0}
						}
						if mode == "trailing" {
							checksumWire = append(checksumWire, 0)
						}
						part.EncPAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: checksumWire}, {PADataType: patype.PA_FX_FAST}}
						if mode == "no-fast" {
							part.EncPAData = part.EncPAData[:1]
						}
						if mode == "missing-checksum" {
							part.EncPAData = part.EncPAData[1:]
						}
						if mode == "duplicate-checksum" {
							part.EncPAData = append(part.EncPAData, part.EncPAData[0])
						}
						if mode == "missing-flag" {
							part.Flags = types.NewKrbFlags()
						}
						rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 11, CRealm: "NFS.TEST", CName: types.NewPrincipalName(1, "alice"), Ticket: messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: req.ReqBody.SName, EncPart: types.EncryptedData{EType: etid, Cipher: []byte("opaque synthetic TGT")}}}}
						switch mode {
						case "client":
							rep.CName = types.NewPrincipalName(1, "bob")
						case "realm":
							rep.CRealm = "OTHER.TEST"
						case "nonce":
							part.Nonce++
						case "ticket-realm":
							rep.Ticket.Realm = "OTHER.TEST"
						case "ticket-name":
							rep.Ticket.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
						case "encrypted-name":
							part.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
						case "expired":
							part.EndTime = now.Add(-time.Second)
						case "future-start":
							part.StartTime = now.Add(time.Hour)
						case "too-long":
							part.EndTime = req.ReqBody.Till.Add(time.Hour)
						}
						plain, _ := part.Marshal()
						encrypted, encryptErr := crypto.GetEncryptedData(plain, key, keyusage.AS_REP_ENCPART, 1)
						rep.EncPart = encrypted
						clear(plain)
						if encryptErr != nil {
							t.Error(encryptErr)
							return nil
						}
						if mode == "ciphertext" {
							rep.EncPart.Cipher[len(rep.EncPart.Cipher)-1] ^= 1
						}
						b, err := rep.Marshal()
						if err != nil {
							t.Error(err)
							return nil
						}
						return b
					})
					cl := asIdentityClient(t, kt, network, server.Address)
					cl.settings.asAlias = "alias@NFS.TEST"
					cl.settings.preAuthEType = etid
					err = cl.Login()
					valid := mode == "valid" || mode == "no-fast" || mode == "preauth"
					if (err == nil) != valid {
						t.Fatal("incorrect canonicalization result", err)
					}
					if cl.Credentials.UserName() != "alice" || cl.Credentials.Realm() != "NFS.TEST" {
						t.Fatal("selected identity mutated")
					}
					if valid {
						if _, ok := cl.sessions.get("NFS.TEST"); !ok {
							t.Fatal("verified TGT missing")
						}
					} else if len(cl.sessions.Entries) != 0 || len(cl.cache.Entries) != 0 {
						t.Fatal("invalid reply entered state")
					}
					want := int32(1)
					if mode == "preauth" {
						want = 2
					}
					if calls.Load() != want {
						t.Fatal("unexpected request/retry")
					}
				})
			}
		}
	}
}

func TestProtectedASAliasBounds(t *testing.T) {
	for _, alias := range []string{"", "alias", "alias@OTHER.TEST", "@NFS.TEST", "a//b@NFS.TEST", "krbtgt/NFS.TEST@NFS.TEST", "a\x00@NFS.TEST", strings.Repeat("a", 257) + "@NFS.TEST"} {
		if _, err := ValidateASAlias(alias, "NFS.TEST"); err == nil {
			t.Fatal("bad alias accepted")
		}
	}
}
