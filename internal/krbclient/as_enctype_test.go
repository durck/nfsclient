package client

import (
	"slices"
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
	"nfs-viewer/internal/testutil/kdcfixture"
)

func enctypeHint(t *testing.T, kind int32, enctypes ...int32) types.PAData {
	t.Helper()
	var value []byte
	var err error
	if kind == patype.PA_ETYPE_INFO2 {
		var entries types.ETypeInfo2
		for _, id := range enctypes {
			entries = append(entries, types.ETypeInfo2Entry{EType: id, Salt: "info2-salt", S2KParams: []byte{0, 0, 0, 1}})
		}
		value, err = asn1.Marshal(entries)
	} else {
		var entries types.ETypeInfo
		for _, id := range enctypes {
			entries = append(entries, types.ETypeInfoEntry{EType: id, Salt: []byte("info-salt")})
		}
		value, err = asn1.Marshal(entries)
	}
	if err != nil {
		t.Fatal(err)
	}
	return types.PAData{PADataType: kind, PADataValue: value}
}

func enctypeChallenge(t *testing.T, hints ...types.PAData) *messages.KRBError {
	t.Helper()
	errReply := messages.NewKRBError(types.NewPrincipalName(2, "krbtgt/NFS.TEST"), "NFS.TEST", errorcode.KDC_ERR_PREAUTH_REQUIRED, "synthetic challenge")
	var err error
	errReply.EData, err = asn1.Marshal(types.PADataSequence(hints))
	if err != nil {
		t.Fatal(err)
	}
	return &errReply
}

func TestASPreauthenticationEnctypeSelection(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		keys, requested, permitted []int32
		hints                      []types.PAData
		previous, want             int32
	}{
		{name: "available-second-key", keys: []int32{17}, requested: []int32{18, 17}, permitted: []int32{18, 17}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO2, 18, 17)}, want: 17},
		{name: "client-preference", keys: []int32{18, 17}, requested: []int32{18, 17}, permitted: []int32{18, 17}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO2, 17, 18)}, want: 18},
		{name: "forbidden-hint", keys: []int32{18, 23}, requested: []int32{18}, permitted: []int32{18}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO2, 23)}},
		{name: "not-requested", keys: []int32{18, 17}, requested: []int32{18}, permitted: []int32{18, 17}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO2, 17)}},
		{name: "not-permitted", keys: []int32{18, 23}, requested: []int32{23, 18}, permitted: []int32{18}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO2, 23)}},
		{name: "info2-first", keys: []int32{18, 17}, requested: []int32{18, 17}, permitted: []int32{18, 17}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO2, 17), enctypeHint(t, patype.PA_ETYPE_INFO, 18)}, want: 17},
		{name: "info2-last", keys: []int32{18, 17}, requested: []int32{18, 17}, permitted: []int32{18, 17}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO, 18), enctypeHint(t, patype.PA_ETYPE_INFO2, 17)}, want: 17},
		{name: "legacy-info", keys: []int32{18}, requested: []int32{18}, permitted: []int32{18}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO, 18)}, want: 18},
		{name: "info2-disjoint-no-fallback", keys: []int32{18, 23}, requested: []int32{18}, permitted: []int32{18}, hints: []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO2, 23), enctypeHint(t, patype.PA_ETYPE_INFO, 18)}},
		{name: "info2-malformed-no-fallback", keys: []int32{18}, requested: []int32{18}, permitted: []int32{18}, hints: []types.PAData{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: []byte{0}}, enctypeHint(t, patype.PA_ETYPE_INFO, 18)}},
		{name: "preemptive-no-preferred-list", keys: []int32{17}, requested: []int32{18, 17}, permitted: []int32{18, 17}, want: 17},
		{name: "renewed-policy", keys: []int32{18, 23}, requested: []int32{18}, permitted: []int32{18}, previous: 23, want: 18},
		{name: "renewed-keytab", keys: []int32{17}, requested: []int32{18, 17}, permitted: []int32{18, 17}, previous: 18, want: 17},
		{name: "no-permitted-key", keys: []int32{17}, requested: []int32{18}, permitted: []int32{18}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kt := keytab.New()
			for _, id := range tc.keys {
				if err := kt.AddEntry("alice", "NFS.TEST", "synthetic-enctype-test-only", time.Now(), 1, id); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.New()
			cfg.LibDefaults.DefaultTktEnctypeIDs, cfg.LibDefaults.PermittedEnctypeIDs = tc.requested, tc.permitted
			cfg.LibDefaults.PreferredPreauthTypes = nil
			cl := NewWithKeytab("alice", "NFS.TEST", kt, cfg, AssumePreAuthentication(true), DisablePAFXFAST(true))
			defer cl.Destroy()
			cl.settings.preAuthEType = tc.previous
			req, err := messages.NewASReqForTGT("NFS.TEST", cfg, types.NewPrincipalName(1, "alice"))
			if err != nil {
				t.Fatal(err)
			}
			var challenge *messages.KRBError
			if tc.hints != nil {
				challenge = enctypeChallenge(t, tc.hints...)
			}
			err = setPAData(cl, challenge, &req)
			if (err == nil) != (tc.want != 0) {
				t.Fatalf("preauthentication result differs from policy: %v", err)
			}
			var found bool
			for _, pa := range req.PAData {
				if pa.PADataType != patype.PA_ENC_TIMESTAMP {
					continue
				}
				found = true
				var encrypted types.EncryptedData
				if _, err := asn1.Unmarshal(pa.PADataValue, &encrypted); err != nil {
					t.Fatal(err)
				}
				if encrypted.EType != tc.want {
					t.Fatalf("timestamp enctype = %d, want %d", encrypted.EType, tc.want)
				}
			}
			if found != (tc.want != 0) {
				t.Fatal("timestamp presence differs from policy")
			}
			if err == nil {
				for _, id := range req.ReqBody.EType {
					if !slices.Contains(tc.keys, id) || !slices.Contains(tc.permitted, id) {
						t.Fatal("advertised unavailable or forbidden enctype")
					}
				}
			}
		})
	}
}

func TestASPasswordPreauthenticationUsesSelectedHint(t *testing.T) {
	for _, code := range []int32{errorcode.KDC_ERR_PREAUTH_REQUIRED, errorcode.KDC_ERR_PREAUTH_FAILED} {
		for _, info2First := range []bool{false, true} {
			cfg := config.New()
			cfg.LibDefaults.DefaultTktEnctypeIDs, cfg.LibDefaults.PermittedEnctypeIDs = []int32{17}, []int32{17}
			cl := NewWithPassword("alice", "NFS.TEST", "synthetic-password-test-only", cfg, AssumePreAuthentication(true), DisablePAFXFAST(true))
			defer cl.Destroy()
			hints := []types.PAData{enctypeHint(t, patype.PA_ETYPE_INFO, 17), enctypeHint(t, patype.PA_ETYPE_INFO2, 18, 17)}
			if info2First {
				slices.Reverse(hints)
			}
			req, err := messages.NewASReqForTGT("NFS.TEST", cfg, types.NewPrincipalName(1, "alice"))
			if err != nil {
				t.Fatal(err)
			}
			challenge := enctypeChallenge(t, hints...)
			challenge.ErrorCode = code
			if err := setPAData(cl, challenge, &req); err != nil {
				t.Fatal(err)
			}
			key, _, err := crypto.GetKeyFromPassword("synthetic-password-test-only", cl.Credentials.CName(), "NFS.TEST", 17, types.PADataSequence{enctypeHint(t, patype.PA_ETYPE_INFO2, 17)})
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, pa := range req.PAData {
				if pa.PADataType == patype.PA_ENC_TIMESTAMP {
					found = true
					var encrypted types.EncryptedData
					if _, err := asn1.Unmarshal(pa.PADataValue, &encrypted); err != nil {
						t.Fatal(err)
					}
					if _, err := crypto.DecryptEncPart(encrypted, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP); err != nil {
						t.Fatal("timestamp did not use selected INFO2 key and salt")
					}
				}
			}
			if !found {
				t.Fatal("missing encrypted timestamp")
			}
		}
	}
}

func TestASPreauthenticationNeverSendsForbiddenEnctype(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			kt := keytab.New()
			for _, id := range []int32{18, 23} {
				if err := kt.AddEntry("alice", "NFS.TEST", "synthetic-enctype-test-only", time.Now(), 1, id); err != nil {
					t.Fatal(err)
				}
			}
			var requests atomic.Int32
			peer := kdcfixture.Start(t, func(_ string, wire []byte) []byte {
				requests.Add(1)
				var req messages.ASReq
				if err := req.Unmarshal(wire); err != nil {
					t.Error(err)
					return nil
				}
				if !slices.Equal(req.ReqBody.EType, []int32{18}) {
					t.Error("AS request advertised forbidden encryption type")
				}
				for _, pa := range req.PAData {
					if pa.PADataType == patype.PA_ENC_TIMESTAMP {
						t.Error("sent timestamp after disjoint challenge")
					}
				}
				challenge := enctypeChallenge(t, enctypeHint(t, patype.PA_ETYPE_INFO2, 23))
				wire, err := challenge.Marshal()
				if err != nil {
					t.Error(err)
					return nil
				}
				return wire
			})
			cl := asIdentityClient(t, kt, network, peer.Address)
			cl.Config.LibDefaults.DefaultTktEnctypeIDs, cl.Config.LibDefaults.PermittedEnctypeIDs = []int32{18}, []int32{18}
			if err := cl.Login(); err == nil {
				t.Fatal("disjoint challenge authenticated")
			}
			if requests.Load() != 1 {
				t.Fatal("client retried after disjoint challenge")
			}
		})
	}
}
