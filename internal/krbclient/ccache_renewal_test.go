package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"nfs-viewer/internal/testutil/kdcfixture"
)

func renewalTestCache(t *testing.T) *credentials.CCache {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	c := &credentials.CCache{Version: 4}
	c.DefaultPrincipal.Realm = "NFS.TEST"
	c.DefaultPrincipal.PrincipalName = types.NewPrincipalName(1, "alice")
	e := &credentials.Credential{AuthTime: now.Add(-time.Hour), StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Minute), RenewTill: now.Add(2 * time.Hour), TicketFlags: types.NewKrbFlags(), Key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x42}, 32)}}
	e.Client, e.Server = c.DefaultPrincipal, c.DefaultPrincipal
	e.Server.PrincipalName = types.NewPrincipalName(2, "krbtgt/NFS.TEST")
	types.SetFlag(&e.TicketFlags, flags.Renewable)
	ticket := messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: e.Server.PrincipalName, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic opaque original TGT")}}
	var err error
	e.Ticket, err = ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c.Credentials = []*credentials.Credential{e}
	return c
}

func TestCCacheRenewalVerifiedExchange(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, scenario := range []string{"valid", "valid-no-start", "client", "realm", "referral", "nonce", "auth-time", "no-extension", "beyond-renew", "renew-extended", "not-renewable", "invalid", "postdated", "short-key", "future-start", "future-start-skew", "start-before-auth", "cipher"} {
			t.Run(transport+"/"+scenario, func(t *testing.T) {
				cache := renewalTestCache(t)
				old := cache.Credentials[0]
				if scenario == "valid-no-start" {
					old.AuthTime = time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
					old.StartTime = old.AuthTime
				}
				before := bytes.Clone(old.Ticket)
				server := kdcfixture.Start(t, func(network string, b []byte) []byte {
					var req messages.TGSReq
					if err := req.Unmarshal(b); err != nil {
						t.Error(err)
						return nil
					}
					if network != transport || !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renew) || !req.ReqBody.SName.Equal(old.Server.PrincipalName) {
						t.Error("wrong renewal request")
					}
					p := messages.EncKDCRepPart{Key: types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x63}, 32)}, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: old.AuthTime, StartTime: time.Now().UTC().Truncate(time.Second), EndTime: old.EndTime.Add(time.Hour), RenewTill: old.RenewTill, SRealm: "NFS.TEST", SName: old.Server.PrincipalName}
					types.SetFlag(&p.Flags, flags.Renewable)
					rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 13, CRealm: "NFS.TEST", CName: cache.DefaultPrincipal.PrincipalName, Ticket: messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: old.Server.PrincipalName, EncPart: types.EncryptedData{EType: 18, Cipher: []byte("synthetic renewed TGT")}}}}
					switch scenario {
					case "client":
						rep.CName = types.NewPrincipalName(1, "mallory")
					case "realm":
						rep.CRealm = "OTHER.TEST"
					case "referral":
						p.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
						rep.Ticket.SName = p.SName
					case "nonce":
						p.Nonce++
					case "auth-time":
						p.AuthTime = p.AuthTime.Add(time.Second)
					case "no-extension":
						p.EndTime = old.EndTime
					case "beyond-renew":
						p.EndTime = old.RenewTill.Add(time.Second)
					case "renew-extended":
						p.RenewTill = old.RenewTill.Add(time.Second)
					case "not-renewable":
						p.Flags = types.NewKrbFlags()
					case "invalid":
						types.SetFlag(&p.Flags, flags.Invalid)
					case "postdated":
						types.SetFlag(&p.Flags, flags.PostDated)
					case "short-key":
						p.Key.KeyValue = p.Key.KeyValue[:4]
					case "valid-no-start":
						p.StartTime = time.Time{}
					case "future-start":
						p.StartTime = time.Now().Add(time.Hour)
					case "future-start-skew":
						p.StartTime = time.Now().Add(30 * time.Second)
					case "start-before-auth":
						p.StartTime = p.AuthTime.Add(-time.Second)
					}
					plain, err := p.Marshal()
					if err != nil {
						t.Error(err)
						return nil
					}
					rep.EncPart, err = crypto.GetEncryptedData(plain, old.Key, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
					if err != nil {
						t.Error(err)
						return nil
					}
					if scenario == "cipher" {
						rep.EncPart.Cipher[0] ^= 1
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
				if transport == "udp" {
					cfg.LibDefaults.UDPPreferenceLimit = 65535
				}
				cfg.Realms = []config.Realm{{Realm: "NFS.TEST", KDC: []string{server.Address}}}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				next, err := RenewCCacheTGT(cache, cfg, NetworkContext(ctx))
				if scenario == "valid" || scenario == "valid-no-start" {
					if err != nil {
						t.Fatal(err)
					}
					if !next.EndTime.After(old.EndTime) || bytes.Equal(next.Key.KeyValue, old.Key.KeyValue) {
						t.Fatal("renewal not published")
					}
				} else if err == nil || next != nil {
					t.Fatal("invalid renewal accepted")
				}
				if server.TCP.Load()+server.UDP.Load() != 1 {
					t.Fatal("renewal followed referral or retried semantic error")
				}
				if !bytes.Equal(old.Ticket, before) {
					t.Fatal("input cache changed")
				}
			})
		}
	}
}

func TestCCacheRenewalLocalRefusals(t *testing.T) {
	for _, scenario := range []string{"expired", "postdated", "nonrenewable", "exhausted"} {
		t.Run(scenario, func(t *testing.T) {
			cache := renewalTestCache(t)
			e := cache.Credentials[0]
			switch scenario {
			case "expired":
				e.EndTime = time.Now().Add(-time.Second)
			case "postdated":
				e.StartTime = time.Now().Add(time.Hour)
			case "nonrenewable":
				e.TicketFlags = types.NewKrbFlags()
			case "exhausted":
				e.RenewTill = e.EndTime
			}
			if next, err := RenewCCacheTGT(cache, config.New()); err == nil || next != nil {
				t.Fatal("invalid renewal was attempted")
			}
		})
	}
}
