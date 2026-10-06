package client

import (
	"errors"
	"slices"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/types"
)

// RenewCCacheTGT renews the selected home TGT without an AS login, referrals,
// mutation of the supplied cache, or publication of an unverified reply.
// RFC 4120 section 2.3 requires renewal before the old ticket expires.
func RenewCCacheTGT(cache *credentials.CCache, cfg *config.Config, settings ...func(*Settings)) (*credentials.Credential, error) {
	if cache == nil || cfg == nil {
		return nil, errors.New("TGT renewal needs explicit cache and configuration")
	}
	cl, err := NewFromCCache(cache, cfg, settings...)
	if cl != nil {
		defer cl.Destroy()
	}
	if err != nil {
		return nil, err
	}
	spn := types.NewPrincipalName(2, "krbtgt/"+cache.DefaultPrincipal.Realm)
	old, ok := cache.GetEntry(spn)
	if !ok || old.TicketFlags.BitLength != 32 || len(old.TicketFlags.Bytes) != 4 || types.IsFlagSet(&old.TicketFlags, flags.Invalid) || types.IsFlagSet(&old.TicketFlags, flags.PostDated) || !types.IsFlagSet(&old.TicketFlags, flags.Renewable) || !time.Now().Before(old.RenewTill) || !old.EndTime.Before(old.RenewTill) {
		return nil, errors.New("selected FILE TGT is not renewable within its remaining lifetime")
	}
	s, _ := cl.sessions.get(cache.DefaultPrincipal.Realm)
	_, ticket, key := s.tgtDetails()
	req, rep, err := cl.TGSREQGenerateAndExchange(spn, cache.DefaultPrincipal.Realm, ticket, key, true)
	if err != nil {
		return nil, err
	}
	p := rep.DecryptedEncPart
	if p.StartTime.IsZero() {
		p.StartTime = p.AuthTime
	}
	et, err := crypto.GetEtype(p.Key.KeyType)
	if err != nil || !slices.Contains(req.ReqBody.EType, p.Key.KeyType) || len(p.Key.KeyValue) != et.GetKeyByteSize() || p.Flags.BitLength != 32 || len(p.Flags.Bytes) != 4 || types.IsFlagSet(&p.Flags, flags.Invalid) || types.IsFlagSet(&p.Flags, flags.PostDated) {
		return nil, errors.New("TGT renewal returned an unusable session key or ticket flags")
	}
	if !rep.CName.Equal(cache.DefaultPrincipal.PrincipalName) || rep.CRealm != cache.DefaultPrincipal.Realm ||
		!rep.Ticket.SName.Equal(spn) || rep.Ticket.Realm != cache.DefaultPrincipal.Realm ||
		!p.AuthTime.Equal(old.AuthTime) || !p.EndTime.After(old.EndTime) || p.EndTime.After(old.RenewTill) ||
		p.StartTime.After(time.Now()) || p.StartTime.Before(p.AuthTime) || !p.StartTime.Before(p.EndTime) ||
		p.RenewTill.After(old.RenewTill) || !time.Now().Before(p.EndTime) ||
		!types.IsFlagSet(&p.Flags, flags.Renewable) || p.RenewTill.Before(p.EndTime) {
		return nil, errors.New("TGT renewal changed identity or violated authenticated lifetime bounds")
	}
	wire, err := rep.Ticket.Marshal()
	if err != nil {
		return nil, errors.New("cannot encode renewed TGT")
	}
	next := *old
	next.Ticket, next.Key = wire, p.Key
	next.AuthTime, next.StartTime, next.EndTime, next.RenewTill = p.AuthTime, p.StartTime, p.EndTime, p.RenewTill
	next.TicketFlags, next.Addresses = p.Flags, p.CAddr
	return &next, nil
}
