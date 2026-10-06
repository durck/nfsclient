package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// SavedSession identifies one original session incarnation. It is useful only
// together with an enclosing journal's exact protected connection profile.
type SavedSession struct {
	Minor, Sequence, LeaseSeconds, ReadSize, WriteSize uint32
	ClientID, ServerMinor                              uint64
	Nonce, Session, Root, Owner, Scope                 []byte
	Channel                                            sessionChannelLimits
	Confirmed                                          time.Time
	Auth                                               Auth
	Identity, Principal                                string
}

// Called under v.mu, including from beforeCached. No secret RPC/GSS keys exist
// in this snapshot; fresh authentication is mandatory during restoration.
func (v *v4Client) saveSession() (SavedSession, error) {
	if v.serverIdentity == nil || v.lastLease.Load() == nil {
		return SavedSession{}, errors.New("session identity or confirmed lease unavailable")
	}
	s := SavedSession{Minor: v.minor, Sequence: v.sequence, LeaseSeconds: v.leaseSeconds, ReadSize: v.c.ReadSize, WriteSize: v.c.WriteSize, ClientID: v.clientID, ServerMinor: v.serverMinor, Nonce: bytes.Clone(v.clientNonce), Session: bytes.Clone(v.session), Root: bytes.Clone(v.root), Owner: []byte(v.serverIdentity.owner), Scope: []byte(v.serverIdentity.scope), Channel: v.channel, Confirmed: *v.lastLease.Load(), Auth: v.c.Auth, Identity: v.c.Identity(), Principal: v.c.principal}
	s.Auth.Groups = slices.Clone(s.Auth.Groups)
	return s, s.Validate()
}

func (s SavedSession) Validate() error {
	if (s.Minor != 1 && s.Minor != 2) || len(s.Nonce) != 16 || len(s.Session) != 16 || len(s.Root) == 0 || len(s.Root) > 128 || len(s.Owner) == 0 || len(s.Owner) > 1024 || len(s.Scope) == 0 || len(s.Scope) > 1024 || s.ClientID == 0 || s.LeaseSeconds == 0 || s.Confirmed.IsZero() || s.ReadSize == 0 || s.WriteSize == 0 || s.ReadSize > 1<<20 || s.WriteSize > 1<<20 || s.Channel.Request == 0 || s.Channel.Response == 0 || s.Channel.Operations == 0 || len(s.Auth.Groups) > 16 {
		return errors.New("invalid saved NFSv4 session bounds")
	}
	return nil
}

// connectSavedSession authenticates and BINDs only. In particular it does not
// consume the unknown slot with TEST_STATEID, lease renewal, or namespace calls.
// Caller must replay the recorded request first, validate retained state, sync
// its journal, then explicitly publish the connection. Until publication Close
// must not destroy the borrowed original session.
func connectSavedSession(ctx context.Context, cfg Config, s SavedSession) (*Client, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if err := validateSecurity(&cfg); err != nil {
		return nil, err
	}
	if cfg.Version != fmt.Sprintf("4.%d", s.Minor) || cfg.PNFS || cfg.Auth.UID != s.Auth.UID || cfg.Auth.GID != s.Auth.GID || !slices.Equal(cfg.Auth.Groups, s.Auth.Groups) {
		return nil, errors.New("saved session profile or credentials changed")
	}
	policy := cfg
	policy.Offload = false
	if _, err := lockProfile(policy); err != nil {
		return nil, err
	}
	if s.Confirmed.After(time.Now().Add(time.Second)) || !time.Now().Before(s.Confirmed.Add(time.Duration(s.LeaseSeconds)*time.Second)) {
		return nil, errors.New("saved session lease expired or local time moved backwards")
	}
	ctx, cancel := context.WithDeadline(ctx, s.Confirmed.Add(time.Duration(s.LeaseSeconds)*time.Second))
	defer cancel()
	oldClient := &Client{Auth: s.Auth, version: cfg.Version, security: cfg.Security, principal: s.Principal, ReadSize: s.ReadSize, WriteSize: s.WriteSize}
	old := &v4Client{c: oldClient, minor: s.Minor, sequence: s.Sequence, clientID: s.ClientID, serverMinor: s.ServerMinor, clientNonce: bytes.Clone(s.Nonce), session: bytes.Clone(s.Session), root: bytes.Clone(s.Root), channel: s.Channel, leaseSeconds: s.LeaseSeconds, recoverBindOnly: true}
	old.serverIdentity = &createSessionKey{nonce: string(s.Nonce), owner: string(s.Owner), scope: string(s.Scope), clientID: s.ClientID, minor: s.Minor}
	old.lastLease.Store(&s.Confirmed)
	// A new callback channel cannot replace the previous session's backchannel.
	// Durable recovery uses foreground status polling after exact request replay.
	cfg.Offload, cfg.OffloadReconcile, cfg.OffloadJournal = false, false, ""
	fresh, err := connectStateProfile(ctx, cfg, nil, old)
	if err != nil {
		return nil, err
	}
	if fresh.Identity() != s.Identity {
		fresh.Close()
		return nil, errors.New("saved session protected identity changed")
	}
	return fresh, nil
}
