package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
)

func (v *v4Client) sessionOwner() *v4Client {
	if v.sharedSession != nil {
		return v.sharedSession
	}
	return v
}

// bindReplaySession runs while ticket.Owner.mu is already held by the original
// failed compound. It binds a new transport, never a new session or slot.
func (v *v4Client) bindReplaySession(ctx context.Context, ticket *v4ReplayRequest, key createSessionKey) error {
	if ticket == nil || ticket.Owner == nil {
		return errors.New("missing cached replay admission")
	}
	owner := ticket.Owner
	if v.exchangeRole != 0x40000 || owner.exchangeRole != 0x40000 || owner.sharedSession != nil || owner.trunked ||
		owner.serverIdentity == nil || *owner.serverIdentity != key || v.serverMinor != owner.serverMinor ||
		len(owner.session) != 16 || !bytes.Equal(owner.session, ticket.Session) || owner.sequence != ticket.Sequence ||
		ticket.Digest != sha256.Sum256(ticket.Inner) || owner.stateLost.Load() || owner.reclaimForbidden.Load() ||
		v.minor != owner.minor || v.c.Security() != owner.c.Security() || v.c.Identity() != owner.c.Identity() ||
		(v.c.Security() != "krb5i" && v.c.Security() != "krb5p") {
		return errors.New("pNFS cached replay did not confirm the original protected DS session")
	}
	e := append(encoder(nil), ticket.Session...)
	e.u32(1)
	e.u32(0)
	return v.compound(ctx, op4(41, e, func(d *decoder) {
		if !bytes.Equal(d.take(16), ticket.Session) || d.u32() != 1 || d.boolean() {
			d.err = errors.New("invalid cached replay session binding")
		}
	}))
}

// The pool calls this only between batches after authenticating the alternate
// with the original user, protection service and explicitly selected DS SPN.
func (v *v4Client) bindSharedSession(ctx context.Context, owner *v4Client, key createSessionKey) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if v.exchangeRole != 0x40000 || owner.exchangeRole != 0x40000 || owner.sharedSession != nil ||
		owner.serverIdentity == nil || *owner.serverIdentity != key || v.serverMinor != owner.serverMinor ||
		len(owner.session) != 16 || owner.stateLost.Load() || v.minor != owner.minor ||
		v.c.Security() != owner.c.Security() || v.c.Identity() != owner.c.Identity() {
		return errors.New("pNFS session trunk did not confirm the original live DS identity")
	}
	id := append([]byte(nil), owner.session...)
	e := append(encoder(nil), id...)
	e.u32(1) // CDFC4_FORE; no additional backchannel or RDMA binding.
	e.u32(0)
	if err := v.compound(ctx, op4(41, e, func(d *decoder) {
		if !bytes.Equal(d.take(16), id) || d.u32() != 1 || d.boolean() {
			d.err = errors.New("invalid pNFS fore-channel session binding")
		}
	})); err != nil {
		return err
	}
	owner.trunked = true
	v.sharedSession, v.serverIdentity = owner, owner.serverIdentity
	v.c.ReadSize, v.c.WriteSize = owner.c.ReadSize, owner.c.WriteSize
	return nil
}
