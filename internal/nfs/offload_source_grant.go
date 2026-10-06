package nfs

import (
	"bytes"
	"errors"
	"time"
)

// No GSS privilege or secret is retained. A positive server lease is measured
// from receipt, an upper bound on its true expiration, never the shorter local
// operation deadline. Infinite or unrepresentable leases have no expiry proof.
type OffloadSourceGrant struct {
	ID                []byte
	Recorded, Expires time.Time
	Revoked           bool
}

func validateOffloadSourceGrant(r, previous OffloadRecord) error {
	g := r.SourceGrant
	if g != nil && (r.Operation != "copyfrom" || len(g.ID) != 16 || g.Recorded.IsZero() || !g.Expires.IsZero() && !g.Expires.After(g.Recorded)) {
		return errors.New("invalid offload source grant evidence")
	}
	if previous.Pending && previous.ID == r.ID && previous.SourceGrant != nil {
		p := previous.SourceGrant
		if g == nil || !bytes.Equal(p.ID, g.ID) || !p.Recorded.Equal(g.Recorded) || !p.Expires.Equal(g.Expires) || p.Revoked && !g.Revoked {
			return errors.New("offload source authorization changed")
		}
	}
	return nil
}

func sourceGrantClosed(r OffloadRecord, now time.Time) bool {
	if r.Operation != "copyfrom" {
		return true
	}
	g := r.SourceGrant
	if g == nil {
		if r.Phase == "prepared" {
			return true
		}
		if e, ok := r.Endpoints["source"]; ok && e.Recovery != nil && e.Recovery.Failure != nil && e.Recovery.Failure.Operation == 61 {
			return true
		}
		if e, ok := r.Endpoints["source"]; ok && e.Recovery != nil && !e.Recovery.NotifyIssued {
			return true
		}
	}
	return g != nil && (g.Revoked || !g.Expires.IsZero() && !now.Before(g.Recorded) && !now.Before(g.Expires))
}

func (v *v4Client) recordSourceGrant(g copyGrant, revoked bool) error {
	if v.c.config == nil || !v.c.config.OffloadSessionRecovery {
		return nil
	}
	v.recall.mu.Lock()
	defer v.recall.mu.Unlock()
	if v.recall.offload == nil || v.recall.offload.journal == nil {
		return errors.New("source authorization journal unavailable")
	}
	j := v.recall.offload.journal
	r := j.record
	if r.SourceGrant != nil {
		if !bytes.Equal(r.SourceGrant.ID, g.id) {
			return errors.New("COPY_NOTIFY identity differs from durable source response")
		}
		grant := *r.SourceGrant
		grant.Revoked = grant.Revoked || revoked
		r.SourceGrant = &grant
	} else {
		r.SourceGrant = &OffloadSourceGrant{ID: bytes.Clone(g.id), Recorded: g.recorded, Expires: g.proofExpires, Revoked: revoked}
	}
	return j.append(r)
}
