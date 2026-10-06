package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
)

// LockReclaimEnabled reports the explicitly selected recovery profile. For NLM
// this is a deployment assertion, not a server capability discovered on wire:
// some servers accept reclaim outside grace and cannot establish continuity.
func (c *Client) LockReclaimEnabled() bool {
	return c.v4 != nil || c.config != nil && c.config.NLMReclaim
}

func (c *Client) reclaimNLMLocks(ctx context.Context) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n := c.nlm
	if c.config == nil || !c.config.NLMReclaim || n == nil || len(n.locks) == 0 {
		return nil, errors.New("NLM reclaim requires --nlm-reclaim, server-enforced grace and previously confirmed locks")
	}
	if n.reclaimAttempted {
		return nil, errors.New("NLM reclaim already attempted; uncertain state remains quarantined")
	}
	for _, l := range n.locks {
		if !l.confirmed || l.info.Uncertain || len(l.owner) == 0 || len(l.fh) == 0 || l.svid == 0 {
			return nil, errors.New("cannot reclaim an unconfirmed NLM acquisition or unlock")
		}
		if !sameNLMAuth(l.auth, c.Auth) {
			return nil, errors.New("restore the locked identity before reclaim")
		}
	}
	if err := validateNLMConfig(*c.config); err != nil {
		return nil, err
	}
	n.reclaimAttempted = true
	// Retain the old inventory as uncertain. Release the callback listener and
	// exclusive journal ownership before opening the same identity on fresh RPCs.
	n.monitor.invalidate()
	n.monitor.close()
	n.rpc.conn.Close()
	cfg := *c.config
	cfg.Host = n.monitor.peer // Never re-resolve DNS onto a different lock server.
	cfg.Auth = c.Auth
	cfg.Auth.Groups = slices.Clone(c.Auth.Groups)
	fresh, err := Connect(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("NLM reclaim connection: %w", err)
	}
	ready := false
	defer func() {
		if !ready {
			if fresh.nlm != nil {
				fresh.nlm.monitor.invalidate()
			}
			fresh.Close()
		}
	}()
	if fresh.Version() != c.Version() || fresh.Transport() != c.Transport() || fresh.Security() != c.Security() || fresh.Identity() != c.Identity() {
		return nil, errors.New("NLM reclaim connection changed profile")
	}
	if err := fresh.initNLMMode(ctx, true); err != nil {
		return nil, err
	}
	if err := fresh.nlm.reclaimSavedLocks(ctx, n); err != nil {
		return nil, fmt.Errorf("NLM reclaim failed; no retry or replacement acquisition: %w", err)
	}
	ready = true
	return fresh, nil
}

func (n *nlmClient) reclaimSavedLocks(ctx context.Context, old *nlmClient) (resultErr error) {
	defer func() {
		if resultErr != nil {
			n.monitor.invalidate()
		}
	}()
	if n.monitor.state.record.NotifyEpoch != 0 || old.monitor.state.record.NotifyEpoch != 0 {
		return errors.New("pending client-crash notification cannot reclaim old locks")
	}
	if old.monitor.peerState > 0x7ffffffd || n.monitor.peerState != old.monitor.peerState+2 || n.monitor.peer != old.monitor.peer {
		return errors.New("NLM reclaim requires exactly one confirmed server NSM restart on the same peer")
	}
	r, previous := n.monitor.state.record, old.monitor.state.record
	if n.version != old.version || r.State != previous.State || r.LastSVID != previous.LastSVID || !r.Dirty || len(r.Locks) != len(old.locks) || len(r.Locks) == 0 {
		return errors.New("NLM reclaim journal changed profile, epoch or inventory")
	}
	seen := make(map[uint64]bool)
	for _, saved := range r.Locks {
		l := old.locks[saved.Info.ID]
		if l == nil || seen[saved.Info.ID] || saved.Version != n.version || !saved.Confirmed || !l.confirmed || saved.Info != l.info ||
			!bytes.Equal(saved.FH, l.fh) || !bytes.Equal(saved.Owner, l.owner) || saved.SVID != l.svid || !sameNLMAuth(saved.Auth, l.auth) {
			return errors.New("NLM reclaim journal changed lock identity")
		}
		seen[saved.Info.ID] = true
	}
	ids := make([]uint64, 0, len(r.Locks))
	for _, saved := range r.Locks {
		l := &nlmLock{info: saved.Info, fh: bytes.Clone(saved.FH), owner: bytes.Clone(saved.Owner), svid: saved.SVID, auth: saved.Auth, confirmed: true}
		l.auth.Groups = slices.Clone(l.auth.Groups)
		n.locks[l.info.ID] = l
		ids = append(ids, l.info.ID)
	}
	n.nextID = old.nextID
	n.monitor.active.Store(int32(len(n.locks)))
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if err := n.guard(ctx); err != nil {
			return err
		}
		l := n.locks[id]
		// A lost reply can leave a delayed LOCK executing. Persist uncertainty
		// before sending it, just as for the initial acquisition.
		l.confirmed = false
		if err := n.saveLocks(); err != nil {
			return err
		}
		status, err := n.mutateMode(ctx, 2, l, true)
		if err != nil {
			return errors.Join(ErrLockUncertain, err)
		}
		if status == 3 {
			return errors.Join(ErrLockUncertain, status)
		} // Unexpected queued request may still acquire.
		if status != 0 {
			// A definitive refusal leaves a known historical owner suitable for
			// explicit exact-owner cleanup, never another acquisition attempt.
			l.confirmed = true
			return errors.Join(status, n.saveLocks())
		}
		if err := n.guard(ctx); err != nil {
			return err
		}
		l.confirmed = true
		if err := n.saveLocks(); err != nil {
			return err
		}
	}
	return n.guard(ctx)
}
