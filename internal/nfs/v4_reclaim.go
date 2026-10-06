package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ReclaimLocks makes one bounded server-restart recovery attempt. It never
// replays file I/O or acquires replacement locks with reclaim=false. The old
// client becomes unusable once recovery starts; on failure its lock inventory
// remains uncertain and can only be explicitly discarded.
func (c *Client) ReclaimLocks(ctx context.Context) (*Client, error) {
	if c.Version() == "2" || c.Version() == "3" {
		return c.reclaimNLMLocks(ctx)
	}
	v := c.v4
	if v == nil || v.journal != nil || c.config == nil || len(v.clientNonce) != 16 || len(v.locks) == 0 {
		return nil, errors.New("reclaim requires a live NFSv4 client with previously confirmed locks")
	}
	if v.reclaimAttempted {
		return nil, errors.New("reclaim already attempted for this server incarnation; discard uncertain state explicitly")
	}
	if v.reclaimForbidden.Load() || v.leaseMoved.Load() {
		return nil, errors.New("server reported revoked, expired or invalid state; reclaim refused")
	}
	for _, l := range v.locks {
		if l.info.Uncertain || len(l.sid) != 16 || len(l.file.owner) == 0 {
			return nil, errors.New("cannot reclaim an unconfirmed acquisition or unlock")
		}
		if l.file.auth.UID != c.Auth.UID || l.file.auth.GID != c.Auth.GID || !slices.Equal(l.file.auth.Groups, c.Auth.Groups) {
			return nil, errors.New("restore the locked identity before reclaim")
		}
	}
	last := v.lastLease.Load()
	if last == nil || v.leaseSeconds == 0 || time.Since(*last) >= time.Duration(v.leaseSeconds)*time.Second {
		return nil, errors.New("last confirmed lease has elapsed; lock continuity cannot be reclaimed safely")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, last.Add(time.Duration(v.leaseSeconds)*time.Second))
	defer cancel()
	v.reclaimAttempted = true
	if v.stop != nil {
		v.stop()
		<-v.done
	}
	v.stateLost.Store(true)
	c.nfs.mu.Lock()
	c.nfs.closeLocked()
	c.nfs.mu.Unlock()
	cfg := *c.config
	cfg.Auth = c.Auth
	cfg.Auth.Groups = append([]uint32(nil), c.Auth.Groups...)
	fresh, err := connectProfile(ctx, cfg, v)
	if err != nil {
		return nil, fmt.Errorf("reclaim connection (old state retained as uncertain): %w", err)
	}
	ready := false
	defer func() {
		if !ready {
			fresh.v4.stateLost.Store(true)
			fresh.Close()
		}
	}()
	if fresh.Identity() != c.Identity() || fresh.Version() != c.Version() || fresh.Transport() != c.Transport() || fresh.v4.clientID == v.clientID {
		return nil, errors.New("reclaim requires the same profile and a changed server client ID; no replacement locks acquired")
	}
	if err := fresh.v4.checkReclaimState(); err != nil {
		return nil, fmt.Errorf("reclaim initialization: %w", err)
	}
	confirmed := time.Now()
	for _, info := range c.Locks() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := fresh.v4.reclaimLock(ctx, v.locks[info.ID]); err != nil {
			return nil, fmt.Errorf("lock %d reclaim failed; no automatic retry or replacement acquisition: %w", info.ID, err)
		}
	}
	if fresh.v4.minor > 0 {
		var e encoder
		e.u32(0)
		if err := fresh.v4.compound(ctx, op4(58, e, nil)); err != nil {
			return nil, fmt.Errorf("RECLAIM_COMPLETE: %w", err)
		}
		if err := fresh.v4.checkReclaimState(); err != nil {
			return nil, fmt.Errorf("RECLAIM_COMPLETE state: %w", err)
		}
	}
	fresh.v4.reclaiming = false
	if err := fresh.v4.keepAlive(ctx); err != nil {
		return nil, err
	}
	if err := fresh.v4.checkReclaimState(); err != nil {
		return nil, fmt.Errorf("reclaimed lease state: %w", err)
	}
	fresh.v4.lastLease.Store(&confirmed)
	ready = true
	return fresh, nil
}

// Successful operations can carry SEQUENCE flags that invalidate the recovered
// state. Check these before continuing recovery or publishing its result.
func (v *v4Client) checkReclaimState() error {
	if v.stateLost.Load() || v.reclaimForbidden.Load() || v.leaseMoved.Load() {
		return ErrLockUncertain
	}
	return nil
}

func (v *v4Client) reclaimLock(ctx context.Context, old *v4Lock) error {
	share, kind := uint32(1), uint32(1)
	if old.info.Write {
		share, kind = 3, 2
	}
	f := &v4Open{fh: append([]byte(nil), old.file.fh...), owner: append([]byte(nil), old.file.owner...), seq: 1, auth: old.file.auth}
	f.auth.Groups = append([]uint32(nil), f.auth.Groups...)
	var e encoder
	e.u32(0)
	e.u32(share)
	e.u32(0)
	e.u64(v.clientID)
	e.opaque(f.owner)
	e.u32(0)
	e.u32(1)
	e.u32(0) // NOCREATE, CLAIM_PREVIOUS, OPEN_DELEGATE_NONE
	var delegation []byte
	err := v.compoundAuth(ctx, f.auth, fh4(f.fh), op4(18, e, func(d *decoder) {
		f.sid = append([]byte(nil), d.take(16)...)
		skipChange4(d)
		flags := d.u32()
		readBitmap4(d)
		if flags&2 != 0 {
			d.err = errors.New("unexpected confirmation during OPEN reclaim")
		}
		delegation = decodeReclaimDelegation(d)
	}), op4(10, nil, func(d *decoder) {
		if !bytes.Equal(f.fh, d.opaque(128)) {
			d.err = errors.New("reclaimed OPEN changed file handle")
		}
	}))
	if err != nil {
		return err
	}
	if err := v.checkReclaimState(); err != nil {
		return err
	}
	if len(delegation) != 0 {
		if err := v.compoundAuth(ctx, f.auth, fh4(f.fh), op4(8, encoder(delegation), nil)); err != nil {
			return fmt.Errorf("return reclaimed delegation: %w", err)
		}
		if err := v.checkReclaimState(); err != nil {
			return err
		}
	}
	l := &v4Lock{info: old.info, file: f, owner: append([]byte(nil), old.owner...)}
	l.info.Uncertain = true
	if v.locks == nil {
		v.locks = make(map[uint64]*v4Lock)
	}
	v.locks[l.info.ID] = l
	v.nextLock = max(v.nextLock, l.info.ID)
	v.lockTracking.Store(true)
	e = nil
	e.u32(kind)
	e.u32(1)
	e.u64(l.info.Offset)
	e.u64(l.info.Length)
	e.u32(1)
	e.u32(f.seq)
	e = append(e, f.sid...)
	e.u32(0)
	e.u64(v.clientID)
	e.opaque(l.owner)
	err = v.compoundAuth(ctx, f.auth, fh4(f.fh), op4(12, e, func(d *decoder) { l.sid = append([]byte(nil), d.take(16)...) }))
	if err != nil {
		return err
	}
	if err := v.checkReclaimState(); err != nil {
		return err
	}
	f.seq++
	l.info.Uncertain = false
	return nil
}

// Some servers return an immediately recalled delegation with CLAIM_PREVIOUS,
// even when OPEN_DELEGATE_NONE was requested. Parse and return it immediately;
// it is never retained or treated as permission for local cached operations.
func decodeReclaimDelegation(d *decoder) []byte {
	kind := d.u32()
	if kind == 0 {
		return nil
	}
	if kind == 3 {
		why := d.u32()
		if why > 8 {
			d.err = errors.New("invalid no-delegation reason")
		}
		if why == 1 || why == 2 {
			d.boolean()
		}
		return nil
	}
	if kind != 1 && kind != 2 {
		d.err = errors.New("invalid reclaim delegation type")
		return nil
	}
	sid := append([]byte(nil), d.take(16)...)
	d.boolean()
	if kind == 2 {
		switch d.u32() {
		case 1:
			d.u64()
		case 2:
			d.u32()
			d.u32()
		default:
			d.err = errors.New("invalid reclaim delegation limit")
		}
	}
	d.u32()
	d.u32()
	d.u32()
	d.str()
	return sid
}
