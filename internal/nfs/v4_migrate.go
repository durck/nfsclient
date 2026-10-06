package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"
)

// MigrationLocks returns confirmed acquisition records only for the explicit
// migration workflow. Locks reports LEASE_MOVED as unusable at the old endpoint;
// that signal alone does not revoke the server's retained state.
func (c *Client) MigrationLocks() ([]LockInfo, error) {
	if c.v4 == nil || c.v4.minor == 0 || c.v4.stateLost.Load() {
		return nil, ErrLockUncertain
	}
	items := c.Locks()
	for i := range items {
		l := c.v4.locks[items[i].ID]
		if l == nil || l.info.Uncertain {
			return nil, ErrLockUncertain
		}
		items[i] = l.info
	}
	return items, nil
}

func (v *v4Client) bindMigration(ctx context.Context, old *v4Client, key createSessionKey, confirmed bool) error {
	if !confirmed || old.serverIdentity == nil || key.clientID != old.clientID || key.scope == "" || key.scope != old.serverIdentity.scope || key.nonce != old.serverIdentity.nonce || v.minor != old.minor || len(old.session) != 16 {
		return errors.New("migration target did not confirm the selected client and common server scope")
	}
	if (old.recoverBindOnly || old.sameIncarnation) && (key != *old.serverIdentity || v.serverMinor != old.serverMinor) {
		return errors.New("saved session server incarnation changed")
	}
	id := bytes.Clone(old.session)
	e := append(encoder(nil), id...)
	e.u32(1)
	e.u32(0)
	if err := v.compound(ctx, op4(41, e, func(d *decoder) {
		if !bytes.Equal(d.take(16), id) || d.u32() != 1 || d.boolean() {
			d.err = errors.New("invalid migrated fore-channel session binding")
		}
	})); err != nil {
		return fmt.Errorf("transferred session binding failed; no new session or reclaim: %w", err)
	}
	v.session, v.sequence = id, old.sequence
	v.serverIdentity = &key
	v.maxReplyPayload, v.maxRequestPayload = old.maxReplyPayload, old.maxRequestPayload
	v.channel = old.channel
	v.c.ReadSize, v.c.WriteSize = old.c.ReadSize, old.c.WriteSize
	if old.recoverBindOnly {
		if err := v.setChannel(old.channel); err != nil {
			return err
		}
		v.root = bytes.Clone(old.root)
		v.leaseSeconds = old.leaseSeconds
		v.lastLease.Store(old.lastLease.Load())
		v.lockTracking.Store(true)
		return nil
	}
	v.lockTracking.Store(true)
	var stateids [][]byte
	for _, info := range old.c.Locks() {
		l := old.locks[info.ID]
		stateids = append(stateids, l.file.sid, l.sid)
	}
	e = nil
	e.u32(uint32(len(stateids)))
	for _, sid := range stateids {
		e = append(e, sid...)
	}
	if err := v.compound(ctx, op4(55, e, func(d *decoder) {
		if d.u32() != uint32(len(stateids)) {
			d.err = errors.New("migration stateid result count differs")
			return
		}
		for range stateids {
			if d.u32() != 0 {
				d.err = errors.New("migration target did not retain every OPEN and LOCK")
				return
			}
		}
	})); err != nil {
		return err
	}
	if v.stateLost.Load() || v.leaseMoved.Load() {
		return errors.New("migration target reported lost or revoked state")
	}
	// The target pseudo-root need not have migrated. Re-obtain it by protocol;
	// export/file handle equality is checked before publishing the new Session.
	return v.compound(ctx, op4(24, nil, nil), op4(10, nil, func(d *decoder) { v.root = bytes.Clone(d.opaque(128)) }))
}

// MigrateLocks validates a transferred session and every confirmed OPEN/LOCK
// before committing a protected endpoint transition. validate must perform the
// caller's read-only namespace checks. No data operation or LOCK is replayed.
// A failed attempt disables the old transport and retains uncertain inventory.
func (c *Client) MigrateLocks(ctx context.Context, target ReadReplica, validate func(*Client) error) (*Client, error) {
	return c.migrateLocks(ctx, target, validate, false)
}

// FailoverLocks requires an exact replica incarnation when no source MOVED proof exists.
func (c *Client) FailoverLocks(ctx context.Context, target ReadReplica, validate func(*Client) error) (*Client, error) {
	return c.migrateLocks(ctx, target, validate, true)
}

func (c *Client) migrateLocks(ctx context.Context, target ReadReplica, validate func(*Client) error, sameIncarnation bool) (*Client, error) {
	if err := c.ValidateReadReplica(target); err != nil {
		return nil, err
	}
	v := c.v4
	if v == nil || v.journal != nil || v.minor == 0 || len(v.locks) == 0 && !v.recoverEmpty || len(v.locks) > 64 || len(v.clientNonce) != 16 || v.serverIdentity == nil || v.stateLost.Load() || v.migrationAttempted || validate == nil {
		return nil, errors.New("migration requires live confirmed NFSv4.1/4.2 locks, known session and namespace validation")
	}
	for _, l := range v.locks {
		if l.info.Uncertain || len(l.sid) != 16 || len(l.file.sid) != 16 || len(l.owner) != 16 || len(l.file.owner) != 16 || l.file.auth.UID != c.Auth.UID || l.file.auth.GID != c.Auth.GID || !slices.Equal(l.file.auth.Groups, c.Auth.Groups) {
			return nil, errors.New("migration refuses uncertain state or changed lock credentials")
		}
	}
	last := v.lastLease.Load()
	if last == nil || v.leaseSeconds == 0 || time.Since(*last) >= time.Duration(v.leaseSeconds)*time.Second {
		return nil, errors.New("migration requires an unexpired confirmed lease")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, last.Add(time.Duration(v.leaseSeconds)*time.Second))
	defer cancel()
	v.migrationAttempted = true
	v.sameIncarnation = sameIncarnation
	if v.stop != nil {
		v.stop()
		<-v.done
	}
	if v.stateLost.Load() {
		return nil, ErrLockUncertain
	}
	v.stateLost.Store(true)
	if c.nfs != nil {
		c.nfs.mu.Lock()
		c.nfs.closeLocked()
		c.nfs.mu.Unlock()
	}
	host, port, _ := net.SplitHostPort(target.Address)
	number, _ := strconv.Atoi(port)
	cfg := *c.config
	cfg.Host, cfg.NFSPort = host, number
	cfg.Version, cfg.Security = c.Version(), c.Security()
	cfg.Auth = c.Auth
	cfg.Auth.Groups = slices.Clone(c.Auth.Groups)
	cfg.Kerberos.SPN, cfg.TLS.ServerName = target.SPN, target.TLSName
	fresh, err := connectStateProfile(ctx, cfg, nil, v)
	if err != nil {
		return nil, fmt.Errorf("migration validation failed (old locks uncertain): %w", err)
	}
	ready := false
	defer func() {
		if !ready {
			fresh.v4.stateLost.Store(true)
			fresh.Close()
		}
	}()
	if fresh.Identity() != c.Identity() || fresh.Version() != c.Version() || fresh.Transport() != c.Transport() {
		return nil, errors.New("migration changed authentication or protocol")
	}
	for id, l := range v.locks {
		f := *l.file
		f.fh, f.sid, f.owner = bytes.Clone(f.fh), bytes.Clone(f.sid), bytes.Clone(f.owner)
		f.auth.Groups = slices.Clone(f.auth.Groups)
		next := &v4Lock{info: l.info, file: &f, sid: bytes.Clone(l.sid), owner: bytes.Clone(l.owner)}
		if fresh.v4.locks == nil {
			fresh.v4.locks = map[uint64]*v4Lock{}
		}
		fresh.v4.locks[id] = next
		fresh.v4.nextLock = max(fresh.v4.nextLock, id)
	}
	if err := validate(fresh); err != nil {
		return nil, fmt.Errorf("migration namespace validation: %w", err)
	}
	if fresh.Auth.UID != cfg.Auth.UID || fresh.Auth.GID != cfg.Auth.GID || !slices.Equal(fresh.Auth.Groups, cfg.Auth.Groups) || len(fresh.v4.locks) != len(v.locks) {
		return nil, errors.New("migration validation changed credentials or lock inventory")
	}
	for id, l := range v.locks {
		n := fresh.v4.locks[id]
		if n == nil || n.info != l.info || !bytes.Equal(n.sid, l.sid) || !bytes.Equal(n.owner, l.owner) || !bytes.Equal(n.file.sid, l.file.sid) || !bytes.Equal(n.file.owner, l.file.owner) || !bytes.Equal(n.file.fh, l.file.fh) {
			return nil, errors.New("migration validation changed retained state")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fresh.v4.stateLost.Load() || fresh.v4.leaseMoved.Load() {
		return nil, ErrLockUncertain
	}
	if err := fresh.v4.keepAlive(ctx); err != nil {
		return nil, err
	}
	if fresh.v4.stateLost.Load() || fresh.v4.leaseMoved.Load() {
		return nil, ErrLockUncertain
	}
	confirmed := time.Now()
	fresh.v4.lastLease.Store(&confirmed)
	fresh.v4.migrationBorrowed = false
	fresh.v4.migrationFrom = nil
	// Ownership transfers once. Closing the retired client must never send
	// DESTROY_SESSION or unlock the state now owned by the new endpoint.
	clear(v.locks)
	v.session = nil
	ready = true
	return fresh, nil
}
