package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// LockToEOF represents the protocol's all-ones length, including future growth.
const LockToEOF = ^uint64(0)

// LockInfo describes a nonblocking advisory lock. Held means the
// server acknowledged acquisition; it is not a promise against future revocation.
type LockInfo struct {
	ID        uint64
	Write     bool
	Uncertain bool
	Offset    uint64
	Length    uint64 // LockToEOF means through future EOF, not a finite length
}

type v4Lock struct {
	info       LockInfo
	file       *v4Open
	sid, owner []byte
}

var ErrLocksHeld = errors.New("file locks remain; unlock them first or explicitly reconnect --discard-locks")
var ErrLockUncertain = errors.New("lock state is uncertain; protected I/O and unlock replay refused; reconnect --discard-locks to abandon it")
var ErrPartialLockIO = errors.New("whole-file transfer refused under a partial-range lock; obtain a whole-file lock first")

// ValidateLockRange implements the RFC 7530 LOCK/LOCKU range bounds. The EOF
// sentinel is exempt from addition overflow; zero is never a valid length.
func ValidateLockRange(offset, length uint64) error {
	if length == 0 {
		return errors.New("lock length must be positive or eof")
	}
	if length != LockToEOF && length > LockToEOF-offset {
		return errors.New("lock offset plus length exceeds uint64")
	}
	return nil
}

// Locks, like the rest of Client's foreground API, must not run concurrently
// with other foreground operations. Lease invalidation is synchronized separately.
func (c *Client) Locks() []LockInfo {
	var out []LockInfo
	if c.nlm != nil {
		for _, l := range c.nlm.locks {
			i := l.info
			i.Uncertain = i.Uncertain || c.nlm.monitor.lost.Load()
			out = append(out, i)
		}
	}
	if c.v4 != nil {
		for _, l := range c.v4.locks {
			i := l.info
			i.Uncertain = i.Uncertain || c.v4.stateLost.Load() || c.v4.leaseMoved.Load()
			out = append(out, i)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LockedFileHandle returns a copy for namespace validation during recovery.
func (c *Client) LockedFileHandle(id uint64) ([]byte, error) {
	if c.nlm != nil && c.nlm.locks[id] != nil {
		return slices.Clone(c.nlm.locks[id].fh), nil
	}
	if c.v4 == nil || c.v4.locks[id] == nil {
		return nil, errors.New("unknown lock ID")
	}
	return append([]byte(nil), c.v4.locks[id].file.fh...), nil
}

func (v *v4Client) lockFor(fh []byte) *v4Lock {
	var found *v4Lock
	for _, l := range v.locks {
		if bytes.Equal(l.file.fh, fh) {
			if l.info.Uncertain {
				return l
			}
			if found == nil || l.info.ID < found.info.ID {
				found = l
			}
		}
	}
	return found
}

// Subtraction avoids overflow for finite ranges and the through-EOF sentinel.
func lockRangesOverlap(aOffset, aLength, bOffset, bLength uint64) bool {
	if aOffset <= bOffset {
		return aLength == LockToEOF || bOffset-aOffset < aLength
	}
	return bLength == LockToEOF || aOffset-bOffset < bLength
}

// Lock locks [0, EOF], including future growth, using an NFSv4 OPEN or explicitly
// configured monitored NLM. It never waits, retries a LOCK or upgrades a held lock.
// A nonzero ID with an error denotes an uncertain acquisition retained in Locks.
func (c *Client) Lock(ctx context.Context, fh []byte, write bool) (uint64, error) {
	return c.LockRange(ctx, fh, write, 0, LockToEOF)
}

// LockRange retains independent nonoverlapping ranges, each with its own
// OPEN and lock owner. A finite length covers [offset, offset+length).
// Existing whole-file transfers refuse any partial lock, even if the current
// file happens to fit: another writer can extend it after a size observation.
func (c *Client) LockRange(ctx context.Context, fh []byte, write bool, offset, length uint64) (uint64, error) {
	return c.LockRangeNamed(ctx, fh, "", write, offset, length)
}

// LockRangeNamed records the resolved path before a durable acquisition.
func (c *Client) LockRangeNamed(ctx context.Context, fh []byte, path string, write bool, offset, length uint64) (uint64, error) {
	if err := ValidateLockRange(offset, length); err != nil {
		return 0, err
	}
	v := c.v4
	if v == nil {
		return c.lockNLM(ctx, fh, write, offset, length)
	}
	if v.stateLost.Load() {
		return 0, ErrLockUncertain
	}
	v.lockTracking.Store(true)
	for _, held := range v.locks {
		if !bytes.Equal(held.file.fh, fh) {
			continue
		}
		if held.info.Uncertain {
			return 0, ErrLockUncertain
		}
		if held.file.auth.UID != c.Auth.UID || held.file.auth.GID != c.Auth.GID || !slices.Equal(held.file.auth.Groups, c.Auth.Groups) {
			return 0, errors.New("all ranges on one file must use the same identity")
		}
		if lockRangesOverlap(offset, length, held.info.Offset, held.info.Length) {
			return 0, errors.New("range overlaps a local lock; unlock that range before changing it")
		}
	}
	if len(v.locks) >= 64 {
		return 0, errors.New("at most 64 locks may be retained")
	}
	if v.journal != nil {
		return v.acquireSavedLock(ctx, fh, path, write, offset, length)
	}
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil {
		return 0, err
	}
	share, kind := uint32(1), uint32(1)
	if write {
		share, kind = 3, 2
	}
	f, err := v.openHandle(ctx, fh, share)
	if err != nil {
		return 0, err
	}
	v.nextLock++
	l := &v4Lock{info: LockInfo{ID: v.nextLock, Write: write, Offset: offset, Length: length}, file: f, owner: owner[:]}
	var e encoder
	e.u32(kind)
	e.u32(0) // not reclaim
	e.u64(offset)
	e.u64(length)
	e.u32(1) // new lock owner
	e.u32(f.seq)
	e = append(e, f.sid...)
	e.u32(0) // initial lock-owner sequence
	e.u64(v.clientID)
	e.opaque(owner[:])
	op := op4(12, e, func(d *decoder) { l.sid = append([]byte(nil), d.take(16)...) })
	op.result = func(s Status) {
		// RFC 7530 9.1.7: even DENIED consumes the open-owner seqid.
		switch s {
		case 10022, 10023, 10025, 10026, 10036, 10018, 10020:
		default:
			f.seq++
		}
	}
	started := time.Now()
	err = v.compoundAuth(ctx, f.auth, fh4(fh), op)
	if err == nil && v.stateLost.Load() {
		err = ErrLockUncertain
	}
	if err != nil {
		var status Status
		if errors.As(err, &status) {
			cleanupErr := v.closeFile(f)
			if v.minor == 0 {
				cleanupErr = errors.Join(cleanupErr, v.releaseOwner(ctx, l))
			}
			if cleanupErr == nil {
				return 0, err
			}
			return 0, errors.Join(err, cleanupErr)
		}
		l.info.Uncertain = true
	}
	if v.locks == nil {
		v.locks = make(map[uint64]*v4Lock)
	}
	v.locks[l.info.ID] = l
	if err != nil {
		return l.info.ID, fmt.Errorf("lock %d acquisition is uncertain: %w", l.info.ID, err)
	}
	v.lastLease.Store(&started)
	return l.info.ID, nil
}

func (v *v4Client) releaseOwner(ctx context.Context, l *v4Lock) error {
	var e encoder
	e.u64(v.clientID)
	e.opaque(l.owner)
	return v.compoundAuth(ctx, l.file.auth, op4(39, e, nil))
}

// Unlock sends LOCKU once. An uncertain result remains visible and is never
// retried with a stale stateid/seqid. A confirmed unlock removes the local lock
// even if subsequent open/owner cleanup fails; that failure is reported.
func (c *Client) Unlock(ctx context.Context, id uint64) (resultErr error) {
	if c.nlm != nil {
		return c.nlm.unlock(ctx, id)
	}
	if c.v4 == nil {
		return errors.New("file locks require NFSv4")
	}
	v := c.v4
	l := v.locks[id]
	if l == nil {
		return errors.New("unknown lock ID")
	}
	if l.info.Uncertain || v.stateLost.Load() {
		return ErrLockUncertain
	}
	if v.journal != nil {
		return v.releaseSavedLock(ctx, id)
	}
	finish, err := v.beginSavedUnlock()
	if err != nil {
		return err
	}
	defer func() { resultErr = finish(resultErr) }()
	var e encoder
	kind := uint32(1)
	if l.info.Write {
		kind = 2
	}
	e.u32(kind)
	e.u32(1) // LOCK consumed lock-owner sequence zero
	e = append(e, l.sid...)
	e.u64(l.info.Offset)
	e.u64(l.info.Length)
	err = v.compoundAuth(ctx, l.file.auth, fh4(l.file.fh), op4(14, e, func(d *decoder) { l.sid = append([]byte(nil), d.take(16)...) }))
	if err != nil {
		l.info.Uncertain = true
		return fmt.Errorf("unlock %d was not confirmed; no replay: %w", id, err)
	}
	delete(v.locks, id)
	var cleanup error
	if v.minor > 0 {
		cleanup = v.compoundAuth(ctx, l.file.auth, op4(45, encoder(l.sid), nil))
	}
	cleanup = errors.Join(cleanup, v.closeFileContext(ctx, l.file))
	if v.minor == 0 {
		cleanup = errors.Join(cleanup, v.releaseOwner(ctx, l))
	}
	if cleanup != nil {
		return fmt.Errorf("lock %d released but state cleanup failed: %w", id, cleanup)
	}
	return nil
}

// DiscardLocks closes this connection and abandons local lock state. Close
// attempts bounded cleanup of confirmed locks. The server may retain uncertain
// locks until lease expiry. Reconnect creates entirely new state, with no reclaim.
func (c *Client) DiscardLocks() {
	c.Close()
}

func (v *v4Client) checkLockedIO(fh []byte, share uint32) error {
	if l := v.lockFor(fh); l != nil {
		if l.info.Uncertain || v.stateLost.Load() || v.leaseMoved.Load() {
			return ErrLockUncertain
		}
		if l.file.auth.UID != v.c.Auth.UID || l.file.auth.GID != v.c.Auth.GID || !slices.Equal(l.file.auth.Groups, v.c.Auth.Groups) {
			return errors.New("file lock belongs to a different identity; restore its identity or unlock first")
		}
		if share == 2 && !l.info.Write {
			return errors.New("writing under a read lock is refused; unlock and obtain a write lock")
		}
		if l.info.Offset != 0 || l.info.Length != LockToEOF {
			return ErrPartialLockIO
		}
	}
	return nil
}

func (v *v4Client) openIO(ctx context.Context, fh []byte, share uint32) ([]byte, func() error, error) {
	if err := v.checkLockedIO(fh, share); err != nil {
		return nil, nil, err
	}
	if l := v.lockFor(fh); l != nil {
		return l.sid, func() error { return v.checkLockedIO(fh, share) }, nil
	}
	f, err := v.openHandle(ctx, fh, share)
	if err != nil {
		return nil, nil, err
	}
	return f.sid, func() error { return v.closeFile(f) }, nil
}
