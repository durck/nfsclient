package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
)

// Each phase is an original operation, with its owner chosen before issue.
// Only a fully decoded cached result may replace it with the next phase.
type savedLockIntent struct {
	Phase      string
	Lock       savedLock
	Path, Name string
	Dir        []byte
	Failure    uint32
}

var ErrLockJournalReleased = errors.New("saved release was confirmed; no locks remain; reconnect normally")

func (i *savedLockIntent) validate(r lockRecord) error {
	if i == nil {
		return nil
	}
	l := i.Lock
	if !r.Pending || r.Retired || l.Info.ID == 0 || l.Info.Uncertain || ValidateLockRange(l.Info.Offset, l.Info.Length) != nil || len(l.Handle) == 0 || len(l.Handle) > 128 || len(l.OpenOwner) != 16 || len(l.LockOwner) != 16 || !validLockPath(i.Path) || r.Namespace.Paths[l.Info.ID] != i.Path {
		return errors.New("invalid saved lock intent")
	}
	switch i.Phase {
	case "open":
		if len(i.Dir) == 0 || len(i.Dir) > 128 || i.Name == "" || len(i.Name) > 255 || bytes.ContainsAny([]byte(i.Name), "/\\\x00") || len(l.OpenState) != 0 || l.OpenSequence != 0 {
			return errors.New("invalid planned OPEN")
		}
	case "lock", "close":
		if len(l.OpenState) != 16 || l.OpenSequence == 0 {
			return errors.New("invalid planned lock/open cleanup")
		}
	case "unlock", "free":
		if len(l.OpenState) != 16 || len(l.LockState) != 16 || l.OpenSequence == 0 {
			return errors.New("invalid planned unlock")
		}
	default:
		return errors.New("unknown saved lock phase")
	}
	var held *savedLock
	for n := range r.Locks {
		if r.Locks[n].Info.ID == l.Info.ID {
			held = &r.Locks[n]
		}
	}
	acquiring := i.Phase == "open" || i.Phase == "lock" || i.Phase == "close" && i.Failure != 0
	if acquiring {
		if held != nil || len(r.Locks) >= 64 || len(l.LockState) != 0 {
			return errors.New("acquisition intent conflicts with confirmed inventory")
		}
	} else {
		if held == nil || len(held.LockState) != 16 || held.Info != l.Info || !bytes.Equal(held.Handle, l.Handle) || !bytes.Equal(held.OpenState, l.OpenState) || !bytes.Equal(held.OpenOwner, l.OpenOwner) || !bytes.Equal(held.LockOwner, l.LockOwner) || held.OpenSequence != l.OpenSequence || len(l.LockState) != 16 || !bytes.Equal(held.LockState[4:], l.LockState[4:]) || i.Phase == "unlock" && !bytes.Equal(held.LockState, l.LockState) {
			return errors.New("release intent differs from confirmed inventory")
		}
	}
	return nil
}

func intentOps(clientID uint64, i *savedLockIntent) []v4Op {
	l := &i.Lock
	var e encoder
	kind, share := uint32(1), uint32(1)
	if l.Info.Write {
		kind, share = 2, 3
	}
	switch i.Phase {
	case "open":
		e.u32(0)
		e.u32(share | 0x400)
		e.u32(0) // WANT_NO_DELEG avoids unjournaled delegation state.
		e.u64(clientID)
		e.opaque(l.OpenOwner)
		e.u32(0)
		e.u32(0)
		e.str(i.Name)
		return []v4Op{fh4(i.Dir), op4(18, e, func(d *decoder) {
			l.OpenState = bytes.Clone(d.take(16))
			skipChange4(d)
			flags := d.u32()
			readBitmap4(d)
			switch d.u32() {
			case 0:
			case 3:
				why := d.u32()
				if why == 1 || why == 2 {
					d.boolean()
				}
			default:
				d.err = errors.New("unexpected delegation in durable OPEN")
			}
			if flags&2 != 0 {
				d.err = errors.New("OPEN_CONFIRM is invalid in a session")
			}
			l.OpenSequence = 1
		}), op4(10, nil, func(d *decoder) {
			if !bytes.Equal(d.opaque(128), l.Handle) {
				d.err = errors.New("durable OPEN file handle changed")
			}
		})}
	case "lock":
		e.u32(kind)
		e.u32(0)
		e.u64(l.Info.Offset)
		e.u64(l.Info.Length)
		e.u32(1)
		e.u32(l.OpenSequence)
		e = append(e, l.OpenState...)
		e.u32(0)
		e.u64(clientID)
		e.opaque(l.LockOwner)
		op := op4(12, e, func(d *decoder) { l.LockState = bytes.Clone(d.take(16)) })
		op.result = func(s Status) {
			switch s {
			case 10022, 10023, 10025, 10026, 10036, 10018, 10020:
			default:
				l.OpenSequence++
			}
		}
		return []v4Op{fh4(l.Handle), op}
	case "unlock":
		e.u32(kind)
		e.u32(1)
		e = append(e, l.LockState...)
		e.u64(l.Info.Offset)
		e.u64(l.Info.Length)
		return []v4Op{fh4(l.Handle), op4(14, e, func(d *decoder) { l.LockState = bytes.Clone(d.take(16)) })}
	case "free":
		return []v4Op{op4(45, encoder(l.LockState), nil)}
	case "close":
		e.u32(l.OpenSequence)
		e = append(e, l.OpenState...)
		return []v4Op{fh4(l.Handle), op4(4, e, func(d *decoder) { d.take(16) })}
	}
	return nil
}

func intentMatches(r lockRecord, ops []v4Op) bool {
	if r.Intent == nil {
		return false
	}
	i := *r.Intent
	want := intentOps(r.ClientID, &i)
	if len(want) != len(ops) {
		return false
	}
	for n := range want {
		if want[n].code != ops[n].code || !bytes.Equal(want[n].args, ops[n].args) {
			return false
		}
	}
	return true
}

func savedIntentMatches(r lockRecord, s SavedCompound) bool {
	ops := make([]v4Op, len(s.Operations))
	for n, o := range s.Operations {
		ops[n] = op4(o.Code, encoder(o.Args), nil)
	}
	return intentMatches(r, ops)
}

func (v *v4Client) beginLockIntent(i savedLockIntent) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	j := v.journal
	if j.record.Pending || j.record.Retired || v.stateLost.Load() || v.leaseMoved.Load() {
		return ErrLockJournalPending
	}
	// Reject insufficient negotiated limits before creating durable intent or
	// acquiring any OPEN state. Later phases contain only fixed-size stateids.
	planned := i
	phases := []string{"unlock", "free", "close"}
	if i.Phase == "open" {
		phases = []string{"open", "lock", "close"}
	}
	for _, phase := range phases {
		planned.Phase = phase
		if phase != "open" && len(planned.Lock.OpenState) == 0 {
			planned.Lock.OpenState = make([]byte, 16)
			planned.Lock.OpenSequence = 1
		}
		if err := v.checkChannel(v.c.Auth, v.c.nfs, nil, intentOps(v.clientID, &planned), true); err != nil {
			return err
		}
	}
	r := j.record
	r.Pending, r.Intent = true, &i
	r.Namespace.Paths = maps.Clone(r.Namespace.Paths)
	r.Namespace.Paths[i.Lock.Info.ID] = i.Path
	if err := j.append(r); err != nil {
		v.stateLost.Store(true)
		return err
	}
	j.transaction = true
	return nil
}

func (v *v4Client) acquireSavedLock(ctx context.Context, fh []byte, path string, write bool, offset, length uint64) (uint64, error) {
	p, ok := v.parents[string(fh)]
	if !ok || !validLockPath(path) {
		return 0, errors.New("durable acquisition requires a resolved pathname")
	}
	var owners [32]byte
	if _, err := rand.Read(owners[:]); err != nil {
		return 0, err
	}
	v.mu.Lock()
	id := v.nextLock + 1
	for _, l := range v.journal.record.Locks {
		id = max(id, l.Info.ID+1)
	}
	v.mu.Unlock()
	i := savedLockIntent{Phase: "open", Path: path, Name: p.name, Dir: bytes.Clone(p.dir), Lock: savedLock{Info: LockInfo{ID: id, Write: write, Offset: offset, Length: length}, Handle: bytes.Clone(fh), OpenOwner: bytes.Clone(owners[:16]), LockOwner: bytes.Clone(owners[16:])}}
	if err := v.beginLockIntent(i); err != nil {
		return 0, err
	}
	v.nextLock = id
	err := v.runLockIntent(ctx)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.journal.record.Intent != nil {
		// Preserve visibility without claiming a confirmed acquisition.
		l := v.journal.record.Intent.Lock
		l.Info.Uncertain = true
		if v.locks == nil {
			v.locks = map[uint64]*v4Lock{}
		}
		v.locks[id] = restoreSavedLock(l, v.c.Auth)
		return id, err
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

func restoreSavedLock(l savedLock, auth Auth) *v4Lock {
	return &v4Lock{info: l.Info, file: &v4Open{fh: bytes.Clone(l.Handle), sid: bytes.Clone(l.OpenState), owner: bytes.Clone(l.OpenOwner), seq: l.OpenSequence, auth: auth}, sid: bytes.Clone(l.LockState), owner: bytes.Clone(l.LockOwner)}
}

func completedSavedAcquisition(previous, current lockRecord, l savedLock) bool {
	if previous.Intent == nil || previous.Intent.Phase != "lock" || current.Intent != nil || current.Pending || current.Slot != previous.Slot+1 {
		return false
	}
	want := previous.Intent.Lock
	return want.Info == l.Info && bytes.Equal(want.Handle, l.Handle) && bytes.Equal(want.OpenState, l.OpenState) && bytes.Equal(want.OpenOwner, l.OpenOwner) && bytes.Equal(want.LockOwner, l.LockOwner) && l.OpenSequence == want.OpenSequence+1 && current.Namespace.Paths[l.Info.ID] == previous.Intent.Path
}

func (j *lockJournal) recoverIntent(ctx context.Context, cfg Config) error {
	r := j.record
	minor := uint32(1)
	if cfg.Version == "4.2" {
		minor = 2
	}
	s := SavedSession{Minor: minor, Sequence: r.Slot, LeaseSeconds: r.Lease, ReadSize: r.ReadSize, WriteSize: r.WriteSize, ClientID: r.ClientID, ServerMinor: r.ServerMinor, Nonce: r.Nonce, Session: r.Session, Root: r.Root, Owner: r.Owner, Scope: r.Scope, Channel: r.Channel, Confirmed: r.Confirmed, Auth: r.Auth, Identity: r.Identity, Principal: r.Principal}
	c, err := connectSavedSession(ctx, cfg, s)
	if err != nil {
		return err
	}
	defer c.Close()
	if c.nfs.conn.RemoteAddr().String() != r.Peer {
		return errors.New("saved lock phase endpoint changed")
	}
	c.v4.journal, j.transaction, j.recovering = j, true, true
	err = c.v4.runLockIntent(ctx)
	j.recovering = false
	c.v4.journal = nil // Caller retains the journal and publishes only after state/namespace validation.
	var status Status
	if j.record.Intent == nil && errors.As(err, &status) {
		return nil
	}
	return err
}

func (v *v4Client) releaseSavedLock(ctx context.Context, id uint64) error {
	v.mu.Lock()
	r := v.journal.record
	v.mu.Unlock()
	for _, l := range r.Locks {
		if l.Info.ID == id {
			i := savedLockIntent{Phase: "unlock", Lock: l, Path: r.Namespace.Paths[id]}
			if err := v.beginLockIntent(i); err != nil {
				return err
			}
			return v.runLockIntent(ctx)
		}
	}
	return errors.New("saved lock ID unavailable")
}

// A phase's result updates only a local copy. The old phase/request remains
// durable until the new phase (or final inventory) has been synchronized.
func (v *v4Client) runLockIntent(ctx context.Context) (result error) {
	j := v.journal
	defer func() {
		v.mu.Lock()
		defer v.mu.Unlock()
		j.transaction = false
		if j.record.Intent != nil {
			v.stateLost.Store(true)
		}
	}()
	for {
		v.mu.Lock()
		r := j.record
		v.mu.Unlock()
		if r.Intent == nil {
			return nil
		}
		i := *r.Intent
		ops := intentOps(r.ClientID, &i)
		started := time.Now()
		var err error
		if r.PendingRequest != nil {
			err = v.replaySavedCompound(ctx, *r.PendingRequest, ops...)
		} else {
			err = v.compoundAuth(ctx, r.Auth, ops...)
		}
		if !cachedReplayConfirmed(err, r.Slot, v.sequence, v.stateLost.Load()) {
			if err == nil {
				err = ErrLockJournalPending
			}
			return err
		}
		var status Status
		if err != nil && !errors.As(err, &status) {
			return err
		}
		done, acquired := false, false
		switch i.Phase {
		case "open":
			if err != nil && len(i.Lock.OpenState) != 0 {
				return err
			} // OPEN succeeded but trailing GETFH did not: retain original evidence.
			if err != nil {
				done = true
				i.Failure = uint32(status)
			} else {
				i.Phase = "lock"
			}
		case "lock":
			if err != nil {
				i.Failure = uint32(status)
				i.Phase = "close"
			} else {
				done, acquired = true, true
			}
		case "unlock":
			if err != nil {
				return err
			}
			i.Phase = "free"
		case "free":
			if err != nil {
				return err
			}
			i.Phase = "close"
		case "close":
			if err != nil {
				return err
			}
			done = true
		}
		r.Slot, r.Confirmed, r.PendingRequest = v.sequence, started, nil
		r.Intent = &i
		if done {
			r.Locks = slices.Clone(r.Locks)
			if acquired {
				r.Locks = append(r.Locks, i.Lock)
			} else {
				r.Locks = slices.DeleteFunc(r.Locks, func(l savedLock) bool { return l.Info.ID == i.Lock.Info.ID })
				r.Namespace.Paths = maps.Clone(r.Namespace.Paths)
				delete(r.Namespace.Paths, i.Lock.Info.ID)
			}
			r.Pending, r.Intent = false, nil
			r.Retired = len(r.Locks) == 0 && !r.Armed
			if j.recovering {
				r.RecoveredRequest = &LockRequestReceipt{Operation: ops[len(ops)-1].code, Status: i.Failure}
			}
		}
		v.mu.Lock()
		err = j.append(r)
		if err == nil {
			v.lastLease.Store(&started)
			if done {
				if v.locks == nil {
					v.locks = map[uint64]*v4Lock{}
				}
				if acquired {
					v.locks[i.Lock.Info.ID] = restoreSavedLock(i.Lock, r.Auth)
				} else {
					delete(v.locks, i.Lock.Info.ID)
				}
			}
		}
		v.mu.Unlock()
		if err != nil {
			return err
		}
		if done {
			if i.Failure != 0 {
				return fmt.Errorf("saved acquisition refused: %w", Status(i.Failure))
			}
			return nil
		}
	}
}
