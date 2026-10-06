package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
)

// OffloadResources inventories only state acquired for this operation. Entries
// borrowed from a caller's retained lock never enter a release transition.
type OffloadResources struct {
	Version  int
	Role     string `json:",omitempty"`
	Complete bool
	Active   uint64
	Entries  []OffloadResource
}

type OffloadResource struct {
	State         string
	Intent        savedLockIntent
	BorrowedState []byte `json:",omitempty"`
}

var errOffloadResourceBusy = errors.New("offload resource transition is awaiting its exact request")

func checkOffloadResourceRequest(r OffloadRecord, s SavedCompound) error {
	if r.Resources != nil && r.Resources.Active != 0 && !resourceRequestMatches(r, s) {
		return errors.Join(errOffloadResourceBusy, channelRefusal("unrelated request cannot consume an offload resource slot"))
	}
	return nil
}

func cloneOffloadResources(x *OffloadResources) *OffloadResources {
	if x == nil {
		return nil
	}
	y := *x
	y.Entries = append([]OffloadResource(nil), x.Entries...)
	return &y
}

func offloadResourcesReleased(r OffloadRecord) bool {
	if !offloadOwnResourcesReleased(r) {
		return false
	}
	if r.Operation == "copyfrom" {
		if _, ok := r.Endpoints["source"]; !ok {
			if r.Phase != "prepared" || r.SourceGrant != nil || r.Recovery == nil || r.Recovery.DataIssued || r.Recovery.Request != nil || len(r.Resources.Entries) != 0 {
				return false
			}
		}
	}
	for key := range r.Endpoints {
		if !offloadOwnResourcesReleased(endpointRecord(r, key)) {
			return false
		}
	}
	return true
}

func offloadOwnResourcesReleased(r OffloadRecord) bool {
	x := r.Resources
	if x == nil || x.Version != 1 || !x.Complete || x.Active != 0 {
		return false
	}
	for _, e := range x.Entries {
		if e.State != "closed" && e.State != "borrowed" {
			return false
		}
	}
	return true
}

func validateOffloadResources(r, previous OffloadRecord) error {
	x, p := r.Resources, previous.Resources
	if previous.ID != r.ID {
		p = nil
	}
	if x == nil {
		if p != nil {
			return errors.New("offload resource inventory removed")
		}
		return nil
	}
	if x.Version != 1 || x.Role != "" && x.Role != "source" && x.Role != "verification" || len(x.Entries) > 32 || x.Active > uint64(len(x.Entries)) {
		return errors.New("invalid offload resource inventory")
	}
	if p != nil && (p.Version != x.Version || p.Role != x.Role || p.Complete != x.Complete || len(x.Entries) < len(p.Entries)) {
		return errors.New("offload resource ownership changed")
	}
	for n, e := range x.Entries {
		i := e.Intent
		l := i.Lock
		if l.Info.ID != uint64(n+1) || len(l.Handle) == 0 || len(l.Handle) > 128 || len(l.OpenOwner) != 16 || len(l.LockState) != 0 && len(l.LockState) != 16 {
			return errors.New("invalid offload resource identity")
		}
		if !bytes.Equal(l.Handle, r.Source) && !bytes.Equal(l.Handle, r.Destination) {
			return errors.New("offload resource outside operation")
		}
		switch e.State {
		case "opening":
			if i.Phase != "open" || len(l.OpenState) != 0 || x.Active != l.Info.ID {
				return errors.New("invalid offload OPEN intent")
			}
		case "open", "closing", "locking", "locked", "unlocking", "unlocked", "freeing":
			if len(l.OpenState) != 16 || l.OpenSequence < 1 || l.OpenSequence > 2 || e.State == "closing" && (i.Phase != "close" || x.Active != l.Info.ID) {
				return errors.New("invalid offload OPEN state")
			}
			if (e.State == "locking" || e.State == "locked" || e.State == "unlocking" || e.State == "unlocked" || e.State == "freeing") && (len(l.LockOwner) != 16 || l.Info.Length != LockToEOF) {
				return errors.New("invalid owned verification lock")
			}
		case "closed", "unknown", "borrowed":
		default:
			return errors.New("invalid offload resource state")
		}
		if (e.State == "borrowed") != (len(e.BorrowedState) == 16) || e.State != "borrowed" && len(e.BorrowedState) != 0 {
			return errors.New("invalid borrowed offload state")
		}
		if e.State != "borrowed" && (len(i.Dir) == 0 || len(i.Dir) > 128 || i.Name == "" || len(i.Name) > 255 || bytes.ContainsAny([]byte(i.Name), "/\\\x00")) {
			return errors.New("invalid offload resource pathname")
		}
		if p != nil && n < len(p.Entries) {
			old := p.Entries[n]
			if old.Intent.Lock.Info != l.Info || !bytes.Equal(old.Intent.Lock.Handle, l.Handle) || !bytes.Equal(old.Intent.Lock.OpenOwner, l.OpenOwner) || !bytes.Equal(old.Intent.Lock.LockOwner, l.LockOwner) || !bytes.Equal(old.Intent.Dir, i.Dir) || old.Intent.Name != i.Name {
				return errors.New("offload resource binding changed")
			}
			if (old.State == "closed" || old.State == "borrowed" || old.State == "unknown") && !reflect.DeepEqual(old, e) {
				return errors.New("terminal offload resource changed")
			}
			if len(old.Intent.Lock.OpenState) != 0 && !bytes.Equal(old.Intent.Lock.OpenState, l.OpenState) {
				return errors.New("offload OPEN stateid changed")
			}
			if old.State != e.State {
				allowed := map[string][]string{"opening": {"open", "closed", "unknown"}, "open": {"closing", "locking"}, "closing": {"closed", "unknown"}, "locking": {"locked", "open", "unknown"}, "locked": {"unlocking"}, "unlocking": {"unlocked", "unknown"}, "unlocked": {"freeing"}, "freeing": {"open", "unknown"}}
				valid := false
				for _, state := range allowed[old.State] {
					if e.State == state {
						valid = true
					}
				}
				unsent := previous.Recovery != nil && previous.Recovery.Request == nil && r.Recovery != nil && r.Recovery.Request == nil && previous.Recovery.Session.Sequence == r.Recovery.Session.Sequence && p.Active == l.Info.ID && x.Active == 0 && unsentResourceState(old.State) == e.State
				if !valid && !unsent {
					return errors.New("invalid offload resource transition")
				}
				if old.State == "opening" || old.State == "closing" || old.State == "locking" || old.State == "unlocking" || old.State == "freeing" {
					if !unsent && (previous.Recovery == nil || previous.Recovery.Request == nil || r.Recovery == nil || r.Recovery.Request != nil || r.Recovery.Session.Sequence != previous.Recovery.Session.Sequence+1) {
						return errors.New("resource completion lacks consumed durable request")
					}
				}
			}
			if len(old.Intent.Lock.LockState) != 0 && !bytes.Equal(old.Intent.Lock.LockState, l.LockState) && (old.State != "unlocking" || e.State != "unlocked" || !bytes.Equal(old.Intent.Lock.LockState[4:], l.LockState[4:])) {
				return errors.New("owned lock identity changed")
			}
		}
	}
	return nil
}

func activeOffloadResource(r *OffloadRecord) *OffloadResource {
	if r.Resources == nil || r.Resources.Active == 0 || r.Resources.Active > uint64(len(r.Resources.Entries)) {
		return nil
	}
	return &r.Resources.Entries[r.Resources.Active-1]
}

func resourceRequestMatches(r OffloadRecord, s SavedCompound) bool {
	e := activeOffloadResource(&r)
	if e == nil {
		return false
	}
	i := e.Intent
	ops := intentOps(safeOffloadClientID(r), &i)
	if len(ops) != len(s.Operations) {
		return false
	}
	for n, op := range ops {
		if op.code != s.Operations[n].Code || !bytes.Equal(op.args, s.Operations[n].Args) {
			return false
		}
	}
	return true
}

func safeOffloadClientID(r OffloadRecord) uint64 {
	if r.Recovery == nil {
		return 0
	}
	return r.Recovery.Session.ClientID
}

func (v *v4Client) offloadOpenIO(ctx context.Context, fh []byte, share uint32) ([]byte, func() error, error) {
	var j *offloadJournal
	if tracked, ok := ctx.Value(offloadResourceContextKey{}).(offloadResourceContext); ok && tracked.v == v {
		j = tracked.journal
	} else if v.recall != nil {
		v.recall.mu.Lock()
		if v.recall.offload != nil {
			j = v.recall.offload.journal
			if j != nil && j.record.Resources == nil {
				j = nil
			}
		}
		v.recall.mu.Unlock()
	}
	if j == nil {
		return v.openIO(ctx, fh, share)
	}
	if err := v.checkLockedIO(fh, share); err != nil {
		return nil, nil, err
	}
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil {
		return nil, nil, err
	}
	var lockOwner [16]byte
	if _, err := rand.Read(lockOwner[:]); err != nil {
		return nil, nil, err
	}
	entry := OffloadResource{State: "opening", Intent: savedLockIntent{Phase: "open", Lock: savedLock{Handle: bytes.Clone(fh), OpenOwner: owner[:], LockOwner: lockOwner[:], Info: LockInfo{Write: share != 1, Length: LockToEOF}}}}
	var borrowed []byte
	if l := v.lockFor(fh); l != nil {
		entry.State = "borrowed"
		borrowed = bytes.Clone(l.sid)
		entry.BorrowedState = bytes.Clone(l.sid)
	} else {
		p, ok := v.parents[string(fh)]
		if !ok {
			return nil, nil, errors.New("offload OPEN requires a resolved pathname")
		}
		entry.Intent.Dir, entry.Intent.Name = bytes.Clone(p.dir), p.name
	}
	v.mu.Lock()
	if j.guard != nil {
		j.guard.Lock()
	}
	r := j.record
	r.Resources = cloneOffloadResources(r.Resources)
	entry.Intent.Lock.Info.ID = uint64(len(r.Resources.Entries) + 1)
	id := entry.Intent.Lock.Info.ID
	if r.Resources.Active != 0 {
		if j.guard != nil {
			j.guard.Unlock()
		}
		v.mu.Unlock()
		return nil, nil, errors.New("offload resource request already pending")
	}
	r.Resources.Entries = append(r.Resources.Entries, entry)
	if entry.State != "borrowed" {
		r.Resources.Active = id
	}
	err := j.append(r)
	if j.guard != nil {
		j.guard.Unlock()
	}
	v.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	if borrowed != nil {
		return borrowed, func() error { return v.checkLockedIO(fh, share) }, nil
	}
	i := entry.Intent
	if err := v.compound(ctx, intentOps(v.clientID, &i)...); err != nil {
		return nil, nil, err
	}
	return bytes.Clone(i.Lock.OpenState), func() error { return v.closeOffloadResource(context.Background(), j, id) }, nil
}

func validateOffloadOwnedStateids(r OffloadRecord, s SavedCompound) error {
	if r.Resources == nil {
		return nil
	}
	has := func(fh, sid []byte, write bool) bool {
		for _, e := range r.Resources.Entries {
			if bytes.Equal(e.Intent.Lock.Handle, fh) && (!write || e.Intent.Lock.Info.Write) && (e.State == "open" && bytes.Equal(e.Intent.Lock.OpenState, sid) || e.State == "borrowed" && bytes.Equal(e.BorrowedState, sid)) {
				return true
			}
		}
		return false
	}
	for _, op := range s.Operations {
		switch op.Code {
		case 61:
			if len(op.Args) < 16 || !has(r.Source, op.Args[:16], false) {
				return errors.New("COPY_NOTIFY lacks inventoried source state")
			}
		case 70:
			if len(op.Args) < 16 || !has(r.Destination, op.Args[:16], true) {
				return errors.New("WRITE_SAME lacks inventoried state ownership")
			}
		case 60, 71:
			if len(op.Args) < 32 || !has(r.Destination, op.Args[16:32], true) {
				return errors.New("COPY destination lacks inventoried state ownership")
			}
			if r.Operation == "copyfrom" {
				if r.SourceGrant == nil || !bytes.Equal(op.Args[:16], r.SourceGrant.ID) {
					return errors.New("COPY source grant differs from durable authorization")
				}
			} else if !has(r.Source, op.Args[:16], false) {
				return errors.New("COPY source lacks inventoried state ownership")
			}
		}
	}
	return nil
}

func (v *v4Client) closeOffloadResource(ctx context.Context, j *offloadJournal, id uint64) error {
	v.mu.Lock()
	if j.guard != nil {
		j.guard.Lock()
	}
	r := j.record
	r.Resources = cloneOffloadResources(r.Resources)
	e := &r.Resources.Entries[id-1]
	if e.State == "closed" || e.State == "borrowed" {
		if j.guard != nil {
			j.guard.Unlock()
		}
		v.mu.Unlock()
		return nil
	}
	if e.State != "open" || r.Resources.Active != 0 || v.stateLost.Load() {
		if j.guard != nil {
			j.guard.Unlock()
		}
		v.mu.Unlock()
		return errors.New("offload OPEN cleanup lacks confirmed ownership")
	}
	e.State, e.Intent.Phase, r.Resources.Active = "closing", "close", id
	i := e.Intent
	err := j.append(r)
	if j.guard != nil {
		j.guard.Unlock()
	}
	v.mu.Unlock()
	if err != nil {
		return err
	}
	return v.compound(ctx, intentOps(v.clientID, &i)...)
}

func (v *v4Client) cleanupOffloadResources(ctx context.Context, j *offloadJournal) error {
	if err := j.cancelUnsentResource(); err != nil {
		return err
	}
	if j.record.Resources == nil {
		return nil
	}
	if j.record.Resources.Active != 0 {
		return errors.New("offload resource request remains pending")
	}
	installRecoveryJournal(v, j)
	for n, e := range j.record.Resources.Entries {
		if e.State == "unknown" || e.State == "opening" || e.State == "closing" {
			return fmt.Errorf("offload resource %d remains unverified", n+1)
		}
		if e.State == "locked" {
			if err := v.offloadResourceTransition(ctx, j, uint64(n+1), "unlock", "unlocking"); err != nil {
				return err
			}
		}
		e = j.record.Resources.Entries[n]
		if e.State == "unlocked" {
			for id, l := range v.locks {
				if bytes.Equal(l.file.owner, e.Intent.Lock.OpenOwner) {
					delete(v.locks, id)
				}
			}
			if err := v.offloadResourceTransition(ctx, j, uint64(n+1), "free", "freeing"); err != nil {
				return err
			}
		}
		e = j.record.Resources.Entries[n]
		if e.State == "open" {
			if err := v.closeOffloadResource(ctx, j, uint64(n+1)); err != nil {
				return err
			}
		}
	}
	return nil
}

func unsentResourceState(state string) string {
	switch state {
	case "opening":
		return "closed"
	case "closing", "locking":
		return "open"
	case "unlocking":
		return "locked"
	case "freeing":
		return "unlocked"
	}
	return ""
}

// The mandatory beforeCached append is the send barrier. An active intent
// without a saved request was never transmitted, even across a process crash.
func (j *offloadJournal) cancelUnsentResource() error {
	r := j.record
	if r.Resources == nil || r.Resources.Active == 0 || r.Recovery == nil || r.Recovery.Request != nil {
		return nil
	}
	r.Resources = cloneOffloadResources(r.Resources)
	e := activeOffloadResource(&r)
	state := unsentResourceState(e.State)
	if state == "" {
		return errors.New("invalid unsent resource intent")
	}
	e.State, r.Resources.Active = state, 0
	return j.append(r)
}

func (v *v4Client) offloadResourceTransition(ctx context.Context, j *offloadJournal, id uint64, phase, state string) error {
	v.mu.Lock()
	if j.guard != nil {
		j.guard.Lock()
	}
	r := j.record
	r.Resources = cloneOffloadResources(r.Resources)
	if r.Resources.Active != 0 || v.stateLost.Load() {
		if j.guard != nil {
			j.guard.Unlock()
		}
		v.mu.Unlock()
		return ErrLockUncertain
	}
	e := &r.Resources.Entries[id-1]
	e.Intent.Phase, e.State, r.Resources.Active = phase, state, id
	i := e.Intent
	err := j.append(r)
	if j.guard != nil {
		j.guard.Unlock()
	}
	v.mu.Unlock()
	if err != nil {
		return err
	}
	return v.compound(ctx, intentOps(v.clientID, &i)...)
}

func (v *v4Client) ownedOffloadReadLock(ctx context.Context, j *offloadJournal, fh []byte) (uint64, error) {
	if _, _, err := v.offloadOpenIO(ctx, fh, 1); err != nil {
		return 0, err
	}
	id := uint64(len(j.record.Resources.Entries))
	if err := v.offloadResourceTransition(ctx, j, id, "lock", "locking"); err != nil {
		return 0, errors.Join(err, v.cleanupOffloadResources(context.Background(), j))
	}
	l := j.record.Resources.Entries[id-1].Intent.Lock
	if v.locks == nil {
		v.locks = make(map[uint64]*v4Lock)
	}
	v.locks[id] = &v4Lock{info: l.Info, sid: bytes.Clone(l.LockState), owner: bytes.Clone(l.LockOwner), file: &v4Open{fh: bytes.Clone(l.Handle), sid: bytes.Clone(l.OpenState), owner: bytes.Clone(l.OpenOwner), seq: l.OpenSequence, auth: v.c.Auth}}
	return id, nil
}
