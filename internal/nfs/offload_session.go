package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// OffloadSessionEvidence preserves the original session's slot and data result.
// It contains no GSS keys. Request arguments can contain WRITE_SAME patterns.
type OffloadSessionEvidence struct {
	Profile      string
	Session      SavedSession
	Request      *SavedCompound     `json:",omitempty"`
	Result       *OffloadCompletion `json:",omitempty"`
	Committed    bool
	Quiescent    bool
	Verified     bool
	DataIssued   bool            `json:",omitempty"`
	NotifyIssued bool            `json:",omitempty"`
	Failure      *OffloadFailure `json:",omitempty"`
	// "confirmed" requires every operation-owned resource to be released;
	// legacy records without an ownership inventory remain "unverified".
	StateCleanup string `json:",omitempty"`
}

type OffloadFailure struct{ Operation, Status uint32 }

type OffloadCompletion struct {
	ID       []byte `json:",omitempty"`
	Count    uint64
	Stable   uint32
	Verifier []byte `json:",omitempty"`
	Status   Status
	Complete bool
}

func validateOffloadSession(r, previous OffloadRecord) error {
	x := r.Recovery
	if x == nil {
		if previous.Pending && previous.ID == r.ID && previous.Recovery != nil {
			return errors.New("offload session evidence was removed")
		}
		return nil
	}
	if len(x.Profile) != 64 || x.Session.Validate() != nil || x.Session.Minor != 2 {
		return errors.New("invalid offload recovery session")
	}
	if x.Request != nil && (x.Request.Validate() != nil || x.Request.Sequence != x.Session.Sequence || !bytes.Equal(x.Request.Session, x.Session.Session)) {
		return errors.New("offload request differs from saved session")
	}
	if x.Request != nil {
		if x.Request.Auth.UID != x.Session.Auth.UID || x.Request.Auth.GID != x.Session.Auth.GID || !slices.Equal(x.Request.Auth.Groups, x.Session.Auth.Groups) {
			return errors.New("offload request credentials changed")
		}
		if err := validateOffloadRequest(r, *x.Request); err != nil {
			return err
		}
	}
	if x.Result != nil {
		p := x.Result
		if p.Count > r.Length || p.Stable > 2 || len(p.ID) != 0 && len(p.ID) != 16 || len(p.Verifier) != 0 && len(p.Verifier) != 8 {
			return errors.New("invalid offload completion evidence")
		}
	}
	if x.Committed && (x.Result == nil || !x.Result.Complete || x.Result.Status != 0 || x.Result.Count != r.Length) {
		return errors.New("offload durability lacks completion")
	}
	if x.Quiescent && (x.Result == nil || !x.Result.Complete) || x.Verified && (!x.Quiescent || !x.Committed || r.Expectation == nil) {
		return errors.New("invalid verified offload evidence")
	}
	if x.StateCleanup != "" && x.StateCleanup != "unverified" && x.StateCleanup != "confirmed" {
		return errors.New("invalid offload original state cleanup evidence")
	}
	if (x.StateCleanup == "unverified") != (r.Outcome == "completed-data-state-unverified") {
		return errors.New("offload state disposition differs from terminal receipt")
	}
	if x.Failure != nil && (x.Failure.Status == 0 || x.Failure.Operation != 60 && x.Failure.Operation != 70 && x.Failure.Operation != 71 && x.Failure.Operation != 61 || !x.DataIssued && (x.Failure.Operation != 61 || r.Resources == nil || r.Resources.Role != "source") || x.Committed) {
		return errors.New("invalid offload operation failure")
	}
	if x.StateCleanup == "confirmed" && (!offloadResourcesReleased(r) || !sourceGrantClosed(r, time.Now()) || r.Pending && x.Failure == nil && (x.Result == nil || !x.Result.Complete)) {
		return errors.New("offload cleanup lacks confirmed operation resource release")
	}
	if previous.Pending && previous.ID == r.ID && previous.Recovery != nil {
		p := previous.Recovery
		if p.DataIssued && !x.DataIssued || p.Failure != nil && (x.Failure == nil || *p.Failure != *x.Failure) {
			return errors.New("offload operation evidence removed")
		}
		if p.NotifyIssued && !x.NotifyIssued {
			return errors.New("source authorization issue evidence removed")
		}
		if p.StateCleanup != "" && p.StateCleanup != x.StateCleanup {
			return errors.New("offload original state disposition changed")
		}
		if p.Profile != x.Profile || !sameOffloadSessionIdentity(p.Session, x.Session) || x.Session.Confirmed.Before(p.Session.Confirmed) || p.Committed && !x.Committed || p.Quiescent && !x.Quiescent || p.Verified && !x.Verified {
			return errors.New("offload recovery identity or durable result changed")
		}
	}
	return nil
}

func sameOffloadSessionIdentity(a, b SavedSession) bool {
	return a.Minor == b.Minor && a.LeaseSeconds == b.LeaseSeconds && a.ReadSize == b.ReadSize && a.WriteSize == b.WriteSize && a.ClientID == b.ClientID && a.ServerMinor == b.ServerMinor && a.Channel == b.Channel && a.Auth.UID == b.Auth.UID && a.Auth.GID == b.Auth.GID && slices.Equal(a.Auth.Groups, b.Auth.Groups) && a.Identity == b.Identity && a.Principal == b.Principal && bytes.Equal(a.Nonce, b.Nonce) && bytes.Equal(a.Session, b.Session) && bytes.Equal(a.Root, b.Root) && bytes.Equal(a.Owner, b.Owner) && bytes.Equal(a.Scope, b.Scope)
}

func validateOffloadRequest(r OffloadRecord, s SavedCompound) error {
	if err := checkOffloadResourceRequest(r, s); err != nil {
		return err
	}
	if err := validateOffloadOwnedStateids(r, s); err != nil {
		return err
	}
	if resourceRequestMatches(r, s) {
		return nil
	}
	if r.Resources != nil && len(s.Operations) == 2 && s.Operations[0].Code == 22 {
		d := &decoder{b: s.Operations[0].Args}
		fh := d.opaque(128)
		if d.err == nil && len(d.b) == 0 && (bytes.Equal(fh, r.Source) || bytes.Equal(fh, r.Destination)) {
			op := s.Operations[1]
			if r.Operation == "copyfrom" && bytes.Equal(fh, r.Source) {
				if op.Code == 61 && len(op.Args) >= 24 {
					d = &decoder{b: op.Args[16:]}
					kind := d.u32()
					network, address := d.str(), d.str()
					endpoint, _ := universalEndpoint(network, address)
					if kind == 3 && endpoint != "" && d.err == nil && len(d.b) == 0 {
						return nil
					}
				}
				if op.Code == 66 && r.SourceGrant != nil && bytes.Equal(op.Args, r.SourceGrant.ID) {
					return nil
				}
			}
			if op.Code == 9 {
				d = &decoder{b: op.Args}
				readBitmap4(d)
				if d.err == nil && len(d.b) == 0 {
					return nil
				}
			}
			if op.Code == 25 && len(op.Args) == 28 {
				return nil
			}
		}
	}
	if len(s.Operations) == 0 {
		return nil
	} // Cacheable lease-only SEQUENCE.
	if len(s.Operations) != 2 && len(s.Operations) != 4 {
		return errors.New("invalid offload request shape")
	}
	file := func(op SavedCompoundOperation, fh []byte) bool {
		if op.Code != 22 {
			return false
		}
		d := &decoder{b: op.Args}
		return bytes.Equal(d.opaque(128), fh) && d.err == nil && len(d.b) == 0
	}
	op := s.Operations[len(s.Operations)-1]
	d := &decoder{b: op.Args}
	if len(s.Operations) == 4 {
		if !file(s.Operations[0], r.Source) || s.Operations[1].Code != 32 || len(s.Operations[1].Args) != 0 || !file(s.Operations[2], r.Destination) || (op.Code != 60 && op.Code != 71) {
			return errors.New("offload source/destination changed")
		}
		if op.Code == 71 && r.Operation != "clonerange" || op.Code == 60 && r.Operation != "copyrange" && r.Operation != "copyasync" && r.Operation != "copyfrom" {
			return errors.New("offload operation differs from intent")
		}
		d.take(32)
		if d.u64() != r.SourceOffset || d.u64() != r.Offset || d.u64() != r.Length {
			return errors.New("offload copy range differs from intent")
		}
		if op.Code == 60 {
			if !d.boolean() || d.boolean() != (r.Operation == "copyrange") {
				return errors.New("offload COPY requirements changed")
			}
			if r.Operation == "copyfrom" {
				d.take(len(d.b))
			} else if d.u32() != 0 {
				return errors.New("intra-server COPY gained external source")
			}
		}
	} else {
		if !file(s.Operations[0], r.Destination) && !(op.Code == 4 && file(s.Operations[0], r.Source)) {
			return errors.New("offload request handle differs from intent")
		}
		switch op.Code {
		case 4:
			d.take(20)
		case 5:
			if d.u64() != r.Offset || d.u32() != 0 {
				return errors.New("offload COMMIT range changed")
			}
		case 66, 67:
			id := d.take(16)
			if !bytes.Equal(id, r.CallbackID) && (r.Recovery.Result == nil || !bytes.Equal(id, r.Recovery.Result.ID)) {
				return errors.New("offload status/cancellation identity changed")
			}
		case 70:
			if r.Operation != "writesame" {
				return errors.New("WRITE_SAME differs from intent")
			}
			d.take(16)
			if d.u32() != 2 {
				return errors.New("WRITE_SAME stability changed")
			}
			b := ApplicationDataBlock{Offset: d.u64(), BlockSize: d.u64(), BlockCount: d.u64()}
			b.NumberOffset = d.u64()
			first := d.u32()
			if b.NumberOffset == ^uint64(0) {
				b.NumberOffset = 0
				if first != 0 {
					return errors.New("unused ADB number changed")
				}
			} else {
				b.FirstNumber = &first
			}
			b.PatternOffset = d.u64()
			b.Pattern = d.opaque(4096)
			if b.PatternOffset == ^uint64(0) {
				b.PatternOffset = 0
				if len(b.Pattern) != 0 {
					return errors.New("unused ADB pattern changed")
				}
			}
			length, err := ValidateApplicationDataBlock(b)
			if err != nil || b.Offset != r.Offset || length != r.Length {
				return errors.New("WRITE_SAME range differs from intent")
			}
		default:
			return errors.New("unexpected operation in offload recovery")
		}
	}
	if d.err != nil || len(d.b) != 0 {
		return errors.New("malformed saved offload arguments")
	}
	return nil
}

func cloneOffloadSession(x *OffloadSessionEvidence) *OffloadSessionEvidence {
	if x == nil {
		return nil
	}
	y := *x
	if x.Result != nil {
		p := *x.Result
		y.Result = &p
	}
	return &y
}

// Called under the callback mutex, before acknowledging CB_OFFLOAD. A crash
// after acknowledgement must never lose the only final durability verifier.
func (j *offloadJournal) recordCallback(reply *offloadReply) error {
	if j.record.Recovery == nil {
		return nil
	}
	r := j.record
	r.Recovery = cloneOffloadSession(r.Recovery)
	id := bytes.Clone(r.CallbackID)
	if len(id) == 0 && r.Recovery.Result != nil {
		id = bytes.Clone(r.Recovery.Result.ID)
	}
	r.Recovery.Result = &OffloadCompletion{ID: id, Count: reply.count, Stable: reply.stable, Verifier: bytes.Clone(reply.verifier), Status: reply.status, Complete: true}
	r.Recovery.Committed = reply.status == 0 && reply.count == r.Length && reply.stable == 2
	return j.append(r)
}

func offloadRecoveryProfile(cfg Config) (string, error) {
	cfg.Offload = false
	return lockProfile(cfg)
}

// installOffloadRecovery is called before any offload request. Hooks are scoped
// to this operation and serialize with the original session's slot mutex.
func (v *v4Client) installOffloadRecovery(j *offloadJournal) (func(), error) {
	if j == nil || v.c.config == nil || !v.c.config.OffloadSessionRecovery && j.parent == nil {
		return func() {}, nil
	}
	profile, err := offloadRecoveryProfile(*v.c.config)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if j.guard == nil && v.recall != nil {
		j.guard = &v.recall.mu
	}
	oldBefore, oldAfter, oldError := v.beforeCached, v.afterCached, v.afterCachedError
	oldRequired := v.requireCached
	v.requireCached = true
	v.beforeCached = func(s SavedCompound) error {
		if oldBefore != nil {
			if err := oldBefore(s); err != nil {
				return err
			}
		}
		if j.guard != nil {
			j.guard.Lock()
			defer j.guard.Unlock()
		}
		// OPEN setup precedes the issued marker. Its result is not a data
		// mutation; the original lease bounds any orphaned OPEN resources.
		if j.record.Phase != "issued" && j.record.Resources == nil {
			return nil
		}
		j.attemptDigest, j.attemptStarted = s.Digest, time.Now()
		session, err := v.saveSession()
		if err != nil {
			return err
		}
		r := j.record
		r.Recovery = cloneOffloadSession(r.Recovery)
		if r.Recovery == nil {
			r.Recovery = &OffloadSessionEvidence{Profile: profile}
		}
		r.Recovery.Session, r.Recovery.Request = session, &s
		markOffloadDataRequest(r.Recovery, s)
		return j.append(r)
	}
	v.afterCached = func(s SavedCompound, body []byte) error {
		if oldAfter != nil {
			if err := oldAfter(s, body); err != nil {
				return err
			}
		}
		if j.guard != nil {
			j.guard.Lock()
			defer j.guard.Unlock()
		}
		if j.record.Recovery == nil {
			return nil
		}
		return v.recordOffloadResponse(j, s, body)
	}
	v.afterCachedError = func(s SavedCompound, body []byte) error {
		if oldError != nil {
			if err := oldError(s, body); err != nil {
				return err
			}
		}
		if j.guard != nil {
			j.guard.Lock()
			defer j.guard.Unlock()
		}
		if j.record.Resources == nil {
			return nil
		}
		return v.recordOffloadResponse(j, s, body)
	}
	return func() {
		v.mu.Lock()
		v.beforeCached, v.afterCached = oldBefore, oldAfter
		v.afterCachedError = oldError
		v.requireCached = oldRequired
		v.mu.Unlock()
	}, nil
}

func (v *v4Client) recordOffloadResponse(j *offloadJournal, s SavedCompound, body []byte) error {
	r := j.record
	r.Recovery = cloneOffloadSession(r.Recovery)
	r.Resources = cloneOffloadResources(r.Resources)
	if r.Recovery.Request == nil || r.Recovery.Request.Digest != s.Digest {
		return errors.New("offload response has no matching durable request")
	}
	if err := consumeOffloadResponse(&r, s, body); err != nil {
		return err
	}
	// A successful SEQUENCE renews the lease. Use the attempt's start rather
	// than receipt time, excluding server/network/fsync latency conservatively.
	if j.attemptDigest == s.Digest && !j.attemptStarted.IsZero() && !v.stateLost.Load() && !v.leaseMoved.Load() && !v.reclaimForbidden.Load() {
		started := j.attemptStarted
		if previous := v.lastLease.Load(); previous == nil || started.After(*previous) {
			v.lastLease.Store(&started)
		}
	}
	session, err := v.saveSession()
	if err != nil {
		return err
	}
	r.Recovery.Session, r.Recovery.Request = session, nil
	return j.append(r)
}

// Both live journaling and recovery use this independent response parser. The
// normal compound decoder has already checked operation status and sequencing.
func consumeOffloadResponse(r *OffloadRecord, s SavedCompound, body []byte) error {
	if err := checkOffloadResourceRequest(*r, s); err != nil {
		return err
	}
	resourceMatch := resourceRequestMatches(*r, s)
	d := &decoder{b: body}
	status := d.u32()
	d.str()
	count := d.u32()
	if count < 1 || count > uint32(len(s.Operations)+1) || status == 0 && count != uint32(len(s.Operations)+1) || d.u32() != 53 || d.u32() != 0 || !bytes.Equal(d.take(16), s.Session) || d.u32() != s.Sequence {
		return errors.New("offload recovery reply sequence mismatch")
	}
	d.take(16) // slot, highest slot, target highest slot, status flags
	for n, op := range s.Operations[:count-1] {
		if d.u32() != op.Code {
			return errors.New("offload recovery operation mismatch")
		}
		failure := d.u32()
		if failure != 0 {
			if status != failure || uint32(n+2) != count {
				return errors.New("inconsistent offload operation failure")
			}
			if op.Code == 60 && failure == 10094 {
				d.boolean()
				d.boolean()
			}
			if op.Code == 12 && failure == 10010 {
				d.u64()
				d.u64()
				d.u32()
				d.u64()
				d.opaque(1024)
			}
			if op.Code == 60 || op.Code == 70 || op.Code == 71 || op.Code == 61 {
				r.Recovery.Failure = &OffloadFailure{Operation: op.Code, Status: failure}
			}
			if e := activeOffloadResource(r); e != nil {
				for _, want := range intentOps(safeOffloadClientID(*r), &e.Intent) {
					if want.code == op.Code && want.result != nil {
						want.result(Status(failure))
					}
				}
			}
			break
		}
		decode := offloadRecoveryDecoder(r, op)
		if decode == nil {
			return fmt.Errorf("offload recovery cannot decode operation %d", op.Code)
		}
		decode(d)
		if d.err != nil {
			return d.err
		}
	}
	if d.err != nil || len(d.b) != 0 {
		return errors.New("malformed offload recovery reply")
	}
	if e := activeOffloadResource(r); e != nil && resourceMatch {
		if status == 0 {
			switch e.Intent.Phase {
			case "open", "free":
				e.State = "open"
			case "lock":
				e.State = "locked"
			case "unlock":
				e.State = "unlocked"
			case "close":
				e.State = "closed"
			}
		} else if e.Intent.Phase == "open" && len(e.Intent.Lock.OpenState) == 0 {
			e.State = "closed"
		} else if e.Intent.Phase == "lock" && len(e.Intent.Lock.LockState) == 0 {
			e.State = "open"
		} else {
			e.State = "unknown"
		}
		r.Resources.Active = 0
	}
	return nil
}

func offloadRecoveryDecoder(r *OffloadRecord, op SavedCompoundOperation) func(*decoder) {
	if e := activeOffloadResource(r); e != nil {
		for _, want := range intentOps(safeOffloadClientID(*r), &e.Intent) {
			if want.code == op.Code {
				return func(d *decoder) {
					if want.result != nil {
						want.result(0)
					}
					if want.decode != nil {
						want.decode(d)
					}
				}
			}
		}
	}
	x := r.Recovery
	switch op.Code {
	case 61:
		return func(d *decoder) {
			g := decodeCopyGrant(d, time.Now())
			if d.err == nil {
				r.SourceGrant = &OffloadSourceGrant{ID: bytes.Clone(g.id), Recorded: g.recorded, Expires: g.proofExpires}
			}
		}
	case 9:
		return func(d *decoder) { readBitmap4(d); d.opaque(1 << 20) }
	case 25:
		return func(d *decoder) { d.boolean(); d.opaque(1 << 20) }
	case 22, 32:
		return func(*decoder) {} // PUTFH, SAVEFH
	case 4:
		return func(d *decoder) { d.take(16) } // CLOSE
	case 5:
		return func(d *decoder) {
			verifier := d.take(8)
			if r.Resources != nil && r.Resources.Role == "verification" {
				return
			}
			if x.Result == nil || !x.Result.Complete || x.Result.Status != 0 || !bytes.Equal(verifier, x.Result.Verifier) {
				d.err = errors.New("offload COMMIT lacks matching completion verifier")
				return
			}
			x.Committed = x.Result.Count == r.Length
		}
	case 60, 70:
		return func(d *decoder) {
			p := decodeOffloadReply(d)
			if op.Code == 70 && len(p.id) != 0 && (len(op.Args) < 16 || !bytes.Equal(p.id, op.Args[:16])) {
				d.err = errors.New("recovered WRITE_SAME callback identity changed")
			}
			if op.Code == 60 && r.Operation == "copyrange" && len(p.id) != 0 {
				d.err = errors.New("synchronous COPY returned asynchronous state")
			}
			if op.Code == 60 {
				consecutive, synchronous := d.boolean(), d.boolean()
				if !consecutive || synchronous != (len(p.id) == 0) {
					d.err = errors.New("invalid recovered COPY result")
				}
			}
			if p.count > r.Length {
				d.err = errors.New("recovered offload count exceeds intent")
			}
			if x.Result != nil && x.Result.Complete {
				if len(p.id) == 0 || len(x.Result.ID) == 0 || !bytes.Equal(p.id, x.Result.ID) {
					d.err = errors.New("offload callback and forechannel identities conflict")
				}
				return // An authenticated, persisted final callback is authoritative.
			}
			x.Result = &OffloadCompletion{ID: bytes.Clone(p.id), Count: p.count, Stable: p.stable, Verifier: bytes.Clone(p.verifier), Complete: len(p.id) == 0}
			x.Committed = len(p.id) == 0 && p.count == r.Length && p.stable == 2
		}
	case 71:
		return func(*decoder) {
			x.Result = &OffloadCompletion{Count: r.Length, Stable: 2, Complete: true}
			x.Committed = true
		}
	case 67:
		return func(d *decoder) {
			count, n := d.u64(), d.u32()
			if n > 1 || count > r.Length {
				d.err = errors.New("invalid recovered OFFLOAD_STATUS")
				return
			}
			if n == 1 {
				status := Status(d.u32())
				if x.Result == nil {
					d.err = errors.New("OFFLOAD_STATUS lacks original result")
					return
				}
				// STATUS proves quiescence but carries no durability verifier.
				// Keep a previously persisted CB_OFFLOAD receipt when available.
				if !x.Result.Complete {
					x.Result.Count = count
					x.Result.Status = status
					x.Result.Complete = true
					x.Quiescent = true
				}
			}
		}
	case 66:
		return func(*decoder) {
			if r.SourceGrant != nil && bytes.Equal(op.Args, r.SourceGrant.ID) {
				g := *r.SourceGrant
				g.Revoked = true
				r.SourceGrant = &g
			}
		} // Cancellation is never copy success.
	}
	return nil
}

// RecoverOffload binds the original protected session and retrieves its exact
// cached request result. It never creates a replacement COPY or WRITE_SAME.
func RecoverOffload(ctx context.Context, cfg Config, path, id string) (OffloadRecord, error) {
	j, err := loadOffloadJournal(path, false)
	if err != nil {
		return OffloadRecord{}, err
	}
	defer j.file.Close()
	r := j.record
	profile, err := offloadRecoveryProfile(cfg)
	if err != nil {
		return r, err
	}
	if !r.Pending || r.ID != id || r.Recovery == nil || r.Recovery.Profile != profile {
		return r, errors.New("offload recovery needs matching pending operation and protected profile")
	}
	if err := j.cancelUnsentResource(); err != nil {
		return j.record, err
	}
	r = j.record
	x := r.Recovery
	if r.Phase == "prepared" && offloadResourcesReleased(r) && x.Request == nil && sourceGrantClosed(r, time.Now()) {
		pending := false
		for _, e := range r.Endpoints {
			if e.Recovery != nil && e.Recovery.Request != nil {
				pending = true
			}
		}
		if !pending {
			r.Recovery = cloneOffloadSession(x)
			r.Recovery.StateCleanup = "confirmed"
			r.Pending, r.Outcome, r.Error = false, "not-issued", ""
			err = j.append(r)
			return j.record, err
		}
	}
	if x.Quiescent && !x.Committed && x.Request == nil && x.Result != nil && x.Result.Status == 0 && x.Result.Count == r.Length && (r.Resources == nil || offloadOwnResourcesReleased(r)) {
		return finishVerifiedOffload(ctx, cfg, j)
	}
	if r.Operation == "copyfrom" && cfg.Kerberos.RPCVersion == 3 && offloadRequestUsesChild(x.Request) {
		return r, errors.New("secure inter-server request requires its original GSS privilege; keep quarantined")
	}
	c, err := connectSavedSession(ctx, cfg, x.Session)
	if err != nil {
		return r, err
	}
	defer c.Close()
	v := c.v4
	if err := v.replayOffloadRequest(ctx, j); err != nil {
		return j.record, err
	}
	if j.record.Phase == "prepared" {
		if err := v.cleanupOffloadResources(ctx, j); err != nil {
			return j.record, err
		}
		if err := recoverOffloadEndpoint(ctx, j, "source"); err != nil {
			return j.record, err
		}
		if !offloadResourcesReleased(j.record) || !sourceGrantClosed(j.record, time.Now()) {
			return j.record, errors.New("prepared offload has unverified original resources")
		}
		r = j.record
		r.Recovery = cloneOffloadSession(r.Recovery)
		r.Recovery.StateCleanup = "confirmed"
		r.Pending, r.Outcome, r.Error = false, "not-issued", ""
		return r, j.append(r)
	}
	if x = j.record.Recovery; r.Resources != nil && (!x.DataIssued && x.Result == nil || x.Failure != nil) {
		if err := v.cleanupOffloadResources(ctx, j); err != nil {
			return j.record, err
		}
		if err := recoverOffloadEndpoint(ctx, j, "source"); err != nil {
			return j.record, err
		}
		r = j.record
		if !offloadResourcesReleased(r) || !sourceGrantClosed(r, time.Now()) {
			return r, errors.New("offload cleanup remains unverified")
		}
		r.Recovery = cloneOffloadSession(r.Recovery)
		r.Recovery.StateCleanup = "confirmed"
		if x.Failure == nil {
			r.Pending, r.Outcome, r.Error = false, "not-issued", ""
			err = j.append(r)
			return j.record, err
		}
		r.Outcome = "unverified"
		r.Error = "server rejected the offload data operation; owned state was released"
		if err := j.append(r); err != nil {
			return j.record, err
		}
		return j.record, Status(x.Failure.Status)
	}
	// A saved callback can finish an asynchronous operation even when the
	// process died before acknowledging it. No server-side status guess is used.
	x = j.record.Recovery
	if x.Result != nil && !x.Result.Complete {
		if err := pollRecoveredOffload(ctx, v, j); err != nil {
			return j.record, err
		}
		x = j.record.Recovery
	}
	if x.Quiescent && !x.Committed && x.Result != nil && x.Result.Status == 0 && x.Result.Count == r.Length {
		if err := v.cleanupOffloadResources(ctx, j); err != nil {
			return j.record, err
		}
		return finishVerifiedOffload(ctx, cfg, j)
	}
	if x.Result == nil || !x.Result.Complete {
		return j.record, errors.New("offload result remains asynchronous; final callback evidence unavailable")
	}
	if x.Result.Status != 0 || x.Result.Count != r.Length {
		if err := v.cleanupOffloadResources(ctx, j); err != nil {
			return j.record, err
		}
		if err := recoverOffloadEndpoint(ctx, j, "source"); err != nil {
			return j.record, err
		}
		r = j.record
		if offloadResourcesReleased(r) && sourceGrantClosed(r, time.Now()) {
			r.Recovery = cloneOffloadSession(r.Recovery)
			r.Recovery.StateCleanup = "confirmed"
			r.Outcome = "unverified"
			r.Error = "offload completed partially or failed; owned state released; destination requires verification"
			if err := j.append(r); err != nil {
				return j.record, err
			}
		}
		return j.record, errors.New("offload completed partially or failed; destination requires verification")
	}
	if !x.Committed {
		var e encoder
		e.u64(r.Offset)
		e.u32(0)
		installRecoveryJournal(v, j)
		var verifier []byte
		if err = v.compound(ctx, fh4(r.Destination), op4(5, e, func(d *decoder) { verifier = bytes.Clone(d.take(8)) })); err != nil {
			return j.record, err
		}
		if !bytes.Equal(verifier, x.Result.Verifier) {
			return j.record, errors.New("recovered offload COMMIT verifier changed")
		}
	}
	if err := v.cleanupOffloadResources(ctx, j); err != nil {
		return j.record, err
	}
	if err := recoverOffloadEndpoint(ctx, j, "source"); err != nil {
		return j.record, err
	}
	r = j.record
	if !sourceGrantClosed(r, time.Now()) {
		return r, errors.New("source COPY authorization has not been confirmed revoked or expired")
	}
	r.Pending = false
	r.Recovery = cloneOffloadSession(r.Recovery)
	r.Recovery.StateCleanup = "unverified"
	r.Outcome = "completed-data-state-unverified"
	if offloadResourcesReleased(r) {
		r.Recovery.StateCleanup, r.Outcome = "confirmed", "completed"
	}
	r.Error = ""
	if err = j.append(r); err != nil {
		return j.record, err
	}
	return j.record, nil
}

func installRecoveryJournal(v *v4Client, j *offloadJournal) {
	v.requireCached = true
	v.beforeCached = func(s SavedCompound) error {
		j.attemptDigest, j.attemptStarted = s.Digest, time.Now()
		r := j.record
		r.Recovery = cloneOffloadSession(r.Recovery)
		session, err := v.saveSession()
		if err != nil {
			return err
		}
		r.Recovery.Session, r.Recovery.Request = session, &s
		markOffloadDataRequest(r.Recovery, s)
		return j.append(r)
	}
	v.afterCached = func(s SavedCompound, body []byte) error { return v.recordOffloadResponse(j, s, body) }
	v.afterCachedError = func(s SavedCompound, body []byte) error {
		if j.record.Resources == nil {
			return nil
		}
		return v.recordOffloadResponse(j, s, body)
	}
}

func pollRecoveredOffload(ctx context.Context, v *v4Client, j *offloadJournal) error {
	if !j.checkpoint {
		return errors.New("legacy offload log cannot sustain recoverable status polling; retain its evidence for explicit reconciliation")
	}
	if j.record.Expectation == nil {
		return errors.New("asynchronous recovery requires pre-issue expected content")
	}
	x := j.record.Recovery
	if x.Result == nil || len(x.Result.ID) != 16 {
		return errors.New("asynchronous recovery lacks a confirmed operation ID")
	}
	installRecoveryJournal(v, j)
	for {
		id := bytes.Clone(j.record.Recovery.Result.ID)
		if err := v.compound(ctx, fh4(j.record.Destination), op4(67, encoder(id), func(d *decoder) {
			count, n := d.u64(), d.u32()
			if n > 1 || count > j.record.Length {
				d.err = errors.New("invalid offload status bounds")
				return
			}
			if n == 1 {
				d.u32()
			}
		})); err != nil {
			return err
		}
		if j.record.Recovery.Result.Complete {
			return nil
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func finishVerifiedOffload(ctx context.Context, cfg Config, j *offloadJournal) (OffloadRecord, error) {
	if err := recoverOffloadEndpoint(ctx, j, "source"); err != nil {
		return j.record, err
	}
	r := j.record
	x := r.Recovery
	if !x.Quiescent || x.Request != nil || x.Result == nil || x.Result.Status != 0 || x.Result.Count != r.Length {
		return r, errors.New("offload did not confirm complete successful quiescence")
	}
	if !sourceGrantClosed(r, time.Now()) {
		return r, errors.New("source COPY authorization has not been confirmed revoked or expired")
	}
	cfg.Offload, cfg.OffloadReconcile, cfg.OffloadSessionRecovery, cfg.OffloadJournal = false, false, false, ""
	ctx, c, restore, err := connectOffloadVerifier(ctx, cfg, j)
	if err != nil {
		return r, err
	}
	defer c.Close()
	defer restore()
	if err := verifyOffloadExpectation(ctx, c, r); err != nil {
		return r, err
	}
	r = j.record
	r.Recovery = cloneOffloadSession(r.Recovery)
	r.Recovery.Verified, r.Recovery.Committed = true, true
	r.Recovery.StateCleanup = "unverified"
	r.Pending, r.Outcome, r.Error = false, "completed-data-state-unverified", ""
	if offloadResourcesReleased(r) {
		r.Recovery.StateCleanup, r.Outcome = "confirmed", "completed"
	}
	if err := j.append(r); err != nil {
		return j.record, err
	}
	return j.record, nil
}

func offloadRequestUsesChild(s *SavedCompound) bool {
	if s == nil {
		return false
	}
	for _, op := range s.Operations {
		switch op.Code {
		case 60, 61, 66, 67:
			return true
		}
	}
	return false
}

func markOffloadDataRequest(x *OffloadSessionEvidence, s SavedCompound) {
	for _, op := range s.Operations {
		if op.Code == 61 {
			x.NotifyIssued = true
		}
		if op.Code == 60 || op.Code == 70 || op.Code == 71 {
			x.DataIssued = true
		}
	}
}

func (v *v4Client) replayOffloadRequest(ctx context.Context, j *offloadJournal) error {
	r := j.record
	x := r.Recovery
	var err error
	if x.Request != nil {
		saved := *x.Request
		var ops []v4Op
		trial := r
		trial.Recovery = cloneOffloadSession(x)
		trial.Resources = cloneOffloadResources(r.Resources)
		for _, op := range saved.Operations {
			decode := offloadRecoveryDecoder(&trial, op)
			if decode == nil {
				return fmt.Errorf("saved offload operation %d is not recoverable", op.Code)
			}
			ops = append(ops, op4(op.Code, encoder(op.Args), decode))
		}
		installRecoveryJournal(v, j)
		if err = v.replaySavedCompound(ctx, saved, ops...); err != nil {
			return err
		}
		if v.stateLost.Load() || v.leaseMoved.Load() || v.reclaimForbidden.Load() {
			return ErrLockUncertain
		}
		v.afterCached = nil
	}

	return nil
}
