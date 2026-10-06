package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SEQUENCE status bits from RFC 8881, section 18.46.2.
const (
	seq4StatusCBPathDown              uint32 = 0x00000001
	seq4StatusCBGSSContextsExpiring   uint32 = 0x00000002
	seq4StatusCBGSSContextsExpired    uint32 = 0x00000004
	seq4StatusExpiredAllStateRevoked  uint32 = 0x00000008
	seq4StatusExpiredSomeStateRevoked uint32 = 0x00000010
	seq4StatusAdminStateRevoked       uint32 = 0x00000020
	seq4StatusRecallableStateRevoked  uint32 = 0x00000040
	seq4StatusLeaseMoved              uint32 = 0x00000080
	seq4StatusRestartReclaimNeeded    uint32 = 0x00000100
	seq4StatusCBPathDownSession       uint32 = 0x00000200
	seq4StatusBackchannelFault        uint32 = 0x00000400
	seq4StatusDeviceChanged           uint32 = 0x00000800
	seq4StatusDeviceDeleted           uint32 = 0x00001000

	seq4StatusRevoked           = seq4StatusExpiredAllStateRevoked | seq4StatusExpiredSomeStateRevoked | seq4StatusAdminStateRevoked | seq4StatusRecallableStateRevoked
	seq4StatusCallbackStateLost = seq4StatusCBPathDown | seq4StatusRevoked | seq4StatusLeaseMoved | seq4StatusRestartReclaimNeeded | seq4StatusCBPathDownSession | seq4StatusBackchannelFault | seq4StatusDeviceChanged | seq4StatusDeviceDeleted
)

// Ordinary operations use the metadata server. Explicit pNFS reads opt into
// file layouts and a bounded recall backchannel; delegations are not retained.
type v4Client struct {
	mu                    sync.Mutex
	c                     *Client
	minor                 uint32
	clientID              uint64
	session               []byte
	sequence              uint32
	maxReplyPayload       uint32
	maxRequestPayload     uint32
	channel               sessionChannelLimits
	statefulFailover      *StatefulFailoverStatus
	recoverStateful       bool
	recoverCached         func(context.Context, *v4ReplayRequest) (*rpcClient, func(bool), error)
	replayFrom            *v4ReplayRequest
	requireCached         bool                              // Durable observers must checkpoint every consumed slot, including renewal.
	beforeCached          func(SavedCompound) error         // Durable intent must be synced before send.
	afterCached           func(SavedCompound, []byte) error // Fully validated NFS result, before another RPC.
	afterCachedError      func(SavedCompound, []byte) error // Checked operation error after successful SEQUENCE.
	recoverEmpty          bool                              // Only an explicitly armed durable namespace can restore an empty inventory.
	sameIncarnation       bool                              // Unavailable-source failover requires an exact replica identity.
	recoverBindOnly       bool                              // Durable recovery must resolve its original slot before any new SEQUENCE.
	root                  []byte
	parents               map[string]v4Name
	stop                  context.CancelFunc
	done                  chan struct{}
	locks                 map[uint64]*v4Lock // foreground operations, like parents
	nextLock              uint64
	stateLost             atomic.Bool  // lease worker can invalidate held state
	leaseMoved            atomic.Bool  // Confirmed state requires an approved endpoint transition.
	journal               *lockJournal // Durable fixed inventory; mutations use explicit transactions.
	lockTracking          atomic.Bool
	clientNonce           []byte
	creates               *createSessionSequences
	serverIdentity        *createSessionKey // Retained only after confirmed session creation.
	serverMinor           uint64
	sharedSession         *v4Client // DS fore-channel aliases share the owner's slot and mutex.
	trunked               bool
	reclaiming            bool
	reclaimAttempted      bool // foreground API only; one attempt per old incarnation
	migrationAttempted    bool
	migrationFrom         *v4Client
	migrationBorrowed     bool // A validation failure must not destroy transferred state.
	leaseSeconds          uint32
	lastLease             atomic.Pointer[time.Time]
	reclaimForbidden      atomic.Bool
	exchangeRole          uint32
	recall                *layoutRecall
	callbackRenewalNeeded bool // guarded by mu; SEQUENCE reports expiring handles
}
type v4Name struct {
	dir  []byte
	name string
}

func (v *v4Client) remember(fh, dir []byte, name string) {
	// Every CLI transfer resolves its path immediately before opening. Keep
	// browsing from retaining an unbounded number of historical handles.
	if len(v.parents) >= 65536 {
		clear(v.parents)
	}
	v.parents[string(fh)] = v4Name{append([]byte(nil), dir...), name}
}

type v4Op struct {
	code                uint32
	args                encoder
	decode              func(*decoder)
	result              func(Status)
	failure             func(*decoder) // Optional strict operation-specific error body.
	revokedLayoutReturn bool           // Only disposal of a callback-confirmed revoked layout.
}

func op4(code uint32, args encoder, decode func(*decoder)) v4Op {
	return v4Op{code: code, args: args, decode: decode}
}
func fh4(fh []byte) v4Op { var e encoder; e.opaque(fh); return op4(22, e, nil) }
func bitmap4(e *encoder, bits ...uint32) {
	var words [3]uint32
	n := uint32(0)
	for _, bit := range bits {
		if bit < 96 {
			words[bit/32] |= 1 << (bit % 32)
			n = max(n, bit/32+1)
		}
	}
	e.u32(n)
	for _, word := range words[:n] {
		e.u32(word)
	}
}
func readBitmap4(d *decoder) []uint32 {
	n := d.u32()
	if n > 3 {
		d.err = errors.New("NFSv4 attribute bitmap exceeds 96 bits")
		return nil
	}
	bits := []uint32{}
	for i := uint32(0); i < n; i++ {
		w := d.u32()
		for b := uint32(0); b < 32; b++ {
			if w&(1<<b) != 0 {
				bits = append(bits, 32*i+b)
			}
		}
	}
	return bits
}
func skipChange4(d *decoder) { d.boolean(); d.u64(); d.u64() }

// Variable read replies can exceed the negotiated slot cache (Linux commonly
// offers 2128 bytes). Keep mutations and unknown operations cached. This only
// selects SEQUENCE cachethis; it does not retry failed or uncertain operations.
func cacheReply4(ops []v4Op) bool {
	variable := false
	for _, op := range ops {
		switch op.code {
		case 9, 25, 26, 27, 33, 47, 52, 68, 72, 74: // Variable read-only replies, including GETDEVICEINFO.
			variable = true
		case 3, 10, 15, 16, 22, 23, 24, 31, 32: // Read-only access/navigation
		default:
			return true
		}
	}
	return !variable
}

// RFC 8881 section 16.2.4 permits these errors without an operation result.
// Filesystem/state errors such as MOVED must identify the failing operation.
func emptyCompoundError4(status uint32) bool {
	switch status {
	case 22, 10006, 10008, 10021, 10036, 10040, 10065, 10066, 10067, 10070:
		// INVAL, SERVERFAULT, DELAY, MINOR_VERS_MISMATCH, BADXDR, BADCHAR,
		// REQ_TOO_BIG, REP_TOO_BIG, REP_TOO_BIG_TO_CACHE, TOO_MANY_OPS.
		return true
	}
	return false
}

func (v *v4Client) compound(ctx context.Context, ops ...v4Op) error {
	return v.compoundAuth(ctx, v.c.Auth, ops...)
}

func (v *v4Client) compoundAuth(ctx context.Context, auth Auth, ops ...v4Op) (resultErr error) {
	if v.sharedSession != nil {
		return v.sharedSession.compoundRPC(ctx, auth, v.c.nfs, ops...)
	}
	return v.compoundRPC(ctx, auth, nil, ops...)
}

func (v *v4Client) compoundRPC(ctx context.Context, auth Auth, rpc *rpcClient, ops ...v4Op) (resultErr error) {
	return v.compoundContext(ctx, auth, rpc, nil, ops...)
}

func (v *v4Client) compoundGSS(ctx context.Context, child *rpcGSS, ops ...v4Op) error {
	return v.compoundContext(ctx, v.c.Auth, nil, child, ops...)
}

func (v *v4Client) compoundContext(ctx context.Context, auth Auth, rpc *rpcClient, child *rpcGSS, ops ...v4Op) (resultErr error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if rpc == nil {
		rpc = v.c.nfs
	}
	if child == nil {
		var err error
		ctx, err = v.renewBackchannelLocked(ctx, auth, rpc)
		if err != nil {
			return err
		}
	}
	return v.compoundContextLocked(ctx, auth, rpc, child, ops...)
}

// The caller owns v.mu. Callback renewal consumes its own SEQUENCE before the
// user's compound is constructed, without recursively taking either mutex.
func (v *v4Client) compoundContextLocked(ctx context.Context, auth Auth, rpc *rpcClient, child *rpcGSS, ops ...v4Op) (resultErr error) {
	if v.leaseMoved.Load() {
		for _, op := range ops {
			switch op.code {
			case 9, 10, 15, 16, 22, 24: // Namespace discovery only; no state or data operations.
			default:
				return ErrLockUncertain
			}
		}
	}
	if v.trunked && v.stateLost.Load() && len(v.session) != 0 {
		return errors.New("NFSv4 shared session has an uncertain slot; no replay")
	}
	cache := cacheReply4(ops)
	if v.requireCached {
		cache = true
	}
	if !v.requireCached && v.channel.Request != 0 && readOnlyCompound4(ops) {
		cache = false
	}
	var fitErr error
	ops, fitErr = v.fitChannel(auth, rpc, child, ops, cache)
	if fitErr != nil {
		return fitErr
	}
	if err := v.checkChannel(auth, rpc, child, ops, cache); err != nil {
		return err
	}
	if v.journal != nil {
		if err := v.journal.before(v, auth, ops); err != nil {
			var refusal lockJournalPolicyError
			if !errors.As(err, &refusal) {
				v.stateLost.Store(true)
			}
			return err
		}
		started := time.Now()
		defer func() {
			if err := v.journal.after(v, started, resultErr); err != nil {
				v.stateLost.Store(true)
				resultErr = errors.Join(resultErr, err)
			}
		}()
	}
	initialSequence := v.sequence
	defer func() {
		var status Status
		if v.recall != nil && v.sequence != initialSequence && (resultErr == nil || errors.As(resultErr, &status)) {
			// An acknowledged failing operation still completes its SEQUENCE.
			v.recall.mu.Lock()
			v.recall.completed = v.sequence - 1
			v.recall.mu.Unlock()
		}
		if resultErr != nil && !errors.As(resultErr, &status) && !channelNotSent(resultErr) {
			// An unvalidated result can leave the session slot sequence unknown.
			// Never reuse it for a different request or trust another held lock.
			v.stateLost.Store(true)
			rpc.mu.Lock()
			rpc.closeLocked()
			rpc.mu.Unlock()
		}
	}()
	if len(v.session) > 0 {
		var seq encoder
		seq = append(seq, v.session...)
		seq.u32(v.sequence)
		seq.u32(0)
		seq.u32(0)
		if cache {
			seq.u32(1)
		} else {
			seq.u32(0)
		}
		ops = append([]v4Op{op4(53, seq, func(d *decoder) {
			id := d.take(16)
			number := d.u32()
			slot := d.u32()
			d.u32()
			d.u32()
			flags := d.u32()
			if !bytes.Equal(id, v.session) || number != v.sequence || slot != 0 {
				d.err = errors.New("invalid NFSv4 SEQUENCE reply")
			}
			if d.err == nil {
				v.sequence++
				if v.recall != nil && flags&(seq4StatusCBGSSContextsExpiring|seq4StatusCBGSSContextsExpired) != 0 {
					v.callbackRenewalNeeded = true
				}
				if v.recall != nil && flags&seq4StatusCallbackStateLost != 0 {
					// Lost callback path, revoked state, restart or changed
					// devices makes further direct data-server I/O unsafe.
					v.stateLost.Store(true)
				}
				if flags&seq4StatusLeaseMoved != 0 && (v.lockTracking.Load() || v.reclaiming) {
					v.leaseMoved.Store(true)
				}
				if v.lockTracking.Load() || v.reclaiming {
					if flags&seq4StatusRevoked != 0 {
						v.reclaimForbidden.Store(true)
						v.stateLost.Store(true)
					}
					if flags&seq4StatusRestartReclaimNeeded != 0 && !v.reclaiming {
						// Suspend old I/O but permit explicit restart reclaim.
						// During reclaim this flag persists until RECLAIM_COMPLETE.
						v.stateLost.Store(true)
					}
				}
			}
		})}, ops...)
	}
	var e encoder
	e.str("")
	e.u32(v.minor)
	e.u32(uint32(len(ops)))
	for _, op := range ops {
		e.u32(op.code)
		e = append(e, op.args...)
	}
	if exact, ok := ctx.Value(savedCompoundExactKey{}).([]byte); ok && !bytes.Equal(exact, e) {
		return channelRefusal("saved compound no longer fits unchanged in the negotiated channel")
	}
	var recorded *SavedCompound
	if (v.beforeCached != nil || v.afterCached != nil || v.afterCachedError != nil) && cache && len(v.session) == 16 {
		saved := saveCompound(v, auth, e, ops)
		recorded = &saved
		if v.beforeCached != nil {
			if err := v.beforeCached(saved); err != nil {
				return err
			}
		}
	}
	if v.journal != nil && cache && len(v.session) == 16 {
		if err := v.journal.capturePending(saveCompound(v, auth, e, ops)); err != nil {
			return err
		}
	}
	var d *decoder
	var err error
	if len(v.session) != 0 && v.channel.Request != 0 {
		limit := v.channel.Response
		if cache {
			limit = min(limit, v.channel.Cached)
		}
		ctx = context.WithValue(ctx, sessionWireBudgetKey{}, sessionWireBudget{v.channel.Request, limit})
	}
	if child != nil {
		d, err = rpc.callGSSChild(ctx, child, nfsProgram, 4, 1, &auth, e)
	} else {
		d, err = rpc.call(ctx, nfsProgram, 4, 1, &auth, e)
	}
	control, _ := ctx.Value(backchannelControlKey{}).(bool)
	if err != nil && child == nil && cache && !control {
		var finish func(bool)
		d, rpc, finish, err = v.replayCached(ctx, auth, rpc, e, ops, err)
		if finish != nil {
			defer func() {
				confirmed := cachedReplayConfirmed(resultErr, initialSequence, v.sequence, v.stateLost.Load())
				if !confirmed {
					v.stateLost.Store(true)
				}
				finish(confirmed)
			}()
		}
	}
	if err != nil {
		if !channelNotSent(err) {
			v.stateLost.Store(true)
		}
		return err
	}
	var originalReply []byte
	if recorded != nil && (v.afterCached != nil || v.afterCachedError != nil) {
		originalReply = bytes.Clone(d.b)
	}
	status := d.u32()
	d.str()
	count := d.u32()
	if d.err != nil {
		return d.err
	}
	if count > uint32(len(ops)) || (status == 0 && count != uint32(len(ops))) {
		return errors.New("invalid NFSv4 result count")
	}
	if count == 0 && status != 0 && !emptyCompoundError4(status) {
		return errors.New("NFSv4 operation error without an operation result")
	}
	for i := uint32(0); i < count; i++ {
		code, s := d.u32(), d.u32()
		if d.err != nil {
			return d.err
		}
		if code != ops[i].code {
			return errors.New("NFSv4 operation mismatch")
		}
		if s != 0 {
			if s != status || i+1 != count {
				return errors.New("inconsistent NFSv4 error reply")
			}
			if ops[i].result != nil {
				ops[i].result(Status(s))
			}
			if ops[i].failure != nil {
				ops[i].failure(d)
				if d.err != nil {
					return d.err
				}
				if len(d.b) != 0 {
					return errors.New("trailing NFSv4 operation error body")
				}
			}
			switch s {
			case 10011, 10022, 10023, 10025, 10026, 10047, 10052, 10055, 10078:
				if s == 10025 && code == 51 && ops[i].revokedLayoutReturn {
					// A confirmed deleted layout has already lost its layout
					// stateid; this says nothing about independent OPEN/LOCKs.
					break
				}
				if s == 10025 && (code == 66 || code == 67) {
					// A completed offload may retire its own stateid. This does
					// not revoke an independent OPEN/LOCK stateid.
					break
				}
				if s == 10011 || s == 10025 || s == 10026 || s == 10047 {
					v.reclaimForbidden.Store(true)
				}
				v.stateLost.Store(true)
			}
			if (code == 12 || code == 13) && s == 10010 {
				d.u64() // conflicting offset and length
				d.u64()
				d.u32()
				d.u64() // conflicting owner is untrusted, not displayed
				d.opaque(1024)
				if d.err != nil || len(d.b) != 0 {
					return errors.New("invalid NFSv4 LOCK denial")
				}
			}
			if code == 60 && s == 10094 {
				// COPY OFFLOAD_NO_REQS carries two strict XDR booleans.
				// Keep the requested requirements; never relax or retry them.
				d.boolean()
				d.boolean()
				if d.err != nil || len(d.b) != 0 {
					return errors.New("invalid NFSv4 COPY requirements refusal")
				}
			}
			if len(d.b) != 0 {
				return errors.New("trailing NFSv4 error reply")
			}
			if recorded != nil && i > 0 && ops[0].code == 53 && v.afterCachedError != nil {
				if err := v.afterCachedError(*recorded, originalReply); err != nil {
					return err
				}
			}
			return Status(s)
		}
		if ops[i].result != nil {
			ops[i].result(0)
		}
		if ops[i].decode != nil {
			ops[i].decode(d)
		}
		if d.err != nil {
			return d.err
		}
	}
	if count != 0 && status != 0 {
		return errors.New("NFSv4 compound status differs from successful operation results")
	}
	if len(d.b) != 0 {
		return errors.New("trailing NFSv4 reply data")
	}
	if status != 0 {
		return Status(status)
	}
	if d.err == nil && recorded != nil && v.afterCached != nil {
		if err := v.afterCached(*recorded, originalReply); err != nil {
			return err
		}
	}
	return d.err
}

func (v *v4Client) initialize(ctx context.Context) error {
	return v.initializeExpected(ctx, nil)
}

func (v *v4Client) initializeExpected(ctx context.Context, expected *createSessionKey) error {
	return v.initializeSession(ctx, expected, nil)
}

func (v *v4Client) initializeSession(ctx context.Context, expected *createSessionKey, shared *v4Client) error {
	if v.clientNonce == nil {
		v.clientNonce = make([]byte, 16)
		if _, err := rand.Read(v.clientNonce); err != nil {
			return err
		}
	}
	nonce := v.clientNonce
	var e encoder
	e = append(e, nonce[:8]...)
	e.str(fmt.Sprintf("nfs-viewer-%x", nonce[:]))
	if v.minor == 0 {
		e.u32(0)
		e.str("tcp")
		e.str("0.0.0.0.0.0")
		e.u32(0)
		var verifier []byte
		if err := v.compound(ctx, op4(35, e, func(d *decoder) { v.clientID = d.u64(); verifier = append([]byte(nil), d.take(8)...) })); err != nil {
			return err
		}
		e = nil
		e.u64(v.clientID)
		e = append(e, verifier...)
		if err := v.compound(ctx, op4(36, e, nil)); err != nil {
			return err
		}
	} else {
		creates := v.sessionSequences()
		if err := creates.lock(ctx); err != nil {
			return err
		}
		defer func() { <-creates.gate }()
		role := v.exchangeRole
		if role == 0 {
			role = 0x10000
		}
		e.u32(role)
		e.u32(0)
		e.u32(0) // non-pNFS, SP4_NONE, no implementation IDs
		var sequence uint32
		var confirmed bool
		key := createSessionKey{nonce: string(nonce), minor: v.minor}
		if err := v.compound(ctx, op4(42, e, func(d *decoder) {
			v.clientID = d.u64()
			key.clientID = v.clientID
			sequence = d.u32()
			flags := d.u32()
			confirmed = flags&0x80000000 != 0
			if v.exchangeRole != 0 && flags&v.exchangeRole == 0 {
				d.err = errors.New("server declined required pNFS role")
				return
			}
			if d.u32() != 0 {
				d.err = errors.New("NFSv4 state protection is unsupported")
				return
			}
			v.serverMinor = d.u64() // Minor ID matters for session, but not client-ID, trunking.
			key.owner = string(d.opaque(1024))
			key.scope = string(d.opaque(1024))
			n := d.u32()
			if n > 1 {
				d.err = errors.New("invalid NFSv4 implementation count")
				return
			}
			for i := uint32(0); i < n; i++ {
				d.str()
				d.str()
				d.take(12)
			}
		})); err != nil {
			return err
		}
		if expected != nil && (!confirmed || key != *expected) {
			return errors.New("pNFS alternate did not confirm the original server/client identity")
		}
		if v.replayFrom != nil {
			return v.bindReplaySession(ctx, v.replayFrom, key)
		}
		if v.migrationFrom != nil {
			return v.bindMigration(ctx, v.migrationFrom, key, confirmed)
		}
		if shared != nil {
			return v.bindSharedSession(ctx, shared, key)
		}
		var err error
		sequence, err = creates.sequence(key, confirmed, sequence)
		if err != nil {
			return err
		}
		e = nil
		e.u64(v.clientID)
		e.u32(sequence)
		if v.recall != nil {
			e.u32(2)
		} else {
			e.u32(0)
		}
		requestLimit, responseLimit, cachedLimit := uint32(1<<20), uint32(1<<20), uint32(65536)
		if v.c.nfs.iwarp != nil {
			requestLimit, responseLimit, cachedLimit = iwarpRPCSize, iwarpRPCSize, iwarpRPCSize
		}
		for i := 0; i < 2; i++ {
			if i == 1 && v.recall != nil {
				for _, n := range []uint32{0, pnfsCallbackSize, pnfsCallbackSize, pnfsCallbackSize, pnfsCallbackOps, 1, 0} {
					e.u32(n)
				}
				continue
			}
			e.u32(0)
			e.u32(requestLimit)
			e.u32(responseLimit)
			e.u32(cachedLimit)
			e.u32(16)
			e.u32(1)
			e.u32(0)
		}
		if v.recall != nil {
			e.u32(pnfsCallbackProgram)
			e.u32(1)
			if g := v.recall.gss; g != nil {
				e.u32(6)
				e.u32(g.service)
				e.opaque(g.foreHandle)
				e.opaque(g.handle)
			} else {
				e.u32(0)
			}
		} else {
			e.u32(0)
			e.u32(0)
		}
		var sessionID []byte
		var backLimits [3]uint32
		// An unsuccessful or unvalidated reply must never cause a different
		// CREATE_SESSION to reuse the same slot. Explicit reconnect is required
		// if the server subsequently reports this identity as confirmed.
		creates.entries[key] = createSessionSequence{next: sequence, uncertain: true}
		if err := v.compound(ctx, op4(43, e, func(d *decoder) {
			sessionID = append([]byte(nil), d.take(16)...)
			if got := d.u32(); d.err == nil && got != sequence {
				d.err = errors.New("NFSv4 CREATE_SESSION reply sequence mismatch")
				return
			}
			flags := d.u32()
			if v.recall != nil && flags&2 == 0 {
				d.err = errors.New("server declined NFSv4 backchannel")
				return
			}
			for i := 0; i < 2; i++ {
				pad := d.u32()
				request, response, cached, operations, slots := d.u32(), d.u32(), d.u32(), d.u32(), d.u32()
				if i == 1 && v.recall != nil {
					if pad != 0 || request < 1024 || request > pnfsCallbackSize || response < 1024 || response > pnfsCallbackSize || cached > pnfsCallbackSize || operations != pnfsCallbackOps || slots != 1 {
						d.err = errors.New("unsupported NFSv4 backchannel negotiation")
						return
					}
					backLimits = [3]uint32{request, response, cached}
				}
				// RFC 8881 permits the server to change forechannel operation
				// and slot counts in either direction. We continue using slot 0.
				if i == 0 && (request > requestLimit || response > responseLimit || cached > cachedLimit || slots < 1 || pad != 0) {
					d.err = errors.New("invalid NFSv4 forechannel negotiation")
					return
				}
				if i == 0 {
					if err := v.setChannel(sessionChannelLimits{request, response, cached, operations}); err != nil {
						d.err = err
						return
					}
				}
				n := d.u32()
				// RFC 8881 18.36.1 permits zero or one RDMA IRD values on
				// either channel. FreeBSD returns one zero even over TCP.
				if n > 1 {
					d.err = errors.New("invalid NFSv4 RDMA array")
					return
				}
				for j := uint32(0); j < n; j++ {
					d.u32()
				}
			}
		})); err != nil {
			return err
		}
		creates.entries[key] = createSessionSequence{next: sequence + 1}
		v.session = sessionID
		v.serverIdentity = &key
		if v.recall != nil {
			v.recall.mu.Lock()
			v.recall.minor = v.minor
			v.recall.session = append([]byte(nil), sessionID...)
			v.recall.requestLimit, v.recall.responseLimit, v.recall.cacheLimit = backLimits[0], backLimits[1], backLimits[2]
			v.recall.mu.Unlock()
		}
		v.sequence = 1
		e = nil
		e.u32(0)
		if !v.reclaiming && v.exchangeRole != 0x40000 {
			if err := v.compound(ctx, op4(58, e, nil)); err != nil {
				return err
			}
		}
	}
	if v.exchangeRole == 0x40000 {
		return nil
	}
	return v.compound(ctx, op4(24, nil, nil), op4(10, nil, func(d *decoder) { v.root = append([]byte(nil), d.opaque(128)...) }))
}

func (v *v4Client) close(ctx context.Context) {
	if v.journal != nil {
		defer v.journal.file.Close()
	}
	if v.sharedSession != nil {
		return // The pool's owner destroys the shared session exactly once.
	}
	if v.stop != nil {
		v.stop()
		<-v.done
	}
	if v.migrationBorrowed {
		return // No new session/state was allocated by this validation connection.
	}
	for id := range v.locks {
		if ctx.Err() != nil {
			break
		}
		_ = v.c.Unlock(ctx, id)
	}
	clear(v.locks)
	if len(v.session) == 0 {
		return
	}
	sid := v.session
	v.session = nil
	_ = v.compound(ctx, op4(44, encoder(sid), nil))
	if v.exchangeRole == 0x40000 {
		// A co-located MDS may share this client ID. Destroy only our DS
		// session; destroying the client ID could invalidate MDS state.
		return
	}
	var e encoder
	e.u64(v.clientID)
	_ = v.compound(ctx, op4(57, e, nil))
}

// Keep the server's lease alive without reading the shell's mutable identity.
// This is the only background caller; compoundAuth serializes SEQUENCE state.
func (v *v4Client) keepAlive(ctx context.Context) error {
	lease := uint32(60)
	started := time.Now()
	if err := v.attrs(ctx, v.root, []uint32{10}, func(_ uint32, d *decoder) { lease = d.u32() }); err != nil {
		return err
	}
	if lease == 0 {
		return errors.New("server returned a zero NFSv4 lease")
	}
	interval := max(250*time.Millisecond, time.Duration(lease)*time.Second/3)
	v.leaseSeconds = lease
	v.lastLease.Store(&started)
	interval = min(interval, 20*time.Second)
	bg, cancel := context.WithCancel(context.Background())
	v.stop = cancel
	v.done = make(chan struct{})
	auth := v.c.Auth
	go func() {
		defer close(v.done)
		ticker := time.NewTicker(v.callbackRenewalInterval(interval))
		defer ticker.Stop()
		for {
			select {
			case <-bg.Done():
				return
			case <-ticker.C:
				started := time.Now()
				var ops []v4Op
				if v.minor == 0 {
					var e encoder
					e.u64(v.clientID)
					ops = []v4Op{op4(30, e, nil)}
				}
				if err := v.compoundAuth(bg, auth, ops...); err != nil {
					var policy lockJournalPolicyError
					if errors.As(err, &policy) || errors.Is(err, errOffloadResourceBusy) {
						continue
					}
					if bg.Err() == nil {
						v.stateLost.Store(true)
					}
					return
				}
				v.lastLease.Store(&started)
				ticker.Reset(v.callbackRenewalInterval(interval))
			}
		}
	}()
	return nil
}
func (v *v4Client) mount(ctx context.Context, path string) (Node, error) {
	n := Node{Handle: v.root}
	var err error
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return Node{}, errors.New("export path cannot contain parent components (..)")
		}
		n, err = v.lookup(ctx, n.Handle, part)
		if err != nil {
			return Node{}, err
		}
	}
	n.Attr, err = v.getAttr(ctx, n.Handle)
	return n, err
}
func (v *v4Client) lookup(ctx context.Context, dir []byte, name string) (Node, error) {
	var e encoder
	e.str(name)
	lookup := op4(15, e, nil)
	if name == ".." {
		// RFC 7530 section 16.14: LOOKUP does not accept a parent component.
		lookup = op4(16, nil, nil)
	}
	var n Node
	err := v.compound(ctx, fh4(dir), lookup, op4(10, nil, func(d *decoder) { n.Handle = append([]byte(nil), d.opaque(128)...) }))
	if err != nil {
		if name != ".." && errors.Is(err, Status(10016)) {
			return n, v.wrongSecurity(ctx, dir, name)
		}
		return n, err
	}
	if name != ".." {
		v.remember(n.Handle, dir, name)
	}
	n.Attr, err = v.getAttr(ctx, n.Handle)
	return n, err
}
func (v *v4Client) attrs(ctx context.Context, fh []byte, bits []uint32, decode func(uint32, *decoder)) error {
	var e encoder
	bitmap4(&e, bits...)
	return v.compound(ctx, fh4(fh), op4(9, e, func(d *decoder) {
		returned := readBitmap4(d)
		values := d.opaque(65536)
		a := &decoder{b: values}
		for _, bit := range returned {
			found := false
			for _, wanted := range bits {
				if bit == wanted {
					found = true
				}
			}
			if !found {
				d.err = errors.New("unsolicited NFSv4 attribute")
				return
			}
			decode(bit, a)
		}
		if a.err != nil {
			d.err = a.err
		} else if len(a.b) != 0 {
			d.err = errors.New("trailing NFSv4 attributes")
		}
	}))
}
func decodeAttr4(a *Attr, bit uint32, d *decoder) {
	switch bit {
	case 1:
		a.Type = d.u32()
	case 3:
		a.Change = d.u64()
		a.HasChange = true
	case 4:
		a.Size = d.u64()
		a.HasSize = true
	case 8:
		a.FSID = d.u64()
		a.FSIDMinor = d.u64()
		a.HasFSID = true
	case 20:
		a.FileID = d.u64()
		a.HasFileID = true
	case 33:
		a.Mode = d.u32()
	case 36:
		a.Owner = d.str()
		if n, err := strconv.ParseUint(a.Owner, 10, 32); err == nil {
			a.UID = uint32(n)
		}
	case 37:
		a.Group = d.str()
		if n, err := strconv.ParseUint(a.Group, 10, 32); err == nil {
			a.GID = uint32(n)
		}
	case 52, 53:
		sec, nsec := int64(d.u64()), d.u32()
		if nsec >= 1e9 {
			d.err = errors.New("invalid NFSv4 timestamp")
		}
		if bit == 52 {
			a.CTime = time.Unix(sec, int64(nsec))
			a.HasCTime = true
		} else {
			a.MTime = time.Unix(sec, int64(nsec))
			a.HasMTime = true
		}
	default:
		d.err = fmt.Errorf("unexpected NFSv4 attribute %d", bit)
	}
}

func (v *v4Client) getAttr(ctx context.Context, fh []byte) (Attr, error) {
	var a Attr
	err := v.attrs(ctx, fh, []uint32{1, 3, 4, 8, 20, 33, 36, 37, 52, 53}, func(bit uint32, d *decoder) { decodeAttr4(&a, bit, d) })
	if err == nil && a.Type == 0 {
		err = errors.New("server omitted NFSv4 file type")
	}
	return a, err
}
func (v *v4Client) tune(ctx context.Context, fh []byte) error {
	return v.attrs(ctx, fh, []uint32{30, 31}, func(bit uint32, d *decoder) {
		n := d.u64()
		if n == 0 {
			d.err = errors.New("server returned zero transfer maximum")
			return
		}
		if bit == 30 {
			v.c.ReadSize = uint32(min(uint64(v.c.ReadSize), n))
		} else {
			v.c.WriteSize = uint32(min(uint64(v.c.WriteSize), n))
		}
	})
}
func (v *v4Client) access(ctx context.Context, fh []byte) (uint32, error) {
	var e encoder
	e.u32(63)
	var access uint32
	err := v.compound(ctx, fh4(fh), op4(3, e, func(d *decoder) { d.u32(); access = d.u32() }))
	return access, err
}
func (v *v4Client) readlink(ctx context.Context, fh []byte) (string, error) {
	var target string
	err := v.compound(ctx, fh4(fh), op4(27, nil, func(d *decoder) { target = d.str() }))
	return target, err
}
func (v *v4Client) readdir(ctx context.Context, fh []byte) ([]Entry, error) {
	entries := []Entry{}
	var cookie uint64
	verifier := make([]byte, 8)
	seen := map[uint64]bool{}
	for {
		var e encoder
		e.u64(cookie)
		e = append(e, verifier...)
		maxCount := uint32(4096)
		if v.channel.Response == 0 && v.maxReplyPayload != 0 {
			maxCount = min(maxCount, v.maxReplyPayload)
		}
		e.u32(maxCount)
		e.u32(maxCount)
		bitmap4(&e, 1, 4, 8, 19, 20, 33, 36, 37, 53)
		old := cookie
		eof := false
		page := []Entry{}
		err := v.compound(ctx, fh4(fh), op4(26, e, func(d *decoder) {
			copy(verifier, d.take(8))
			for d.boolean() && d.err == nil {
				cookie = d.u64()
				entry := Entry{Name: d.str()}
				bits := readBitmap4(d)
				a := &decoder{b: d.opaque(65536)}
				for _, bit := range bits {
					if bit == 19 {
						entry.Handle = append([]byte(nil), a.opaque(128)...)
					} else {
						decodeAttr4(&entry.Attr, bit, a)
					}
				}
				if a.err != nil {
					d.err = a.err
					return
				}
				if len(a.b) != 0 {
					d.err = errors.New("trailing READDIR attributes")
					return
				}
				page = append(page, entry)
			}
			eof = d.boolean()
		}))
		if err != nil {
			return nil, err
		}
		for _, entry := range page {
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			if len(entry.Handle) == 0 || entry.Attr.Type == 0 {
				n, err := v.lookup(ctx, fh, entry.Name)
				if errors.Is(err, Status(2)) {
					continue
				}
				if err != nil {
					return nil, err
				}
				entry.Node = n
			} else {
				v.remember(entry.Handle, fh, entry.Name)
			}
			entries = append(entries, entry)
			if len(entries) > 1000000 {
				return nil, errors.New("directory exceeds one million entries")
			}
		}
		if eof {
			break
		}
		if cookie == old || seen[cookie] {
			return nil, errors.New("directory listing made no progress")
		}
		seen[cookie] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

type v4Open struct {
	fh, sid []byte
	owner   []byte
	seq     uint32
	auth    Auth
}

func mode4(mode uint32) encoder {
	var e, val encoder
	bitmap4(&e, 33)
	val.u32(mode)
	e.opaque(val)
	return e
}

// Each open has its own owner so failed OPENs cannot desynchronize another
// owner's NFSv4.0 seqid. Explicit locks retain their open until unlock.
func (v *v4Client) open(ctx context.Context, dir []byte, name string, share uint32, create bool, mode uint32) (*v4Open, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	var e encoder
	e.u32(0)
	e.u32(share)
	e.u32(0)
	e.u64(v.clientID)
	e.opaque(nonce[:])
	if create {
		e.u32(1)
		e.u32(1)
		e = append(e, mode4(mode)...)
	} else {
		e.u32(0)
	}
	e.u32(0)
	e.str(name)
	f := &v4Open{seq: 1, auth: v.c.Auth, owner: append([]byte(nil), nonce[:]...)}
	f.auth.Groups = append([]uint32(nil), f.auth.Groups...)
	var flags uint32
	var delegation []byte
	err := v.compound(ctx, fh4(dir), op4(18, e, func(d *decoder) {
		f.sid = append([]byte(nil), d.take(16)...)
		skipChange4(d)
		flags = d.u32()
		readBitmap4(d)
		kind := d.u32()
		switch kind {
		case 0:
		case 1, 2:
			delegation = append([]byte(nil), d.take(16)...)
			d.boolean()
			if kind == 2 {
				limit := d.u32()
				switch limit {
				case 1:
					d.u64()
				case 2:
					d.u32()
					d.u32()
				default:
					d.err = errors.New("invalid delegation limit")
				}
			}
			d.u32()
			d.u32()
			d.u32()
			d.str()
		case 3:
			why := d.u32()
			if why == 1 || why == 2 {
				d.boolean()
			}
		default:
			d.err = errors.New("invalid NFSv4 delegation")
		}
	}), op4(10, nil, func(d *decoder) { f.fh = append([]byte(nil), d.opaque(128)...) }))
	if err != nil {
		return nil, err
	}
	if flags&2 != 0 {
		e = append(encoder(nil), f.sid...)
		e.u32(f.seq)
		f.seq++
		if err := v.compound(ctx, fh4(f.fh), op4(20, e, func(d *decoder) { f.sid = append([]byte(nil), d.take(16)...) })); err != nil {
			return nil, err
		}
	}
	if len(delegation) > 0 {
		if err := v.compound(ctx, fh4(f.fh), op4(8, encoder(delegation), nil)); err != nil {
			_ = v.closeFile(f)
			return nil, err
		}
	}
	v.remember(f.fh, dir, name)
	return f, nil
}
func (v *v4Client) closeFile(f *v4Open) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return v.closeFileContext(ctx, f)
}
func (v *v4Client) closeFileContext(ctx context.Context, f *v4Open) error {
	var e encoder
	e.u32(f.seq)
	e = append(e, f.sid...)
	return v.compoundAuth(ctx, f.auth, fh4(f.fh), op4(4, e, func(d *decoder) { d.take(16) }))
}
func (v *v4Client) openHandle(ctx context.Context, fh []byte, share uint32) (*v4Open, error) {
	p, ok := v.parents[string(fh)]
	if !ok {
		return nil, errors.New("NFSv4 file must be resolved by name before opening")
	}
	f, err := v.open(ctx, p.dir, p.name, share, false, 0)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(f.fh, fh) {
		_ = v.closeFile(f)
		return nil, errors.New("remote file changed while opening; resolve it again")
	}
	return f, nil
}
func (v *v4Client) create(ctx context.Context, dir []byte, name string, mode uint32, directory bool) (Node, error) {
	if directory {
		var e encoder
		e.u32(2)
		e.str(name)
		e = append(e, mode4(mode)...)
		if err := v.compound(ctx, fh4(dir), op4(6, e, func(d *decoder) { skipChange4(d); readBitmap4(d) }), op4(10, nil, func(d *decoder) { d.opaque(128) })); err != nil {
			return Node{}, err
		}
	} else {
		f, err := v.open(ctx, dir, name, 2, true, mode)
		if err != nil {
			return Node{}, err
		}
		if err = v.closeFile(f); err != nil {
			return Node{}, err
		}
	}
	return v.lookup(ctx, dir, name)
}
func (v *v4Client) chmod(ctx context.Context, fh []byte, mode uint32) error {
	e := make(encoder, 16)
	e = append(e, mode4(mode)...)
	return v.compound(ctx, fh4(fh), op4(34, e, func(d *decoder) { readBitmap4(d) }))
}
func (v *v4Client) remove(ctx context.Context, dir []byte, name string) error {
	var e encoder
	e.str(name)
	return v.compound(ctx, fh4(dir), op4(28, e, skipChange4))
}
func (v *v4Client) rename(ctx context.Context, fromDir []byte, from string, toDir []byte, to string) error {
	var e encoder
	e.str(from)
	e.str(to)
	return v.compound(ctx, fh4(fromDir), op4(32, nil, nil), fh4(toDir), op4(29, e, func(d *decoder) { skipChange4(d); skipChange4(d) }))
}
func (v *v4Client) read(ctx context.Context, fh []byte, w io.Writer, progress func(uint64)) (count int64, resultErr error) {
	sid, closeIO, err := v.openIO(ctx, fh, 1)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	for {
		if err := v.checkLockedIO(fh, 1); err != nil {
			return count, err
		}
		e := append(encoder(nil), sid...)
		e.u64(uint64(count))
		e.u32(v.c.ReadSize)
		var data []byte
		var eof bool
		if err := v.compound(ctx, fh4(fh), op4(25, e, func(d *decoder) { eof = d.boolean(); data = d.opaque(v.c.ReadSize) })); err != nil {
			return count, err
		}
		if err := v.checkLockedIO(fh, 1); err != nil {
			return count, err
		}
		n, err := w.Write(data)
		count += int64(n)
		if progress != nil {
			progress(uint64(count))
		}
		if err != nil {
			return count, err
		}
		if n != len(data) {
			return count, io.ErrShortWrite
		}
		if eof {
			return count, nil
		}
		if n == 0 {
			return count, io.ErrNoProgress
		}
	}
}
func (v *v4Client) write(ctx context.Context, fh []byte, r io.Reader, progress func(uint64)) (count int64, resultErr error) {
	return v.writeAt(ctx, fh, r, progress, 0)
}

func (v *v4Client) writeAt(ctx context.Context, fh []byte, r io.Reader, progress func(uint64), base uint64) (count int64, resultErr error) {
	sid, closeIO, err := v.openIO(ctx, fh, 2)
	if err != nil {
		return 0, err
	}
	return v.writeAtState(ctx, fh, r, progress, base, sid, func() error { return v.checkLockedIO(fh, 2) }, closeIO)
}

func (v *v4Client) writeAtState(ctx context.Context, fh []byte, r io.Reader, progress func(uint64), base uint64, sid []byte, check, closeIO func() error) (count int64, resultErr error) {
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	buf := make([]byte, v.c.WriteSize)
	for {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		n, readErr := r.Read(buf)
		if n == 0 && readErr == nil {
			return count, io.ErrNoProgress
		}
		for data := buf[:n]; len(data) > 0; {
			if base > uint64(1<<63-1)-uint64(count) || uint64(len(data)) > uint64(1<<63-1)-base-uint64(count) {
				return count, errors.New("NFSv4 write exceeds supported signed 64-bit file size")
			}
			if err := check(); err != nil {
				return count, err
			}
			e := append(encoder(nil), sid...)
			e.u64(base + uint64(count))
			e.u32(2)
			e.opaque(data)
			var accepted, stable uint32
			var verifier []byte
			if err := v.compound(ctx, fh4(fh), op4(38, e, func(d *decoder) { accepted = d.u32(); stable = d.u32(); verifier = append([]byte(nil), d.take(8)...) })); err != nil {
				return count, err
			}
			if err := check(); err != nil {
				return count, err
			}
			if accepted == 0 || accepted > uint32(len(data)) || stable > 2 {
				return count, errors.New("invalid NFSv4 WRITE reply")
			}
			if stable != 2 {
				e = nil
				e.u64(base + uint64(count))
				e.u32(accepted)
				if err := v.compound(ctx, fh4(fh), op4(5, e, func(d *decoder) {
					if !bytes.Equal(d.take(8), verifier) {
						d.err = errors.New("server rebooted during upload; write verifier changed")
					}
				})); err != nil {
					return count, err
				}
			}
			count += int64(accepted)
			data = data[accepted:]
			if progress != nil {
				progress(uint64(count))
			}
		}
		if readErr == io.EOF {
			return count, nil
		}
		if readErr != nil {
			return count, readErr
		}
	}
}
