package nfs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type backchannelContextKey struct{}
type backchannelControlKey struct{}

type retainedBackchannel struct {
	g       *gssBackchannel
	cleanup func()
}

// BACKCHANNEL_CTL adds handles (RFC 8881 section 18.33); it does not revoke
// previous handles. Each handle retains its own authenticated replay window,
// while all of them share the session's CB_SEQUENCE and state in recall.
type gssBackchannelSet struct {
	mu      sync.Mutex
	recall  *layoutRecall
	entries []retainedBackchannel
}

func newGSSBackchannelSet(g *gssBackchannel, r *layoutRecall) *gssBackchannelSet {
	return &gssBackchannelSet{recall: r, entries: []retainedBackchannel{{g: g}}}
}

func (s *gssBackchannelSet) pruneLocked() {
	kept := s.entries[:0]
	for _, entry := range s.entries {
		if entry.cleanup != nil && !entry.g.expiry.IsZero() && !time.Now().Before(entry.g.expiry) {
			entry.cleanup()
			continue
		}
		kept = append(kept, entry)
	}
	clear(s.entries[len(kept):])
	s.entries = kept
}

func (s *gssBackchannelSet) callback(raw []byte) ([]byte, error) {
	// Keep the selected context alive through authentication and reply signing.
	// Never hold this mutex over KDC or fore-channel I/O: the same reader must
	// deliver the control reply even while callbacks arrive during renewal.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	d := &decoder{b: raw}
	d.take(24)
	if d.u32() != 6 {
		return nil, errors.New("backchannel requires RPCSEC_GSS")
	}
	a := &decoder{b: d.opaque(400)}
	a.take(16)
	handle := a.opaque(380)
	if d.err != nil || a.err != nil || len(a.b) != 0 {
		return nil, errors.New("invalid backchannel GSS credential")
	}
	for _, entry := range s.entries {
		if string(entry.g.handle) == string(handle) {
			return entry.g.callback(raw, s.recall)
		}
	}
	return nil, errors.New("unknown backchannel GSS context")
}

func (s *gssBackchannelSet) retire(cleanup func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	// A peer cannot force unbounded retention through rapid sequence exhaustion.
	if len(s.entries) >= 8 {
		return errors.New("too many live callback contexts; renewal refused")
	}
	s.entries[len(s.entries)-1].cleanup = cleanup
	return nil
}

func (s *gssBackchannelSet) add(g *gssBackchannel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, retainedBackchannel{g: g})
}

func (s *gssBackchannelSet) exhausted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.entries[len(s.entries)-1].g
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.highest >= 0x7ffffffe
}

func (s *gssBackchannelSet) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if entry.cleanup != nil {
			entry.cleanup()
		}
	}
	s.entries = nil
}

// v.mu serializes all fore-channel work, so no previous RPC is in flight here.
// The control stays on the existing connection/session; layouts, locks, offload
// stateids and callback sequence numbers are never transferred to a new session.
func (v *v4Client) renewBackchannelLocked(ctx context.Context, auth Auth, rpc *rpcClient) (context.Context, error) {
	rpc.mu.Lock()
	if rpc.backchannel == nil || rpc.kerberos == nil || rpc.gss == nil || len(v.session) != 16 || rpc.closing {
		rpc.mu.Unlock()
		return ctx, nil
	}
	fail := func(err error) (context.Context, error) {
		v.stateLost.Store(true)
		rpc.closeLocked()
		rpc.mu.Unlock()
		return ctx, fmt.Errorf("callback Kerberos renewal refused; pending work not sent, no replay: %w", err)
	}
	if rpc.closed {
		rpc.mu.Unlock()
		return ctx, ErrConnectionLost
	}
	old := rpc.gss
	if time.Now().Before(old.renewAt) && old.seq < 0x7ffffffe && !rpc.backchannel.exhausted() && !v.callbackRenewalNeeded {
		rpc.mu.Unlock()
		return context.WithValue(ctx, backchannelContextKey{}, old), nil
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	_, exact := ctx.Value(savedCompoundExactKey{}).([]byte)
	// These recorders require their own durable slot schema. Refuse before
	// changing any slot or overwriting their saved request, even if its latest
	// operation was acknowledged. Removing an unknown request is never safe.
	if !old.established || rpc.copyParentPins != 0 || v.stateLost.Load() || v.leaseMoved.Load() || v.recoverBindOnly || v.replayFrom != nil || exact || v.journal != nil || v.requireCached || v.beforeCached != nil || v.afterCached != nil || v.afterCachedError != nil {
		return fail(errors.New("session has pinned COPY state, uncertain work or a durable recovery recorder"))
	}
	s := rpc.kerberos
	if err := rpc.backchannel.retire(s.cleanup); err != nil {
		return fail(err)
	}
	s.cleanup = nil // The dispatcher now owns the old crypto until expiry/close.
	rpc.backchannelRenewing = true
	cleanup, err := rpc.establishKerberosLocked(ctx, s.config, s.security, s.version)
	if err != nil {
		rpc.backchannelRenewing = false
		return fail(err)
	}
	s.cleanup = cleanup
	fresh := rpc.gss
	g, err := newGSSBackchannel(fresh)
	if err != nil {
		rpc.backchannelRenewing = false
		return fail(err)
	}
	// The peer may use the new callback handle immediately before its control
	// reply. It is already authenticated under the selected identity/protection.
	rpc.backchannel.add(g)
	rpc.mu.Unlock()
	ctx = context.WithValue(ctx, backchannelContextKey{}, fresh)
	controlCtx := context.WithValue(ctx, backchannelControlKey{}, true)
	var e encoder
	e.u32(pnfsCallbackProgram)
	e.u32(1)
	e.u32(6)
	e.u32(g.service)
	e.opaque(g.foreHandle)
	e.opaque(g.handle)
	err = v.compoundContextLocked(controlCtx, auth, rpc, nil, op4(40, e, nil))
	rpc.mu.Lock()
	rpc.backchannelRenewing = false
	if err != nil || ctx.Err() != nil || v.stateLost.Load() {
		return fail(errors.Join(err, ctx.Err(), errors.New("BACKCHANNEL_CTL was not safely acknowledged")))
	}
	s.renewals++
	v.callbackRenewalNeeded = false
	rpc.mu.Unlock()
	return ctx, nil
}

func (v *v4Client) callbackRenewalInterval(interval time.Duration) time.Duration {
	rpc := v.c.nfs
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	if rpc.backchannel != nil && rpc.gss != nil {
		return min(interval, max(10*time.Millisecond, time.Until(rpc.gss.renewAt)))
	}
	return interval
}
