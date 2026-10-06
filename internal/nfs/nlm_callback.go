package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

// The callback registry contains immutable identity snapshots. Callback workers
// never read the foreground lock map or write its durable journal.
type nlmPending struct {
	fh, owner      []byte
	svid           uint32
	auth           Auth
	write          bool
	offset, length uint64
	accept         bool
	done           chan error
}

type nlmCallbacks struct {
	mu      sync.Mutex
	version uint32
	monitor *nsmMonitor
	entries map[string]*nlmPending
	send    func(context.Context, []byte, NLMStatus, Auth) error
}

func (n *nlmClient) callbacks() *nlmCallbacks {
	if cb := n.monitor.callbacks.Load(); cb != nil {
		return cb
	}
	cb := &nlmCallbacks{version: n.version, monitor: n.monitor, entries: make(map[string]*nlmPending)}
	// GRANTED_RES is a one-way RPC (FreeBSD deliberately sends no RPC reply).
	// A separate TCP connection prevents optional void replies from corrupting
	// the retained control stream. The GRANTED notification establishes the
	// grant; successful sending does not claim an acknowledgement from lockd.
	address := n.rpc.conn.RemoteAddr().String()
	cb.send = func(ctx context.Context, cookie []byte, status NLMStatus, auth Auth) error {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return err
		}
		rpc, err := dialRPC(ctx, host, port, n.monitor.cfg.Timeout, n.monitor.cfg.ReservedPort)
		if err != nil {
			return err
		}
		defer rpc.conn.Close()
		deadline, _ := ctx.Deadline()
		if err := rpc.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		var e encoder
		for _, v := range []uint32{rpc.xid, 0, 2, nlmProgram, n.version, 15} {
			e.u32(v)
		}
		auth.encode(&e)
		e.u32(0)
		e.u32(0)
		e.opaque(cookie)
		e.u32(uint32(status))
		record := nsmRecordBytes(e)
		written, err := rpc.conn.Write(record)
		if err == nil && written != len(record) {
			err = io.ErrShortWrite
		}
		return err
	}
	n.monitor.callbacks.Store(cb)
	return cb
}

func (cb *nlmCallbacks) register(l *nlmLock) *nlmPending {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	p := &nlmPending{fh: slices.Clone(l.fh), owner: slices.Clone(l.owner), svid: l.svid, auth: l.auth, write: l.info.Write, offset: l.info.Offset, length: l.info.Length, accept: true, done: make(chan error, 1)}
	cb.entries[string(l.owner)] = p
	return p
}

func (cb *nlmCallbacks) disable(l *nlmLock) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if p := cb.entries[string(l.owner)]; p != nil {
		p.accept = false
	}
}

func (cb *nlmCallbacks) remove(l *nlmLock) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.entries, string(l.owner))
}

func (cb *nlmCallbacks) dispatch(procedure uint32, d *decoder) uint32 {
	if procedure == 0 {
		return 0
	}
	if procedure != 10 {
		return 3
	}
	cookie, p, valid := cb.matchGrant(d)
	if !valid {
		return 4
	}
	if p == nil {
		return 0
	}
	defer cb.mu.Unlock()
	status := cb.grantStatus(p)
	timeout := cb.monitor.cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cb.grantSent(p, status, cb.send(ctx, cookie, status, p.auth))
	return 0
}

// A matched grant retains mu until its reply has been sent. Cancellation must
// not disable acceptance and send UNLOCK while a positive reply is in flight.
func (cb *nlmCallbacks) matchGrant(d *decoder) ([]byte, *nlmPending, bool) {
	cookie := d.opaque(1024)
	write := d.boolean()
	caller, fh, owner, svid := string(d.opaque(1024)), d.opaque(64), d.opaque(1024), d.u32()
	var offset, length uint64
	if cb.version == 1 {
		offset, length = uint64(d.u32()), uint64(d.u32())
	} else {
		offset, length = d.u64(), d.u64()
	}
	if length == 0 {
		length = LockToEOF
	}
	if d.err != nil || len(d.b) != 0 || len(cookie) == 0 {
		return nil, nil, false
	}
	cb.mu.Lock()
	p := cb.entries[string(owner)]
	if p == nil || caller != cb.monitor.cfg.NLMClientIP || !bytes.Equal(fh, p.fh) || svid != p.svid || write != p.write || offset != p.offset || length != p.length {
		cb.mu.Unlock()
		return cookie, nil, true
	}
	return cookie, p, true
}

func (cb *nlmCallbacks) grantStatus(p *nlmPending) NLMStatus {
	if !p.accept || cb.monitor.lost.Load() {
		return 1
	}
	return 0
}

func (cb *nlmCallbacks) grantSent(p *nlmPending, status NLMStatus, err error) {
	if err != nil {
		cb.monitor.invalidate()
	}
	if status == 0 {
		select {
		case p.done <- err:
		default:
		}
	}
}

func (cb *nlmCallbacks) synchronousGrant(d *decoder) (encoder, uint32, func(error)) {
	cookie, p, valid := cb.matchGrant(d)
	if !valid {
		return nil, 4, nil
	}
	status := NLMStatus(1)
	if p != nil {
		status = cb.grantStatus(p)
	}
	var result encoder
	result.opaque(cookie)
	result.u32(uint32(status))
	if p == nil {
		return result, 0, nil
	}
	var once sync.Once
	return result, 0, func(err error) {
		once.Do(func() { defer cb.mu.Unlock(); cb.grantSent(p, status, err) })
	}
}

// LockRangeNativeWait uses one blocking NLM LOCK and GRANTED/GRANTED_MSG
// callbacks. It requires the retained AUTH_SYS/IPv4 NSM profile (NFSv2/v3).
// Foreground Client APIs must remain serialized while this call is pending.
func (c *Client) LockRangeNativeWait(ctx context.Context, fh []byte, write bool, offset, length uint64, wait time.Duration) (uint64, error) {
	if wait <= 0 || wait > 24*time.Hour {
		return 0, errors.New("native lock wait must be positive and at most 24h")
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return c.lockNLMMode(ctx, fh, write, offset, length, true)
}

func (n *nlmClient) finishNativeWait(ctx context.Context, l *nlmLock, p *nlmPending, status NLMStatus) (uint64, error) {
	if status == 3 {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		waiting := true
		for waiting {
			select {
			case err := <-p.done:
				if err != nil {
					return n.nativeUncertain(l, err)
				}
				waiting = false
			case <-ctx.Done():
				waiting = false
			case <-ticker.C:
				if n.monitor.lost.Load() {
					return n.nativeUncertain(l, ErrLockUncertain)
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return n.cancelNativeWait(l, err)
	}
	if err := n.guard(ctx); err != nil {
		return n.nativeUncertain(l, err)
	}
	l.confirmed = true
	if err := n.saveLocks(); err != nil {
		return n.nativeUncertain(l, err)
	}
	return l.info.ID, nil
}

func (n *nlmClient) nativeUncertain(l *nlmLock, err error) (uint64, error) {
	n.callbacks().disable(l)
	l.info.Uncertain = true
	n.monitor.invalidate()
	return l.info.ID, errors.Join(ErrLockUncertain, err)
}

func (n *nlmClient) cancelNativeWait(l *nlmLock, cause error) (uint64, error) {
	// Serialize against positive grant replies before starting cancellation.
	n.callbacks().disable(l)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.guard(ctx); err != nil {
		return n.nativeUncertain(l, errors.Join(cause, err))
	}
	status, err := n.mutate(ctx, 3, l)
	if err != nil || status != 0 && status != 1 {
		return n.nativeUncertain(l, errors.Join(cause, err, status))
	}
	if err := n.guard(ctx); err != nil {
		return n.nativeUncertain(l, errors.Join(cause, err))
	}
	// CANCEL denied can mean the grant already won. An exact-owner UNLOCK is
	// required even after successful CANCEL before the journal becomes clean.
	if err := n.unlock(ctx, l.info.ID); err != nil {
		return n.nativeUncertain(l, errors.Join(cause, err))
	}
	return 0, cause
}
