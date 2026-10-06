package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
)

type nlmLock struct {
	info      LockInfo
	fh, owner []byte
	svid      uint32
	auth      Auth
	confirmed bool
	blocking  bool
}

type nlmClient struct {
	c                *Client
	rpc              *rpcClient
	monitor          *nsmMonitor
	version          uint32
	nextID           uint64
	locks            map[uint64]*nlmLock
	reclaimAttempted bool
}

func (c *Client) initNLM(ctx context.Context) error {
	return c.initNLMMode(ctx, false)
}

func (c *Client) initNLMMode(ctx context.Context, recoverLocks bool) error {
	if c.nlm != nil {
		return nil
	}
	if c.config == nil || c.config.NLMClientIP == "" {
		return errors.New("retained NLM requires --nlm-client-ip and --nlm-state-dir; no implicit unmonitored locks")
	}
	cfg := *c.config
	if err := validateNLMConfig(cfg); err != nil {
		return err
	}
	if c.Security() != "sys" {
		return errors.New("NLM security downgrade refused")
	}
	peer, _, err := net.SplitHostPort(c.nfs.conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	if cfg.NLMAutoNotify {
		local, _, splitErr := net.SplitHostPort(c.nfs.conn.LocalAddr().String())
		if splitErr != nil || !net.ParseIP(local).Equal(net.ParseIP(cfg.NLMClientIP)) {
			return errors.New("automatic NSM notification requires the dedicated client address as the NFS transport source")
		}
	}
	if ip := net.ParseIP(peer); ip == nil || ip.To4() == nil {
		return errors.New("retained NLM currently requires an IPv4 server")
	}
	cfg.Host, cfg.Transport = peer, "tcp" // Retain the control connection to detect lockd restarts.
	version := uint32(4)
	if c.Version() == "2" {
		version = 1
	}
	port := cfg.NLMPort
	if port == 0 {
		port, err = discoverNLMPort(ctx, cfg, version)
		if err != nil {
			return err
		}
	}
	rpc, err := dialConfiguredRPC(ctx, cfg, port, nlmProgram, version)
	if err != nil {
		return err
	}
	n := &nlmClient{c: c, rpc: rpc, version: version, locks: make(map[uint64]*nlmLock)}
	monitor, err := startNSMMode(ctx, cfg, peer, 111, func() { c.nfs.conn.Close(); rpc.conn.Close() }, func(ctx context.Context) error {
		d, err := rpc.call(ctx, nlmProgram, version, 0, nil, nil)
		if err != nil {
			return err
		}
		if d.err != nil || len(d.b) != 0 {
			return errors.New("invalid NLM NULL reply")
		}
		return nil
	}, recoverLocks || cfg.NLMAutoRecover)
	if err != nil {
		rpc.conn.Close()
		return err
	}
	n.monitor = monitor
	c.nlm = n
	if cfg.NLMAutoRecover && !recoverLocks {
		return n.prepareAutomaticRecovery(ctx)
	}
	return nil
}

// Complete cleanup before allowing a new acquisition. A failed attempt poisons
// this connection; retries require reopening the durable journal explicitly.
func (n *nlmClient) prepareAutomaticRecovery(ctx context.Context) (resultErr error) {
	defer func() {
		if resultErr != nil {
			n.monitor.invalidate()
		}
	}()
	if len(n.locks) != 0 {
		return errors.New("automatic NLM cleanup requires a fresh lock inventory")
	}
	for _, saved := range n.monitor.state.record.Locks {
		if !sameNLMAuth(saved.Auth, n.c.Auth) {
			return errors.New("automatic NLM cleanup requires the identity of every saved lock; use explicit nlmrecover for mixed identities")
		}
		if !saved.Confirmed || saved.Version != n.version {
			return errors.New("automatic cleanup requires confirmed acquisitions of the same protocol")
		}
	}
	if err := n.prepareCrashNotification(ctx); err != nil {
		return err
	}
	if _, err := n.recoverSavedLocks(ctx); err != nil {
		return fmt.Errorf("automatic NLM cleanup failed; no new lock acquired: %w", err)
	}
	return n.finishCrashNotification(ctx)
}

func (c *Client) lockNLM(ctx context.Context, fh []byte, write bool, offset, length uint64) (uint64, error) {
	return c.lockNLMMode(ctx, fh, write, offset, length, false)
}

func (c *Client) lockNLMMode(ctx context.Context, fh []byte, write bool, offset, length uint64, blocking bool) (uint64, error) {
	version := uint32(4)
	if c.Version() == "2" {
		version = 1
	}
	if c.Version() != "2" && c.Version() != "3" || len(fh) == 0 || len(fh) > 64 || version == 1 && len(fh) != 32 {
		return 0, errors.New("invalid legacy NLM file handle/profile")
	}
	if err := validateNLMRange(version, offset, length); err != nil {
		return 0, err
	}
	if len(c.Auth.Groups) > 16 {
		return 0, errors.New("too many AUTH_SYS groups")
	}
	if err := c.initNLM(ctx); err != nil {
		return 0, err
	}
	n := c.nlm
	if n.monitor.state.record.NotifyEpoch != 0 {
		return 0, ErrNSMNotificationUnverified
	}
	if err := n.guard(ctx); err != nil {
		return 0, err
	}
	if len(n.locks) >= 64 {
		return 0, errors.New("at most 64 NLM locks may be retained")
	}
	// Leave enough journal capacity for this acquisition's confirmation and all
	// currently held locks to be released without requiring compaction.
	if n.monitor.state.size+int64(len(n.locks)+3)*65536 > maxNSMJournal {
		return 0, errors.New("NSM journal has insufficient reserved cleanup capacity; new lock refused")
	}
	for _, held := range n.locks {
		if held.info.Uncertain {
			return 0, ErrLockUncertain
		}
		if !bytes.Equal(held.fh, fh) {
			continue
		}
		if !sameNLMAuth(held.auth, c.Auth) {
			return 0, errors.New("all NLM ranges on a file must use the same identity")
		}
		if lockRangesOverlap(offset, length, held.info.Offset, held.info.Length) {
			return 0, errors.New("NLM range overlaps a local lock")
		}
	}
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil {
		return 0, err
	}
	// Persistently monotonic IDs keep delayed recovery UNLOCKs from addressing
	// later acquisitions, including servers which ignore the opaque owner.
	svid := n.monitor.state.record.LastSVID + 1
	if svid == uint32(os.Getpid()) {
		svid++
	}
	if svid > 0x7fffffff {
		return 0, errors.New("NLM process identity counter exhausted")
	}
	n.monitor.state.record.LastSVID = svid
	n.nextID++
	auth := c.Auth
	auth.Groups = slices.Clone(auth.Groups)
	l := &nlmLock{info: LockInfo{ID: n.nextID, Write: write, Offset: offset, Length: length}, fh: slices.Clone(fh), owner: owner[:], svid: svid, auth: auth}
	n.locks[l.info.ID] = l
	if err := n.saveLocks(); err != nil {
		delete(n.locks, l.info.ID)
		n.monitor.invalidate()
		return 0, err
	}
	n.monitor.active.Store(int32(len(n.locks)))
	l.blocking = blocking
	var pending *nlmPending
	if blocking {
		pending = n.callbacks().register(l)
	}
	status, err := n.mutate(ctx, 2, l)
	if blocking {
		if err != nil {
			return n.nativeUncertain(l, err)
		}
		if status == 0 || status == 3 {
			return n.finishNativeWait(ctx, l, pending, status)
		}
		n.callbacks().remove(l)
	}
	if err == nil && status == 0 {
		err = n.guard(ctx)
		if err == nil {
			l.confirmed = true
			err = n.saveLocks()
		}
	}
	if err != nil || status == 3 {
		l.info.Uncertain = true
		n.monitor.invalidate()
		return l.info.ID, errors.Join(ErrLockUncertain, err, fmt.Errorf("NLM acquisition %d not confirmed (status %d); no replay", l.info.ID, status))
	}
	if status != 0 {
		delete(n.locks, l.info.ID)
		n.monitor.active.Store(int32(len(n.locks)))
		if err := n.saveLocks(); err != nil {
			n.monitor.invalidate()
			return 0, errors.Join(status, err)
		}
		return 0, status
	}
	return l.info.ID, nil
}

func (n *nlmClient) mutate(ctx context.Context, procedure uint32, l *nlmLock) (NLMStatus, error) {
	return n.mutateMode(ctx, procedure, l, false)
}

func (n *nlmClient) mutateMode(ctx context.Context, procedure uint32, l *nlmLock, reclaim bool) (NLMStatus, error) {
	var cookie [16]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return 0, err
	}
	var e encoder
	e.opaque(cookie[:])
	if procedure == 2 || procedure == 3 {
		if l.blocking {
			e.u32(1)
		} else {
			e.u32(0)
		}
		if l.info.Write {
			e.u32(1)
		} else {
			e.u32(0)
		}
	}
	e.str(n.monitor.cfg.NLMClientIP)
	e.opaque(l.fh)
	e.opaque(l.owner)
	e.u32(l.svid)
	encodeNLMRange(&e, n.version, l.info.Offset, l.info.Length)
	if procedure == 2 {
		if reclaim {
			e.u32(1)
		} else {
			e.u32(0)
		}
		e.u32(n.monitor.state.record.State)
	}
	d, err := n.rpc.call(ctx, nlmProgram, n.version, procedure, &l.auth, e)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(d.opaque(1024), cookie[:]) {
		return 0, errors.New("NLM mutation cookie mismatch")
	}
	status := NLMStatus(d.u32())
	if d.err != nil {
		return 0, d.err
	}
	if len(d.b) != 0 || status > 9 || n.version == 1 && status > 5 {
		return 0, errors.New("invalid NLM mutation reply")
	}
	return status, nil
}

func (n *nlmClient) unlock(ctx context.Context, id uint64) error {
	l := n.locks[id]
	if l == nil {
		return errors.New("unknown NLM lock ID")
	}
	if l.info.Uncertain {
		return ErrLockUncertain
	}
	if err := n.guard(ctx); err != nil {
		return err
	}
	if cb := n.monitor.callbacks.Load(); cb != nil {
		cb.disable(l)
	}
	status, err := n.mutate(ctx, 4, l)
	if err == nil && status == 0 {
		err = n.guard(ctx)
	}
	if err != nil || status != 0 {
		l.info.Uncertain = true
		n.monitor.invalidate()
		if status != 0 {
			err = errors.Join(err, status)
		}
		return errors.Join(ErrLockUncertain, err)
	}
	delete(n.locks, id)
	if cb := n.monitor.callbacks.Load(); cb != nil {
		cb.remove(l)
	}
	n.monitor.active.Store(int32(len(n.locks)))
	if err := n.saveLocks(); err != nil {
		n.monitor.invalidate()
		return err
	}
	return nil
}

func (n *nlmClient) saveLocks() error {
	s := n.monitor.state
	s.record.Locks = nil
	for _, l := range n.locks {
		info := l.info
		info.Uncertain = false
		s.record.Locks = append(s.record.Locks, nsmSavedLock{Version: n.version, Info: info, FH: l.fh, Owner: l.owner, SVID: l.svid, Auth: l.auth, Confirmed: l.confirmed})
	}
	s.record.Dirty = len(n.locks) > 0
	return s.append()
}

// RecoverNLMLocks releases durably confirmed pre-crash identities. It never
// reacquires a lock or replays file I/O, and refuses unresolved LOCK requests.
func (c *Client) RecoverNLMLocks(ctx context.Context) (int, error) {
	if c.Version() != "2" && c.Version() != "3" {
		return 0, errors.New("nlmrecover requires NFSv2/v3")
	}
	if c.nlm != nil || len(c.Locks()) != 0 {
		return 0, errors.New("nlmrecover requires a fresh connection without local lock state")
	}
	if err := c.initNLMMode(ctx, true); err != nil {
		return 0, err
	}
	n := c.nlm
	defer func() { n.monitor.close(); n.rpc.conn.Close(); c.nlm = nil }()
	return n.recoverSavedLocks(ctx)
}

func (n *nlmClient) recoverSavedLocks(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	for _, saved := range n.monitor.state.record.Locks {
		if !saved.Confirmed {
			return 0, errors.New("unconfirmed NLM acquisition cannot be cleaned up")
		}
		if saved.Version != n.version {
			return 0, errors.New("recovery NFS version differs from saved lock protocol")
		}
	}
	for _, saved := range n.monitor.state.record.Locks {
		n.locks[saved.Info.ID] = &nlmLock{info: saved.Info, fh: saved.FH, owner: saved.Owner, svid: saved.SVID, auth: saved.Auth, confirmed: true}
	}
	n.monitor.active.Store(int32(len(n.locks)))
	count := 0
	for id := range n.locks {
		if err := n.unlock(ctx, id); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (n *nlmClient) guard(ctx context.Context) error {
	for _, l := range n.locks {
		if l.info.Uncertain {
			return ErrLockUncertain
		}
	}
	return n.monitor.probe(ctx)
}

func sameNLMAuth(a, b Auth) bool {
	return a.UID == b.UID && a.GID == b.GID && slices.Equal(a.Groups, b.Groups)
}

func (n *nlmClient) checkIO(fh []byte, write bool) error {
	if n.monitor.lost.Load() {
		return ErrLockUncertain
	}
	for _, l := range n.locks {
		if l.info.Uncertain {
			return ErrLockUncertain
		}
		if !bytes.Equal(l.fh, fh) {
			continue
		}
		if !sameNLMAuth(l.auth, n.c.Auth) {
			return errors.New("NLM lock belongs to a different identity")
		}
		if write && !l.info.Write {
			return errors.New("writing under an NLM read lock is refused")
		}
		if l.info.Offset != 0 || l.info.Length != LockToEOF {
			return ErrPartialLockIO
		}
	}
	return nil
}

func (n *nlmClient) beforeRPC(ctx context.Context, proc uint32, e encoder) error {
	if err := n.guard(ctx); err != nil {
		return err
	}
	if scope, _ := ctx.Value(nlmRangeKey{}).(*nlmRangeScope); scope != nil {
		return scope.request(n.c, proc, e)
	}
	writeProc := uint32(7)
	if n.version == 1 {
		writeProc = 8
	}
	if proc == 6 || proc == writeProc || proc == 2 || n.version == 4 && proc == 21 {
		d := &decoder{b: e}
		var fh []byte
		if n.version == 1 {
			fh = d.take(32)
		} else {
			fh = d.opaque(64)
		}
		if d.err != nil {
			return d.err
		}
		return n.checkIO(fh, proc != 6)
	}
	return nil
}

func (n *nlmClient) close(ctx context.Context) {
	for id := range n.locks {
		if err := n.unlock(ctx, id); err != nil {
			break
		}
	}
	n.monitor.close()
	n.rpc.conn.Close()
}
