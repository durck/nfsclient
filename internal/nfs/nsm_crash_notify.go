package nfs

import (
	"context"
	"errors"
	"math"
)

// ErrNSMNotificationUnverified means that NSM cannot establish when the
// server's separate lockd cleanup has finished. The durable journal is retained
// and new locks are forbidden, even after an acknowledged notification.
var ErrNSMNotificationUnverified = errors.New("NSM notification receipt provides no server lock-cleanup barrier; pending journal retained and new locks quarantined")

// Persist notification intent before cleanup, including its last UNLOCK. A
// death at any later boundary must not forget the crash or choose a new epoch.
func (n *nlmClient) prepareCrashNotification(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s := n.monitor.state
	enabled := n.c.config != nil && n.c.config.NLMAutoNotify
	if s.record.NotifyEpoch != 0 && !enabled {
		return errors.New("pending NSM notification requires explicit automatic notification")
	}
	if !enabled || s.record.NotifyEpoch != 0 || !s.record.Dirty {
		return nil
	}
	if s.record.State > math.MaxInt32-2 {
		return errors.New("NSM notification epoch exhausted; cleanup refused")
	}
	s.record.NotifyEpoch = s.record.State + 2
	return s.append()
}

// SM_NOTIFY has a void result: its acknowledgement cannot prove lock removal.
// Exact confirmed-owner cleanup therefore precedes notification. Even a reply
// cannot release the new-LOCK gate: delayed host-wide cleanup can delete a new
// lock. The advanced durable epoch marks a possible send, never a completion.
func (n *nlmClient) finishCrashNotification(ctx context.Context) error {
	s := n.monitor.state
	if s.record.NotifyEpoch == 0 {
		return nil
	}
	if n.c.config == nil || !n.c.config.NLMAutoNotify || s.record.Dirty || len(s.record.Locks) != 0 || len(n.locks) != 0 {
		return errors.New("NSM notification requires enabled, complete confirmed-owner cleanup")
	}
	if s.record.State == s.record.NotifyEpoch {
		// Includes older journals and death after syncing but before sending.
		// Delivery is ambiguous, so do not queue another host-wide cleanup.
		return ErrNSMNotificationUnverified
	}
	if err := n.monitor.probe(ctx); err != nil {
		return err
	}
	if s.record.State != s.record.NotifyEpoch {
		s.record.State = s.record.NotifyEpoch
		if err := s.append(); err != nil {
			return err
		}
		n.monitor.localEpoch.Store(s.record.State)
	}
	n.monitor.probeMu.Lock()
	defer n.monitor.probeMu.Unlock()
	if n.monitor.lost.Load() {
		return ErrLockUncertain
	}
	var e encoder
	e.str(s.record.Address)
	e.u32(s.record.NotifyEpoch)
	d, err := n.monitor.statRPC.call(ctx, nsmProgram, 1, 6, nil, e)
	if err != nil {
		return errors.Join(ErrNSMNotificationUnverified, err)
	}
	if d.err != nil || len(d.b) != 0 {
		return errors.Join(ErrNSMNotificationUnverified, errors.New("SM_NOTIFY did not return an empty acknowledgement"))
	}
	// Record receipt separately from completion. SM_STAT only reports statd's
	// own epoch, and neither it nor NLM TEST is a lockd callback barrier.
	s.record.NotifyAcknowledged = true
	if err := s.append(); err != nil {
		return errors.Join(ErrNSMNotificationUnverified, err)
	}
	return ErrNSMNotificationUnverified
}
