package nfs

import (
	"context"
	"encoding/binary"
	"errors"
	"time"
)

func savedLockDataRequest(s SavedCompound) bool {
	if len(s.Operations) != 2 || s.Operations[0].Code != 22 {
		return false
	}
	op := s.Operations[1]
	return op.Code == 38 && len(op.Args) >= 32 || op.Code == 5 && len(op.Args) == 12
}

func (j *lockJournal) capturePending(saved SavedCompound) error {
	if !savedLockDataRequest(saved) && !savedIntentMatches(j.record, saved) {
		return nil
	}
	r := j.record
	r.PendingRequest = &saved
	return j.append(r)
}

func (j *lockJournal) recoverPending(ctx context.Context, cfg Config) error {
	r := j.record
	if r.PendingRequest == nil || !savedLockDataRequest(*r.PendingRequest) {
		return ErrLockJournalPending
	}
	s := SavedSession{Minor: r.PendingRequest.Minor, Sequence: r.Slot, LeaseSeconds: r.Lease, ReadSize: r.ReadSize, WriteSize: r.WriteSize, ClientID: r.ClientID, ServerMinor: r.ServerMinor, Nonce: r.Nonce, Session: r.Session, Root: r.Root, Owner: r.Owner, Scope: r.Scope, Channel: r.Channel, Confirmed: r.Confirmed, Auth: r.Auth, Identity: r.Identity, Principal: r.Principal}
	c, err := connectSavedSession(ctx, cfg, s)
	if err != nil {
		return err
	}
	defer c.Close() // Borrowed session: close only this recovery transport.
	if c.nfs.conn.RemoteAddr().String() != r.Peer {
		return errors.New("saved pending request endpoint changed")
	}
	op := r.PendingRequest.Operations[1]
	receipt := &LockRequestReceipt{Operation: op.Code}
	decode := func(d *decoder) { d.take(8) } // COMMIT verifier; command is not resumed.
	if op.Code == 38 {
		decode = func(d *decoder) {
			receipt.Count = d.u32()
			stable := d.u32()
			d.take(8)
			requested := binary.BigEndian.Uint32(op.Args[28:])
			if receipt.Count == 0 || receipt.Count > requested || stable != 2 {
				d.err = errors.New("recovered WRITE is unstable or invalid; retain quarantine")
			}
		}
	}
	ops := []v4Op{op4(22, encoder(r.PendingRequest.Operations[0].Args), nil), op4(op.Code, encoder(op.Args), decode)}
	started := time.Now()
	err = c.v4.replaySavedCompound(ctx, *r.PendingRequest, ops...)
	if !cachedReplayConfirmed(err, r.Slot, c.v4.sequence, c.v4.stateLost.Load()) {
		if err == nil {
			err = ErrLockJournalPending
		}
		return err
	}
	var status Status
	if errors.As(err, &status) {
		receipt.Status = uint32(status)
	}
	// Resolve and durably synchronize the slot before subsequent validation
	// consumes another sequence. A process crash can now use clean recovery.
	r.Pending, r.PendingRequest = false, nil
	r.Slot, r.Confirmed, r.RecoveredRequest = c.v4.sequence, started, receipt
	return j.append(r)
}
