package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"slices"
	"strconv"
)

const maxReconcileBytes = 16 << 20

// A receipt is saved only after a synchronous operation and its durability
// checks complete. It authorizes verification, never mutation replay.
type OffloadReconcileEvidence struct {
	ExpectedSHA256, RecoveryProfile string
	Size, FSID, FSIDMinor, FileID   uint64
	Receipt                         bool
}

func validateOffloadReconcile(r, previous OffloadRecord) error {
	e := r.Reconcile
	if e != nil {
		digest, err := hex.DecodeString(e.ExpectedSHA256)
		profile, profileErr := hex.DecodeString(e.RecoveryProfile)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != e.ExpectedSHA256 || profileErr != nil || len(profile) != 32 || hex.EncodeToString(profile) != e.RecoveryProfile || e.Size == 0 || e.Size > maxReconcileBytes || e.Size != r.Length || r.Offset != 0 || r.SourceOffset != 0 || r.Operation != "copyrange" && r.Operation != "clonerange" || len(r.Source) == 0 || e.Receipt && r.Phase != "issued" {
			return errors.New("invalid automatic offload reconciliation evidence")
		}
	}
	if previous.Sequence == 0 || !previous.Pending {
		return nil
	}
	if previous.Reconcile == nil {
		if e != nil && (previous.Phase != "prepared" || r.Phase != "prepared" || e.Receipt) {
			return errors.New("reconciliation evidence appeared after issue")
		}
	} else {
		if e == nil {
			return errors.New("reconciliation evidence removed")
		}
		before, after := *previous.Reconcile, *e
		before.Receipt, after.Receipt = false, false
		if before != after || previous.Reconcile.Receipt && !e.Receipt {
			return errors.New("reconciliation intent or receipt changed")
		}
	}
	return nil
}

type boundedOffloadDigest struct {
	h         hash.Hash
	remaining uint64
}

func (d *boundedOffloadDigest) Write(p []byte) (int, error) {
	if uint64(len(p)) > d.remaining {
		return 0, errors.New("offload file grew beyond the recorded whole-file bound")
	}
	n, err := d.h.Write(p)
	d.remaining -= uint64(n)
	return n, err
}

func reconcileAttributes(a Attr) bool {
	return a.Type == 1 && a.HasSize && a.HasFSID && a.HasFileID && a.HasChange && a.HasMTime && a.HasCTime
}

func sameReconcileAttributes(a, b Attr) bool {
	return reconcileAttributes(a) && reconcileAttributes(b) && a.Type == b.Type && a.Size == b.Size && a.FSID == b.FSID && a.FSIDMinor == b.FSIDMinor && a.FileID == b.FileID && a.Change == b.Change && a.MTime.Equal(b.MTime) && a.CTime.Equal(b.CTime) && a.Mode == b.Mode && a.Owner == b.Owner && a.Group == b.Group && a.UID == b.UID && a.GID == b.GID
}

func (c *Client) prepareOffloadReconcile(ctx context.Context, source, destination []byte, length uint64) error {
	if c.config.OffloadJournal == "" {
		return errors.New("automatic reconciliation recording requires an offload journal")
	}
	cfg := *c.config
	cfg.Offload = false
	profile, err := lockProfile(cfg)
	if err != nil {
		return err
	}
	src, err := c.GetAttr(ctx, source)
	if err != nil {
		return err
	}
	dst, err := c.GetAttr(ctx, destination)
	if err != nil {
		return err
	}
	if !reconcileAttributes(src) || !reconcileAttributes(dst) || src.Size != length || dst.Size != length {
		return errors.New("reconciliation recording requires complete equal-size regular files with stable identity/change attributes")
	}
	digest := &boundedOffloadDigest{h: sha256.New(), remaining: length}
	n, err := c.ReadTo(ctx, source, digest)
	if err != nil {
		return err
	}
	if uint64(n) != length || digest.remaining != 0 {
		return io.ErrUnexpectedEOF
	}
	check, err := c.GetAttr(ctx, source)
	if err != nil {
		return err
	}
	if !sameReconcileAttributes(src, check) {
		return errors.New("offload source changed while recording expected bytes")
	}
	r := c.v4.recall
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.offload == nil || r.offload.journal == nil {
		return errors.New("reconciliation journal unavailable")
	}
	j := r.offload.journal
	record := j.record
	record.Reconcile = &OffloadReconcileEvidence{ExpectedSHA256: hex.EncodeToString(digest.h.Sum(nil)), RecoveryProfile: profile, Size: length, FSID: dst.FSID, FSIDMinor: dst.FSIDMinor, FileID: dst.FileID}
	return j.append(record)
}

func (v *v4Client) offloadReconcileReceipt() error {
	r := v.recall
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.offload == nil || r.offload.journal == nil || r.offload.journal.record.Reconcile == nil {
		return errors.New("completion receipt lacks recorded expectation")
	}
	j := r.offload.journal
	record := j.record
	e := *record.Reconcile
	e.Receipt = true
	record.Reconcile = &e
	if err := j.append(record); err != nil {
		v.stateLost.Store(true)
		return err
	}
	return nil
}

// ReconcileOffload automatically verifies a receipt-confirmed issued operation
// after a process crash. Unknown/unreceipted operations remain quarantined.
// Only fresh READ/OPEN/LOCK/COMMIT/cleanup are used; no COPY or WRITE is replayed.
func (c *Client) ReconcileOffload(ctx context.Context, path, id string, destination []byte) (resultErr error) {
	if c.config == nil || c.Version() != "4.2" || c.v4 == nil || c.v4.stateLost.Load() || len(c.Locks()) != 0 {
		return errors.New("offload reconciliation requires a fresh ordinary protected NFSv4.2 connection without locks")
	}
	profile, err := lockProfile(*c.config)
	if err != nil {
		return err
	}
	port := c.config.NFSPort
	if port == 0 {
		port = 2049
	}
	if err = c.ValidateReadReplica(ReadReplica{Address: net.JoinHostPort(c.config.Host, strconv.Itoa(port)), SPN: c.config.Kerberos.SPN, TLSName: c.config.TLS.ServerName}); err != nil {
		return err
	}
	j, err := loadOffloadJournal(path, false)
	if err != nil {
		return err
	}
	defer j.file.Close()
	r := j.record
	if !r.Pending || r.Phase != "issued" || r.ID != id || r.Reconcile == nil || !r.Reconcile.Receipt || r.Profile != c.offloadProfile() || r.Reconcile.RecoveryProfile != profile || !bytes.Equal(r.Destination, destination) {
		return ErrOffloadPending
	}
	e := r.Reconcile
	auth := c.Auth
	auth.Groups = append([]uint32(nil), auth.Groups...)
	identity := c.Identity()
	before, err := c.GetAttr(ctx, destination)
	if err != nil {
		return err
	}
	if !reconcileAttributes(before) || before.Size != e.Size || before.FSID != e.FSID || before.FSIDMinor != e.FSIDMinor || before.FileID != e.FileID {
		return errors.New("offload destination identity or whole-file size changed")
	}
	lock, err := c.Lock(ctx, destination, false)
	if err != nil {
		return err
	}
	released := false
	defer func() {
		if !released {
			resultErr = errors.Join(resultErr, c.Unlock(ctx, lock))
		}
	}()
	// Synchronize the known completed operation's current bytes, then compare
	// the full file under fresh advisory read state and stable metadata.
	var commit encoder
	commit.u64(0)
	commit.u32(0)
	if err = c.v4.compound(ctx, fh4(destination), op4(5, commit, func(d *decoder) { d.take(8) })); err != nil {
		return err
	}
	digest := &boundedOffloadDigest{h: sha256.New(), remaining: e.Size}
	n, err := c.ReadTo(ctx, destination, digest)
	if err != nil {
		return err
	}
	if uint64(n) != e.Size || digest.remaining != 0 || hex.EncodeToString(digest.h.Sum(nil)) != e.ExpectedSHA256 {
		return errors.New("offload destination differs from the pre-issue expected bytes; no repair or replay")
	}
	after, err := c.GetAttr(ctx, destination)
	if err != nil {
		return err
	}
	if !sameReconcileAttributes(before, after) || c.Identity() != identity || c.Auth.UID != auth.UID || c.Auth.GID != auth.GID || !slices.Equal(c.Auth.Groups, auth.Groups) {
		return errors.New("offload metadata or credentials changed during verification")
	}
	err = c.Unlock(ctx, lock)
	released = true // Never repeat cleanup after its outcome becomes uncertain.
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	r.Pending = false
	r.Outcome = "reconciled-verified"
	return j.append(r)
}
