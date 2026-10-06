package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

type offloadReply struct {
	id       []byte
	count    uint64
	stable   uint32
	verifier []byte
	status   Status
}
type offloadPending struct {
	fh, id  []byte
	length  uint64
	result  *offloadReply
	journal *offloadJournal
}

func decodeOffloadReply(d *decoder) (r offloadReply) {
	n := d.u32()
	if n > 1 {
		d.err = errors.New("invalid offload callback ID count")
		return
	}
	if n == 1 {
		r.id = bytes.Clone(d.take(16))
		if len(r.id) == 16 && bytes.Equal(r.id[:4], []byte{0, 0, 0, 0}) {
			d.err = errors.New("offload callback stateid sequence must not be zero")
		}
	}
	r.count = d.u64()
	r.stable = d.u32()
	r.verifier = bytes.Clone(d.take(8))
	if r.stable > 2 {
		d.err = errors.New("invalid offload stability")
	}
	return
}
func sameOffloadReply(a, b offloadReply) bool {
	return a.count == b.count && a.stable == b.stable && a.status == b.status && bytes.Equal(a.verifier, b.verifier) && bytes.Equal(a.id, b.id)
}

func ValidateOffloadWait(wait time.Duration) error {
	if wait <= 0 || wait > 24*time.Hour {
		return errors.New("offload wait must be positive and at most 24h")
	}
	return nil
}

func (v *v4Client) beginOffload(intent offloadIntent) (func(*error), error) {
	r := v.recall
	if r == nil || !r.offloadEnabled {
		return nil, errors.New("this operation requires --offload and a negotiated backchannel")
	}
	r.mu.Lock()
	if r.offload != nil || v.stateLost.Load() {
		r.mu.Unlock()
		return nil, errors.New("offload state unavailable; reconnect before another operation")
	}
	var journal *offloadJournal
	if v.c.config != nil && v.c.config.OffloadJournal != "" {
		var err error
		intent.Target = v.c.offloadTarget()
		journal, err = openOffloadJournal(v.c.config.OffloadJournal, v.c.offloadProfile(), intent, v.c.config.OffloadSessionRecovery)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
	}
	r.offload = &offloadPending{fh: bytes.Clone(intent.Destination), length: intent.Length, journal: journal}
	r.mu.Unlock()
	if journal != nil && v.c.config.OffloadSessionRecovery {
		record := journal.record
		record.Resources = &OffloadResources{Version: 1, Complete: true}
		v.mu.Lock()
		saved, saveErr := v.saveSession()
		v.mu.Unlock()
		profile, profileErr := offloadRecoveryProfile(*v.c.config)
		if err := errors.Join(saveErr, profileErr); err != nil {
			journal.file.Close()
			return nil, err
		}
		record.Recovery = &OffloadSessionEvidence{Profile: profile, Session: saved}
		if err := journal.append(record); err != nil {
			journal.file.Close()
			return nil, err
		}
	}
	restore, err := v.installOffloadRecovery(journal)
	if err != nil {
		r.mu.Lock()
		r.offload = nil
		r.mu.Unlock()
		if journal != nil {
			err = errors.Join(err, journal.finish(err))
		}
		return nil, err
	}
	return func(resultErr *error) {
		restore()
		r.mu.Lock()
		r.offload = nil
		r.mu.Unlock()
		if journal != nil {
			if err := journal.finish(*resultErr); err != nil {
				v.stateLost.Store(true)
				*resultErr = errors.Join(*resultErr, fmt.Errorf("offload journal persistence failed; outcome remains unverified: %w", err))
			}
		}
	}, nil
}

// Sync the issued marker before any data operation or inter-server privilege.
func (v *v4Client) issueOffload() error {
	if v.recall == nil {
		return nil
	}
	v.recall.mu.Lock()
	defer v.recall.mu.Unlock()
	if v.recall.offload == nil || v.recall.offload.journal == nil {
		return nil
	}
	return v.recall.offload.journal.issue()
}

// cancelOffload never retries. Unconfirmed cancellation invalidates the session;
// a successful cancellation stops work but does not restore destination bytes.
func optionalGSSChild(children []*rpcGSS) *rpcGSS {
	if len(children) != 0 {
		return children[0]
	}
	return nil
}

func (v *v4Client) cancelOffload(fh, id []byte, cause error, children ...*rpcGSS) error {
	if v.stateLost.Load() {
		return fmt.Errorf("offload outcome unverified; server work may continue: %w", cause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := v.compoundGSS(ctx, optionalGSSChild(children), fh4(fh), op4(66, encoder(id), nil))
	if err != nil {
		v.stateLost.Store(true)
		v.c.nfs.mu.Lock()
		v.c.nfs.closeLocked()
		v.c.nfs.mu.Unlock()
		return fmt.Errorf("offload cancellation unconfirmed; server work may continue; no replay: %w", errors.Join(cause, err))
	}
	return fmt.Errorf("offload cancelled; destination may be partially modified: %w", cause)
}

func (v *v4Client) awaitOffload(ctx context.Context, fh []byte, initial offloadReply, length uint64, children ...*rpcGSS) (offloadReply, error) {
	if len(initial.id) == 0 {
		return initial, nil
	}
	r := v.recall
	r.mu.Lock()
	r.offload.id = bytes.Clone(initial.id)
	journal := r.offload.journal
	r.mu.Unlock()
	if journal != nil {
		if err := journal.callbackID(initial.id); err != nil {
			return offloadReply{}, v.cancelOffload(fh, initial.id, fmt.Errorf("persist offload callback identity: %w", err), children...)
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	polls := 0
	for {
		r.mu.Lock()
		result := r.offload.result
		r.mu.Unlock()
		if result != nil {
			return *result, nil
		}
		if v.stateLost.Load() {
			return offloadReply{}, fmt.Errorf("offload outcome unverified; server work may continue: %w", ErrLockUncertain)
		}
		select {
		case <-ctx.Done():
			return offloadReply{}, v.cancelOffload(fh, initial.id, ctx.Err(), children...)
		case <-ticker.C:
			polls++
			if polls%5 != 0 {
				continue
			}
			var count uint64
			var complete bool
			var status Status
			err := v.compoundGSS(ctx, optionalGSSChild(children), fh4(fh), op4(67, encoder(initial.id), func(d *decoder) {
				count = d.u64()
				n := d.u32()
				if n > 1 {
					d.err = errors.New("invalid OFFLOAD_STATUS completion count")
					return
				}
				complete = n == 1
				if complete {
					status = Status(d.u32())
				}
				if count > length {
					d.err = errors.New("OFFLOAD_STATUS exceeds requested length")
				}
			}))
			if err != nil {
				var status Status
				if errors.As(err, &status) && !v.stateLost.Load() {
					r.mu.Lock()
					result := r.offload.result
					r.mu.Unlock()
					if result != nil {
						return *result, nil
					}
				}
				return offloadReply{}, v.cancelOffload(fh, initial.id, err, children...)
			}
			if complete && status != 0 {
				return offloadReply{count: count, status: status}, nil
			}
			// Successful STATUS lacks a durability verifier. Wait for CB_OFFLOAD.
		}
	}
}

func (v *v4Client) finishOffload(ctx context.Context, fh []byte, offset, length uint64, r offloadReply) (uint64, error) {
	if r.count > length {
		return 0, errors.New("offload result exceeds requested length")
	}
	if r.status != 0 {
		return r.count, fmt.Errorf("offload failed after %d bytes; destination may be modified: %w", r.count, r.status)
	}
	if v.stateLost.Load() {
		return r.count, ErrLockUncertain
	}
	if err := v.checkLockedIO(fh, 2); err != nil {
		return r.count, err
	}
	if r.stable < 2 && r.count > 0 {
		var e encoder
		e.u64(offset)
		e.u32(0)
		var verifier []byte
		if err := v.compound(ctx, fh4(fh), op4(5, e, func(d *decoder) { verifier = bytes.Clone(d.take(8)) })); err != nil {
			return r.count, fmt.Errorf("offload acknowledged but durability unverified: %w", err)
		}
		if !bytes.Equal(verifier, r.verifier) {
			return r.count, errors.New("offload COMMIT verifier changed; no replay")
		}
	}
	if r.count != length {
		return r.count, fmt.Errorf("offload changed %d of %d bytes; no continuation: %w", r.count, length, io.ErrShortWrite)
	}
	return r.count, nil
}

// ValidateWriteSame bounds one repeated, fully specified block and its total
// range. ADB block numbering is disabled; the pattern fills the entire block.
func ValidateWriteSame(offset, count uint64, pattern []byte) (uint64, error) {
	if len(pattern) == 0 || len(pattern) > 4096 || count == 0 || count > ^uint64(0)/uint64(len(pattern)) {
		return 0, errors.New("WRITE_SAME needs a 1..4096-byte pattern and a positive nonoverflowing repeat count")
	}
	length := count * uint64(len(pattern))
	return length, ValidateSpaceRange(offset, length)
}

// WriteApplicationDataBlocks issues one WRITE_SAME and waits for synchronous or callback
// completion. Unknown mutations are never replayed or emulated with WRITE.
func (c *Client) WriteApplicationDataBlocks(ctx context.Context, fh []byte, b ApplicationDataBlock, wait time.Duration) (written uint64, resultErr error) {
	if c.config != nil && c.config.OffloadReconcile {
		return 0, errors.New("automatic reconciliation recording supports synchronous intra-server COPY/CLONE only")
	}
	if c.v4 == nil || c.v4.minor != 2 {
		return 0, ErrRequiresV42
	}
	length, err := ValidateApplicationDataBlock(b)
	if err != nil {
		return 0, err
	}
	if err := ValidateOffloadWait(wait); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	v := c.v4
	end, err := v.beginOffload(offloadIntent{Operation: "writesame", Destination: fh, Offset: b.Offset, Length: length})
	if err != nil {
		return 0, err
	}
	defer end(&resultErr)
	if err := c.prepareOffloadExpectation(ctx, nil, nil, fh, 0, b.Offset, length, &b); err != nil {
		return 0, err
	}
	sid, closeIO, err := v.offloadOpenIO(ctx, fh, 2)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	e := append(encoder(nil), sid...)
	e.u32(2)
	e.u64(b.Offset)
	e.u64(b.BlockSize)
	e.u64(b.BlockCount)
	if b.FirstNumber == nil {
		e.u64(^uint64(0))
		e.u32(0)
	} else {
		e.u64(b.NumberOffset)
		e.u32(*b.FirstNumber)
	}
	if len(b.Pattern) == 0 {
		e.u64(^uint64(0))
	} else {
		e.u64(b.PatternOffset)
	}
	e.opaque(b.Pattern)
	if err := v.issueOffload(); err != nil {
		return 0, err
	}
	var reply offloadReply
	if err := v.compound(ctx, fh4(fh), op4(70, e, func(d *decoder) {
		reply = decodeOffloadReply(d)
		if reply.count > length || len(reply.id) > 0 && !bytes.Equal(reply.id, sid) {
			d.err = errors.New("invalid WRITE_SAME result identity or count")
		}
	})); err != nil {
		var status Status
		if errors.As(err, &status) {
			return 0, err
		}
		return 0, fmt.Errorf("WRITE_SAME outcome unverified; server work may continue; no replay: %w", err)
	}
	reply, err = v.awaitOffload(ctx, fh, reply, length)
	if err != nil {
		return 0, err
	}
	return v.finishOffload(ctx, fh, b.Offset, length, reply)
}
