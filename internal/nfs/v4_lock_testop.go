package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
)

// testLock uses a fresh owner so the server does not exempt this client's
// retained locks. RFC 8881 18.11 requires neither OPEN nor a lock stateid.
func (v *v4Client) testLock(ctx context.Context, fh []byte, write bool, offset, length uint64) (*LockConflict, error) {
	if err := ValidateLockRange(offset, length); err != nil {
		return nil, err
	}
	if len(fh) == 0 || len(fh) > 128 {
		return nil, errors.New("invalid NFSv4 handle for LOCKT")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil {
		return nil, err
	}
	var e encoder
	kind := uint32(1)
	if write {
		kind = 2
	}
	e.u32(kind)
	e.u64(offset)
	e.u64(length)
	// v4.0 needs the confirmed client ID. v4.1+ derives it from SEQUENCE.
	clientID := uint64(0)
	if v.minor == 0 {
		clientID = v.clientID
	}
	e.u64(clientID)
	e.opaque(owner[:])
	var conflict *LockConflict
	var status Status
	op := op4(13, e, nil)
	op.result = func(s Status) { status = s }
	op.failure = func(d *decoder) {
		if status != 10010 {
			return
		}
		conflict = &LockConflict{Protocol: "NFSv4", Offset: d.u64(), Length: d.u64()}
		typ := d.u32()
		conflict.Write = typ == 2 || typ == 4
		conflict.ClientID = d.u64()
		conflict.Owner = bytes.Clone(d.opaque(1024))
		if d.err == nil && (typ < 1 || typ > 4 || ValidateLockRange(conflict.Offset, conflict.Length) != nil || !write && !conflict.Write || !lockRangesOverlap(offset, length, conflict.Offset, conflict.Length)) {
			d.err = errors.New("invalid or nonconflicting NFSv4 LOCKT denial")
		}
	}
	err := v.compound(ctx, fh4(fh), op)
	if errors.Is(err, Status(10010)) && conflict != nil {
		return conflict, nil
	}
	return nil, err
}
