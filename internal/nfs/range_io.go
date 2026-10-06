package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"slices"
)

func (c *Client) rangeLock(fh []byte, offset, length uint64, write bool) (*v4Lock, error) {
	if length == 0 || length > math.MaxInt64 || offset > math.MaxInt64-length {
		return nil, errors.New("transfer range must be nonempty and fit a signed 64-bit file size")
	}
	if c.v4 == nil {
		return nil, errors.New("range transfers require a retained NFSv4 lock")
	}
	if c.v4.stateLost.Load() {
		return nil, ErrLockUncertain
	}
	var selected *v4Lock
	for _, l := range c.v4.locks {
		if !bytes.Equal(l.file.fh, fh) {
			continue
		}
		if l.info.Uncertain {
			return nil, ErrLockUncertain
		}
		if l.file.auth.UID != c.Auth.UID || l.file.auth.GID != c.Auth.GID || !slices.Equal(l.file.auth.Groups, c.Auth.Groups) {
			return nil, errors.New("restore the locked identity before range I/O")
		}
		if write && !l.info.Write || offset < l.info.Offset {
			continue
		}
		delta := offset - l.info.Offset
		if l.info.Length == LockToEOF || delta <= l.info.Length && length <= l.info.Length-delta {
			selected = l
		}
	}
	if selected == nil {
		return nil, errors.New("one confirmed lock must cover the complete transfer range with the required access")
	}
	return selected, nil
}

// RequireRangeLock checks coverage without acquiring, upgrading or merging locks.
func (c *Client) RequireRangeLock(fh []byte, offset, length uint64, write bool) error {
	if c.v4 == nil {
		_, err := c.nlmRangeLock(fh, offset, length, write)
		return err
	}
	_, err := c.rangeLock(fh, offset, length, write)
	return err
}

// ReadRangeToProgress reads exactly length bytes under retained NLM or NFSv4 state.
// Early EOF, uncertainty and out-of-range access are explicit failures.
func (c *Client) ReadRangeToProgress(ctx context.Context, fh []byte, offset, length uint64, w io.Writer, progress func(uint64)) (int64, error) {
	if c.v4 == nil {
		return c.readNLMRange(ctx, fh, offset, length, w, progress)
	}
	l, err := c.rangeLock(fh, offset, length, false)
	if err != nil {
		return 0, err
	}
	var count uint64
	for count < length {
		if err := ctx.Err(); err != nil {
			return int64(count), err
		}
		if err := c.RequireRangeLock(fh, offset, length, false); err != nil {
			return int64(count), err
		}
		var e encoder
		e = append(e, l.sid...)
		e.u64(offset + count)
		limit := uint32(min(uint64(c.ReadSize), length-count))
		e.u32(limit)
		var data []byte
		var eof bool
		if err := c.v4.compound(ctx, fh4(fh), op4(25, e, func(d *decoder) { eof = d.boolean(); data = d.opaque(limit) })); err != nil {
			return int64(count), err
		}
		if err := c.RequireRangeLock(fh, offset, length, false); err != nil {
			return int64(count), err
		}
		n, err := w.Write(data)
		count += uint64(n)
		if progress != nil {
			progress(count)
		}
		if err != nil {
			return int64(count), err
		}
		if err := ctx.Err(); err != nil {
			return int64(count), err
		}
		if n != len(data) {
			return int64(count), io.ErrShortWrite
		}
		if eof && count != length {
			return int64(count), io.ErrUnexpectedEOF
		}
		if n == 0 {
			return int64(count), io.ErrNoProgress
		}
	}
	return int64(count), nil
}

// WriteRangeFromProgress updates the requested bytes in place, without rollback
// or replay. Bytes outside the range are never submitted to WRITE.
func (c *Client) WriteRangeFromProgress(ctx context.Context, fh []byte, offset, length uint64, r io.Reader, progress func(uint64)) (int64, error) {
	if c.v4 == nil {
		return c.writeNLMRange(ctx, fh, offset, length, r, progress)
	}
	l, err := c.rangeLock(fh, offset, length, true)
	if err != nil {
		return 0, err
	}
	check := func() error { return c.RequireRangeLock(fh, offset, length, true) }
	n, err := c.v4.writeAtState(ctx, fh, io.LimitReader(r, int64(length)), progress, offset, l.sid, check, check)
	if err == nil && uint64(n) != length {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
