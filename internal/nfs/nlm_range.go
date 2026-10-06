package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
)

type nlmRangeKey struct{}
type nlmRangeScope struct {
	n              *nlmClient
	lock           *nlmLock
	fh             []byte
	offset, length uint64
	write          bool
}

func (c *Client) nlmRangeLock(fh []byte, offset, length uint64, write bool) (*nlmLock, error) {
	if length == 0 || length > math.MaxInt64 || offset > math.MaxInt64-length {
		return nil, errors.New("transfer range must be nonempty and fit a signed 64-bit file size")
	}
	if c.Version() != "2" && c.Version() != "3" || c.nlm == nil || c.nlm.monitor == nil {
		return nil, errors.New("range transfers require a retained NLM lock")
	}
	if len(fh) == 0 || len(fh) > 64 || c.Version() == "2" && (len(fh) != 32 || offset+length > maxV2File) {
		return nil, errors.New("invalid legacy range handle or NFSv2 size limit")
	}
	n := c.nlm
	if n.monitor.lost.Load() {
		return nil, ErrLockUncertain
	}
	for _, l := range n.locks {
		if l.info.Uncertain || !l.confirmed {
			return nil, ErrLockUncertain
		}
	}
	for _, l := range n.locks {
		if !bytes.Equal(l.fh, fh) {
			continue
		}
		if !sameNLMAuth(l.auth, c.Auth) {
			return nil, errors.New("NLM lock belongs to a different identity")
		}
		if write && !l.info.Write || offset < l.info.Offset {
			continue
		}
		delta := offset - l.info.Offset
		if l.info.Length == LockToEOF || delta <= l.info.Length && length <= l.info.Length-delta {
			return l, nil
		}
	}
	return nil, errors.New("one confirmed NLM lock must cover the complete transfer range with the required access")
}

func (s *nlmRangeScope) check(c *Client) error {
	l, err := c.nlmRangeLock(s.fh, s.offset, s.length, s.write)
	if err != nil {
		return err
	}
	if c.nlm != s.n || l != s.lock {
		return errors.New("range I/O lost its original NLM acquisition")
	}
	return nil
}

// A private per-call scope preserves the whole-file guard on ordinary APIs.
// No mutable client-wide bypass survives a transfer or reaches its callbacks.
func (c *Client) nlmRangeContext(ctx context.Context, fh []byte, offset, length uint64, write bool) (context.Context, *nlmRangeScope, error) {
	l, err := c.nlmRangeLock(fh, offset, length, write)
	if err != nil {
		return ctx, nil, err
	}
	s := &nlmRangeScope{n: c.nlm, lock: l, fh: bytes.Clone(fh), offset: offset, length: length, write: write}
	return context.WithValue(ctx, nlmRangeKey{}, s), s, nil
}

func (s *nlmRangeScope) request(c *Client, proc uint32, e encoder) error {
	if err := s.check(c); err != nil {
		return err
	}
	d := &decoder{b: e}
	var fh []byte
	var offset, length uint64
	if c.Version() == "2" {
		fh = d.take(32)
		switch proc {
		case 6:
			offset = uint64(d.u32())
			length = uint64(d.u32())
			d.u32()
		case 8:
			d.u32()
			offset = uint64(d.u32())
			d.u32()
			length = uint64(len(d.opaque(8192)))
		default:
			return errors.New("unsupported RPC in NLM range transfer")
		}
	} else {
		fh = d.opaque(64)
		offset = d.u64()
		length = uint64(d.u32())
		switch proc {
		case 6, 21:
		case 7:
			d.u32()
			if uint64(len(d.opaque(c.WriteSize))) != length {
				return errors.New("range WRITE count mismatch")
			}
		default:
			return errors.New("unsupported RPC in NLM range transfer")
		}
	}
	if d.err != nil || len(d.b) != 0 || !bytes.Equal(fh, s.fh) || proc != 6 && !s.write || length == 0 || offset < s.offset || offset-s.offset > s.length || length > s.length-(offset-s.offset) {
		return errors.New("RPC exceeds the authorized NLM transfer range")
	}
	return nil
}

func (c *Client) readNLMRange(ctx context.Context, fh []byte, offset, length uint64, w io.Writer, progress func(uint64)) (int64, error) {
	ctx, s, err := c.nlmRangeContext(ctx, fh, offset, length, false)
	if err != nil {
		return 0, err
	}
	if c.ReadSize == 0 {
		return 0, errors.New("zero range read size")
	}
	var count uint64
	for count < length {
		if err := ctx.Err(); err != nil {
			return int64(count), err
		}
		limit := uint32(min(uint64(c.ReadSize), length-count))
		var e encoder
		if c.Version() == "2" {
			limit = min(limit, 8192)
			e = append(e, fh...)
			e.u32(uint32(offset + count))
			e.u32(limit)
			e.u32(0)
		} else {
			e.opaque(fh)
			e.u64(offset + count)
			e.u32(limit)
		}
		d, err := c.call(ctx, 6, e)
		if err != nil {
			return int64(count), err
		}
		var data []byte
		var eof bool
		if c.Version() == "2" {
			a := attr2(d)
			data = d.opaque(limit)
			eof = offset+count+uint64(len(data)) >= a.Size
			if a.Type != 1 || a.Size > maxV2File {
				return int64(count), errors.New("invalid NFSv2 range attributes")
			}
		} else {
			postAttr(d)
			size := d.u32()
			eof = d.boolean()
			data = d.opaque(limit)
			if size != uint32(len(data)) {
				return int64(count), errors.New("range READ count mismatch")
			}
		}
		if d.err != nil {
			return int64(count), d.err
		}
		if len(d.b) != 0 {
			return int64(count), errors.New("trailing range READ reply")
		}
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return int64(count), errors.New("invalid range writer count")
		}
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
		if err := s.check(c); err != nil {
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
	return int64(count), s.n.guard(ctx)
}

func (c *Client) writeNLMRange(ctx context.Context, fh []byte, offset, length uint64, r io.Reader, progress func(uint64)) (int64, error) {
	ctx, s, err := c.nlmRangeContext(ctx, fh, offset, length, true)
	if err != nil {
		return 0, err
	}
	write := c.write3At
	if c.Version() == "2" {
		write = c.write2At
	}
	n, err := write(ctx, fh, io.LimitReader(r, int64(length)), progress, offset)
	if err != nil {
		return n, err
	}
	if uint64(n) != length {
		return n, io.ErrUnexpectedEOF
	}
	if err := s.check(c); err != nil {
		return n, err
	}
	return n, s.n.guard(ctx)
}
