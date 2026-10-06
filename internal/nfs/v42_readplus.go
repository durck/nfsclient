package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
)

type readPlusPart struct {
	offset, end uint64
	data        []byte // nil means a hole; no hole-sized allocation is made.
}

// Validate the complete reply before giving any of its content to a writer.
// Only a hole may begin before or extend beyond the requested interval.
func decodeReadPlus(d *decoder, offset uint64, count uint32) ([]readPlusPart, bool, uint64) {
	if count > 1<<20 || offset > math.MaxUint64-uint64(count) {
		d.err = errors.New("invalid READ_PLUS requested interval")
		return nil, false, offset
	}
	eof := d.boolean()
	n := d.u32()
	if n > 1024 {
		d.err = errors.New("READ_PLUS exceeds 1024 segments")
		return nil, false, offset
	}
	parts := make([]readPlusPart, 0, n)
	end := offset
	for i := uint32(0); i < n && d.err == nil; i++ {
		kind := d.u32()
		start := d.u64()
		var data []byte
		var length uint64
		switch kind {
		case 0:
			data = d.opaque(count)
			length = uint64(len(data))
		case 1:
			length = d.u64()
		default:
			d.err = errors.New("unknown READ_PLUS content kind")
			continue
		}
		if d.err != nil {
			break
		}
		if start > math.MaxUint64-length {
			d.err = errors.New("READ_PLUS extent overflow")
			break
		}
		stop := start + length
		if length == 0 {
			if n != 1 || !eof || start != offset {
				d.err = errors.New("invalid empty READ_PLUS segment")
			}
		} else if (i == 0 && (start > offset || stop <= offset || (kind == 0 && start != offset))) || (i > 0 && start != end) {
			d.err = errors.New("noncontiguous READ_PLUS segments")
		}
		requestEnd := offset + uint64(count)
		if (kind == 0 && stop > requestEnd) || (i+1 < n && stop >= requestEnd) {
			d.err = errors.New("READ_PLUS data exceeds requested interval")
		}
		parts = append(parts, readPlusPart{offset: start, end: stop, data: data})
		end = stop
	}
	if d.err == nil && !eof && end == offset {
		d.err = io.ErrNoProgress
	}
	return parts, eof, end
}

// ReadPlusToProgress reads the expected logical size using NFSv4.2 READ_PLUS.
// Holes become bounded zero writes; this saves network payload, not local disk
// space. The caller must verify the source attributes before publication.
func (c *Client) ReadPlusToProgress(ctx context.Context, fh []byte, size uint64, w io.Writer, progress func(uint64)) (count int64, resultErr error) {
	if c.v4 == nil || c.v4.minor != 2 {
		return 0, ErrRequiresV42
	}
	if size > math.MaxInt64 || c.ReadSize == 0 {
		return 0, errors.New("invalid READ_PLUS file or read size")
	}
	v := c.v4
	sid, closeIO, err := v.openIO(ctx, fh, 1)
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeIO()) }()
	zeros := make([]byte, 32768)
	for {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if err := v.checkLockedIO(fh, 1); err != nil {
			return count, err
		}
		offset := uint64(count)
		limit := uint32(min(uint64(c.ReadSize), uint64(1<<20), size-offset))
		e := append(encoder(nil), sid...)
		e.u64(offset)
		e.u32(limit)
		var parts []readPlusPart
		var eof bool
		var end uint64
		if err := v.compound(ctx, fh4(fh), op4(68, e, func(d *decoder) { parts, eof, end = decodeReadPlus(d, offset, limit) })); err != nil {
			return count, err
		}
		if err := v.checkLockedIO(fh, 1); err != nil {
			return count, err
		}
		if eof && end < size {
			return count, fmt.Errorf("READ_PLUS source ended early: %w", io.ErrUnexpectedEOF)
		}
		for _, part := range parts {
			start, stop := max(offset, part.offset), min(part.end, offset+uint64(limit))
			for start < stop {
				if err := ctx.Err(); err != nil {
					return count, err
				}
				if err := v.checkLockedIO(fh, 1); err != nil {
					return count, err
				}
				next := min(stop-start, uint64(len(zeros)))
				data := zeros[:next]
				if part.data != nil {
					data = part.data[start-part.offset : start-part.offset+next]
				}
				n, err := w.Write(data)
				if n < 0 || n > len(data) {
					return count, io.ErrShortWrite
				}
				count += int64(n)
				start += uint64(n)
				if progress != nil {
					progress(uint64(count))
				}
				if err != nil {
					return count, err
				}
				if n != len(data) {
					return count, io.ErrShortWrite
				}
			}
		}
		if uint64(count) == size {
			if !eof {
				return count, errors.New("READ_PLUS did not report EOF at the expected size")
			}
			return count, nil
		}
		if uint64(count) == offset {
			return count, io.ErrNoProgress
		}
	}
}
