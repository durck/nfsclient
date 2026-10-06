package nfs

import (
	"context"
	"errors"
	"fmt"
)

var ErrRequiresV42 = errors.New("this operation requires NFSv4.2")

type SeekResult struct {
	Offset uint64 `json:"offset"`
	EOF    bool   `json:"eof"`
}

// Seek asks the server for its next data/hole boundary. Filesystems may report
// allocated zero ranges as data; this is not a content or physical extent map.
func (c *Client) Seek(ctx context.Context, fh []byte, offset uint64, hole bool) (result SeekResult, resultErr error) {
	if c.v4 == nil || c.v4.minor != 2 {
		return result, ErrRequiresV42
	}
	v := c.v4
	sid, closeIO, err := v.openIO(ctx, fh, 1)
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, closeIO())
		if resultErr != nil {
			result = SeekResult{}
		}
	}()
	e := append(encoder(nil), sid...)
	e.u64(offset)
	if hole {
		e.u32(1)
	} else {
		e.u32(0)
	}
	err = v.compound(ctx, fh4(fh), op4(69, e, func(d *decoder) {
		result.EOF = d.boolean()
		result.Offset = d.u64()
		if d.err == nil && result.Offset < offset {
			d.err = errors.New("NFSv4.2 SEEK returned an offset before the request")
		}
	}))
	if err != nil {
		return result, err
	}
	return result, v.checkLockedIO(fh, 1)
}

// ValidateSpaceRange uses finite byte lengths: zero and uint64 wrap are invalid.
func ValidateSpaceRange(offset, length uint64) error {
	if length == 0 || offset > ^uint64(0)-length {
		return errors.New("space range needs a positive length without uint64 overflow")
	}
	return nil
}

// Allocate reserves server storage and may extend file size. It does not send
// zero-filled payloads or emulate an unsupported server operation.
func (c *Client) Allocate(ctx context.Context, fh []byte, offset, length uint64) error {
	return c.space42(ctx, fh, offset, length, 59, "ALLOCATE")
}

// Deallocate discards bytes in the requested range (subsequent reads return
// zero) without shrinking file size. This is an explicit destructive mutation.
func (c *Client) Deallocate(ctx context.Context, fh []byte, offset, length uint64) error {
	return c.space42(ctx, fh, offset, length, 62, "DEALLOCATE")
}

func (c *Client) space42(ctx context.Context, fh []byte, offset, length uint64, code uint32, name string) (resultErr error) {
	if c.v4 == nil || c.v4.minor != 2 {
		return ErrRequiresV42
	}
	if err := ValidateSpaceRange(offset, length); err != nil {
		return err
	}
	v := c.v4
	sid, closeIO, err := v.openIO(ctx, fh, 2)
	if err != nil {
		return err
	}
	acknowledged := false
	defer func() {
		if err := closeIO(); err != nil {
			if acknowledged {
				err = fmt.Errorf("%s acknowledged, but state cleanup failed: %w", name, err)
			}
			resultErr = errors.Join(resultErr, err)
		}
	}()
	e := append(encoder(nil), sid...)
	e.u64(offset)
	e.u64(length)
	if err = v.compound(ctx, fh4(fh), op4(code, e, nil)); err != nil {
		var status Status
		if !errors.As(err, &status) {
			return fmt.Errorf("%s outcome unverified; request was not replayed: %w", name, err)
		}
		return err
	}
	acknowledged = true
	return v.checkLockedIO(fh, 2)
}
