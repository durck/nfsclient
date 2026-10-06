package nfs

import (
	"context"
	"errors"
	"math"
	"time"
)

// SetMTime changes only mtime and verifies the server's stored value. A server
// with coarser timestamp precision returns an explicit verification error.
func (c *Client) SetMTime(ctx context.Context, fh []byte, value time.Time) error {
	var e encoder
	if c.v4 != nil {
		e = make(encoder, 16) // anonymous stateid; no size change
		bitmap4(&e, 54)
		var a encoder
		a.u32(1) // SET_TO_CLIENT_TIME4
		a.u64(uint64(value.Unix()))
		a.u32(uint32(value.Nanosecond()))
		e.opaque(a)
		if err := c.v4.compound(ctx, fh4(fh), op4(34, e, func(d *decoder) { readBitmap4(d) })); err != nil {
			return err
		}
	} else {
		if value.Unix() < 0 || value.Unix() > math.MaxUint32 {
			return errors.New("mtime is outside the legacy NFS timestamp range")
		}
		if c.Version() == "2" {
			return errors.New("setting mtime requires NFSv3 or NFSv4")
		}
		e.opaque(fh)
		for range 5 {
			e.u32(0)
		} // unchanged mode, uid, gid, size, atime
		e.u32(2) // SET_TO_CLIENT_TIME
		e.u32(uint32(value.Unix()))
		e.u32(uint32(value.Nanosecond()))
		e.u32(0) // no ctime guard
		d, err := c.call(ctx, 2, e)
		if err != nil {
			return err
		}
		wcc(d)
		if d.err != nil {
			return d.err
		}
	}
	a, err := c.GetAttr(ctx, fh)
	if err != nil {
		return err
	}
	if !a.HasMTime || !a.MTime.Equal(value) {
		return errors.New("server did not preserve the requested mtime exactly")
	}
	return nil
}
