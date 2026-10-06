package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// RequireWriteLock requires this connection's confirmed whole-file write lock.
// NFS locks are advisory: this is not protection from uncooperative writers.
func (c *Client) RequireWriteLock(fh []byte) error {
	if c.v4 == nil {
		if c.nlm != nil {
			for _, l := range c.nlm.locks {
				if bytes.Equal(l.fh, fh) && l.confirmed {
					return c.nlm.checkIO(fh, true)
				}
			}
		}
		return errors.New("upload resume requires a confirmed whole-file NLM write lock; run lock first")
	}
	if c.v4.lockFor(fh) == nil {
		return errors.New("upload resume requires a held whole-file write lock; run lock first")
	}
	return c.v4.checkLockedIO(fh, 2)
}

// AppendFromProgress writes only after a caller-verified prefix. The caller must
// compare that prefix and check remote/local source stability before invoking it.
// Each WRITE is sent once. An uncertain write may have reached the server.
func (c *Client) AppendFromProgress(ctx context.Context, fh []byte, offset, expectedChange uint64, r io.Reader, progress func(uint64)) (int64, error) {
	if c.v4 == nil {
		return 0, errors.New("change-attribute append requires NFSv4")
	}
	if err := c.RequireWriteLock(fh); err != nil {
		return 0, err
	}
	if offset > uint64(1<<63-1) {
		return 0, errors.New("append offset exceeds supported signed 64-bit size")
	}
	before, err := c.GetAttr(ctx, fh)
	if err != nil {
		return 0, err
	}
	if !before.HasSize || before.Size != offset || before.Type != 1 || !before.HasChange || before.Change != expectedChange {
		return 0, errors.New("append preflight no longer matches the verified regular-file size/change")
	}
	return c.v4.writeAt(ctx, fh, r, progress, offset)
}

// AppendLegacyFromProgress appends to a caller-verified complete prefix under
// this connection's retained NLM lock. Timestamps detect changes, not snapshots.
// No uncertain WRITE or COMMIT is replayed.
func (c *Client) AppendLegacyFromProgress(ctx context.Context, fh []byte, expected Attr, r io.Reader, progress func(uint64)) (int64, error) {
	if c.Version() != "2" && c.Version() != "3" {
		return 0, errors.New("legacy append requires NFSv2/v3")
	}
	if err := c.RequireWriteLock(fh); err != nil {
		return 0, err
	}
	if !legacyAppendMatches(expected, expected) || expected.Size > 1<<63-1 || c.Version() == "2" && expected.Size > maxV2File {
		return 0, errors.New("legacy append requires a supported size, identity and timestamps")
	}
	before, err := c.GetAttr(ctx, fh)
	if err != nil {
		return 0, err
	}
	if !legacyAppendMatches(expected, before) {
		return 0, errors.New("append preflight no longer matches the verified regular-file size/identity/timestamps")
	}
	if c.Version() == "2" {
		return c.write2At(ctx, fh, r, progress, expected.Size)
	}
	return c.write3At(ctx, fh, r, progress, expected.Size)
}

func legacyAppendMatches(a, b Attr) bool {
	return a.Type == 1 && b.Type == 1 && a.HasSize && b.HasSize && a.Size == b.Size &&
		a.HasFSID && b.HasFSID && a.FSID == b.FSID && a.FSIDMinor == b.FSIDMinor &&
		a.HasFileID && b.HasFileID && a.FileID == b.FileID &&
		a.HasMTime && b.HasMTime && a.MTime.Equal(b.MTime) &&
		a.HasCTime && b.HasCTime && a.CTime.Equal(b.CTime)
}

// A malformed acknowledgement or failed COMMIT cannot establish durable bytes.
func (c *Client) uncertainLegacyWrite(err error) error {
	if c.nlm != nil && len(c.nlm.locks) > 0 {
		c.nlm.monitor.invalidate()
		return errors.Join(ErrLockUncertain, err)
	}
	return err
}
