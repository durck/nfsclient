package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxXattrValue = 65536
const MaxXattrName = 255
const maxXattrNames = 4096

func ValidateXattrName(name string) error {
	if name == "" || len(name) > MaxXattrName || !utf8.ValidString(name) || strings.ContainsAny(name, "/\x00") {
		return errors.New("xattr name must be 1..255 UTF-8 bytes without NUL or slash")
	}
	return nil
}

// RFC 8276 support must be established before sending an extension opcode.
// Query per object, without a stale capability cache across filesystems.
func (c *Client) xattrReady(ctx context.Context, fh []byte, write bool) error {
	if c.v4 == nil || c.v4.minor != 2 {
		return ErrRequiresV42
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	share := uint32(1)
	if write {
		share = 2
	}
	if err := c.v4.checkLockedIO(fh, share); err != nil {
		return err
	}
	var advertised []uint32
	if err := c.v4.attrs(ctx, fh, []uint32{0}, func(_ uint32, d *decoder) { advertised = readBitmap4(d) }); err != nil {
		return err
	}
	if !slices.Contains(advertised, uint32(82)) {
		return Status(10004)
	}
	supported := false
	if err := c.v4.attrs(ctx, fh, []uint32{82}, func(_ uint32, d *decoder) { supported = d.boolean() }); err != nil {
		return err
	}
	if !supported {
		return Status(10004)
	}
	return c.v4.checkLockedIO(fh, share)
}

func (c *Client) getXattr42(ctx context.Context, fh []byte, name string) ([]byte, error) {
	var e encoder
	e.str(name)
	limit := uint32(MaxXattrValue)
	if c.v4.channel.Response == 0 && c.v4.maxReplyPayload != 0 {
		limit = min(limit, c.v4.maxReplyPayload)
	}
	var value []byte
	err := c.v4.compound(ctx, fh4(fh), op4(72, e, func(d *decoder) { value = append([]byte{}, d.opaque(limit)...) }))
	if err != nil {
		return nil, err
	}
	if err := c.v4.checkLockedIO(fh, 1); err != nil {
		return nil, err
	}
	return value, nil
}

func (c *Client) GetXattr(ctx context.Context, fh []byte, name string) ([]byte, error) {
	if err := ValidateXattrName(name); err != nil {
		return nil, err
	}
	if err := c.xattrReady(ctx, fh, false); err != nil {
		return nil, err
	}
	return c.getXattr42(ctx, fh, name)
}

// ListXattrs returns a bounded, sorted complete list. Cookie cycles, duplicate
// names and observed metadata changes refuse the result instead of returning
// a partial or mixed list. It is not a snapshot against undetectable changes.
func (c *Client) ListXattrs(ctx context.Context, fh []byte) ([]string, error) {
	if err := c.xattrReady(ctx, fh, false); err != nil {
		return nil, err
	}
	v := c.v4
	before, err := v.getAttr(ctx, fh)
	if err != nil {
		return nil, err
	}
	if !before.HasChange {
		return nil, errors.New("xattr listing requires the source change attribute")
	}
	limit := uint32(65536)
	if v.channel.Response == 0 && v.maxReplyPayload != 0 {
		limit = min(limit, v.maxReplyPayload)
	}
	if v.channel.Response == 0 && limit < 512 {
		return nil, errors.New("negotiated xattr listing budget is too small")
	}
	names := []string{}
	seen := map[string]bool{}
	cookies := map[uint64]bool{0: true}
	cookie := uint64(0)
	for page := 0; page < maxXattrNames; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var e encoder
		e.u64(cookie)
		e.u32(limit)
		var next uint64
		var eof bool
		var part []string
		err := v.compound(ctx, fh4(fh), op4(74, e, func(d *decoder) {
			start := len(d.b)
			next = d.u64()
			count := d.u32()
			if count > maxXattrNames || int(count) > maxXattrNames-len(names) {
				d.err = errors.New("xattr name count exceeds 4096")
				return
			}
			for range count {
				name := string(d.opaque(MaxXattrName))
				if d.err != nil {
					return
				}
				if err := ValidateXattrName(name); err != nil {
					d.err = err
					return
				}
				if seen[name] {
					d.err = errors.New("duplicate xattr name across listing pages")
					return
				}
				seen[name] = true
				part = append(part, name)
			}
			eof = d.boolean()
			if start-len(d.b) > int(limit) {
				d.err = errors.New("xattr listing exceeds requested response budget")
			}
		}))
		if err != nil {
			return nil, err
		}
		names = append(names, part...)
		if eof {
			after, err := v.getAttr(ctx, fh)
			if err != nil {
				return nil, err
			}
			if !after.HasChange || before.Change != after.Change {
				return nil, errors.New("xattrs changed while listing; partial list discarded")
			}
			if err := v.checkLockedIO(fh, 1); err != nil {
				return nil, err
			}
			sort.Strings(names)
			return names, nil
		}
		if len(part) == 0 || cookies[next] {
			return nil, errors.New("xattr listing made no progress or repeated a cookie")
		}
		cookies[next] = true
		cookie = next
	}
	return nil, errors.New("xattr listing exceeded 4096 pages")
}

// SetXattr accepts RFC options 0=either, 1=create, 2=replace. A mutation is
// issued once and its value is read back separately; no retry or rollback.
func (c *Client) SetXattr(ctx context.Context, fh []byte, name string, value []byte, option uint32) error {
	if err := ValidateXattrName(name); err != nil {
		return err
	}
	if option > 2 {
		return errors.New("xattr option must be either, create or replace")
	}
	if len(value) > MaxXattrValue {
		return errors.New("xattr value exceeds 65536 bytes")
	}
	var e encoder
	e.u32(option)
	e.str(name)
	e.opaque(value)
	if c.v4 != nil && c.v4.channel.Request == 0 && c.v4.maxRequestPayload != 0 && uint32(len(e)) > c.v4.maxRequestPayload {
		return errors.New("xattr value exceeds negotiated request budget")
	}
	if err := c.xattrReady(ctx, fh, true); err != nil {
		return err
	}
	if err := c.v4.compound(ctx, fh4(fh), op4(73, e, skipChange4)); err != nil {
		return fmt.Errorf("xattr mutation failed; inspect the attribute before retrying (no replay): %w", err)
	}
	if err := c.v4.checkLockedIO(fh, 2); err != nil {
		return fmt.Errorf("xattr acknowledged, but lock state lost: %w", err)
	}
	got, err := c.getXattr42(ctx, fh, name)
	if err != nil {
		return fmt.Errorf("xattr acknowledged, but readback failed: %w", err)
	}
	if !bytes.Equal(got, value) {
		return errors.New("xattr acknowledged, but readback differs; no rollback or replay")
	}
	return nil
}

func (c *Client) RemoveXattr(ctx context.Context, fh []byte, name string) error {
	if err := ValidateXattrName(name); err != nil {
		return err
	}
	if err := c.xattrReady(ctx, fh, true); err != nil {
		return err
	}
	var e encoder
	e.str(name)
	if err := c.v4.compound(ctx, fh4(fh), op4(75, e, skipChange4)); err != nil {
		return fmt.Errorf("xattr removal failed; inspect the attribute before retrying (no replay): %w", err)
	}
	if err := c.v4.checkLockedIO(fh, 2); err != nil {
		return fmt.Errorf("xattr removal acknowledged, but lock state lost: %w", err)
	}
	_, err := c.getXattr42(ctx, fh, name)
	if errors.Is(err, Status(10095)) {
		return nil
	}
	if err == nil {
		return errors.New("xattr removal acknowledged, but attribute is still present; no replay")
	}
	return fmt.Errorf("xattr removal acknowledged, but absence could not be verified: %w", err)
}
