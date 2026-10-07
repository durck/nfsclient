package nfs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrMutationUncertain means the request may have changed the server. Callers
// must inspect the object rather than replaying the mutation automatically.
var ErrMutationUncertain = errors.New("mutation outcome uncertain; inspect the object before retrying")

func mutationResult(err error) error {
	if err == nil {
		return nil
	}
	var status Status
	if errors.As(err, &status) {
		return err
	}
	return errors.Join(ErrMutationUncertain, err)
}

// ValidateOwnership validates protocol values without consulting local users,
// Windows identities, or the selected RPC authentication principal.
func ValidateOwnership(version string, owner, group *string) error {
	if owner == nil && group == nil {
		return errors.New("owner or group is required")
	}
	for _, value := range []*string{owner, group} {
		if value == nil {
			continue
		}
		if *value == "" || len(*value) > 1024 || strings.ContainsRune(*value, 0) || !utf8.ValidString(*value) {
			return errors.New("ownership values must be 1-1024 bytes of UTF-8 without NUL")
		}
		if strings.HasPrefix(version, "4") {
			continue
		}
		for _, ch := range *value {
			if ch < '0' || ch > '9' {
				return errors.New("NFSv2/v3 ownership requires decimal numeric UID/GID")
			}
		}
		n, err := strconv.ParseUint(*value, 10, 32)
		if err != nil || version == "2" && n == uint64(^uint32(0)) {
			return errors.New("ownership ID is out of range (NFSv2 reserves 4294967295)")
		}
	}
	return nil
}

// SetOwnership changes only the requested owner/group attributes and verifies
// them on the same handle. The caller decides how path symlinks are handled.
func (c *Client) SetOwnership(ctx context.Context, fh []byte, owner, group *string) error {
	if err := ValidateOwnership(c.Version(), owner, group); err != nil {
		return err
	}
	var e encoder
	if c.v4 != nil {
		bits := []uint32{}
		var values encoder
		if owner != nil {
			bits = append(bits, 36)
			values.str(*owner)
		}
		if group != nil {
			bits = append(bits, 37)
			values.str(*group)
		}
		e = make(encoder, 16) // anonymous stateid; no size change
		bitmap4(&e, bits...)
		e.opaque(values)
		changed := false
		op := op4(34, e, func(d *decoder) {
			got := readBitmap4(d)
			if d.err == nil && !slices.Equal(got, bits) {
				d.err = errors.New("server did not acknowledge exactly the requested ownership attributes")
			}
		})
		op.failure = func(d *decoder) {
			got := readBitmap4(d)
			changed = len(got) != 0
			for _, bit := range got {
				if !slices.Contains(bits, bit) {
					d.err = errors.New("failed SETATTR acknowledged an unrequested attribute")
				}
			}
		}
		if err := c.v4.compound(ctx, fh4(fh), op); err != nil {
			if changed {
				return errors.Join(ErrMutationUncertain, err)
			}
			return mutationResult(err)
		}
	} else {
		ids := [2]uint32{^uint32(0), ^uint32(0)}
		for i, value := range []*string{owner, group} {
			if value != nil {
				n, _ := strconv.ParseUint(*value, 10, 32)
				ids[i] = uint32(n)
			}
		}
		if c.Version() == "2" {
			var err error
			e, err = handle2(fh)
			if err != nil {
				return err
			}
			e.u32(^uint32(0))
			e.u32(ids[0])
			e.u32(ids[1])
			for range 5 {
				e.u32(^uint32(0))
			}
		} else {
			e.opaque(fh)
			e.u32(0) // mode unchanged
			for i, value := range []*string{owner, group} {
				if value == nil {
					e.u32(0)
				} else {
					e.u32(1)
					e.u32(ids[i])
				}
			}
			for range 4 {
				e.u32(0)
			} // size, atime, mtime, guard
		}
		d, err := c.call(ctx, 2, e)
		if err != nil {
			// RFC 1813 SETATTR is not atomic, even when it returns an NFS
			// error. Preserve that status while warning about partial changes.
			return errors.Join(ErrMutationUncertain, err)
		}
		if c.Version() == "2" {
			attr2(d)
		} else {
			wcc(d)
		}
		if d.err != nil {
			return mutationResult(d.err)
		}
	}
	a, err := c.GetAttr(ctx, fh)
	if err != nil {
		return errors.Join(ErrMutationUncertain, fmt.Errorf("ownership readback failed: %w", err))
	}
	for i, value := range []*string{owner, group} {
		if value == nil {
			continue
		}
		actual := []string{a.Owner, a.Group}[i]
		if c.v4 == nil {
			actual = strconv.FormatUint(uint64([]uint32{a.UID, a.GID}[i]), 10)
			n, _ := strconv.ParseUint(*value, 10, 32)
			if actual == strconv.FormatUint(n, 10) {
				continue
			}
		} else if actual == *value {
			continue
		}
		return errors.Join(ErrMutationUncertain, fmt.Errorf("ownership readback mismatch: requested %q, received %q", *value, actual))
	}
	return nil
}
