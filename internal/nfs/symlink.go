package nfs

import (
	"context"
	"errors"
	"strings"
)

// Symlink creates a new link without replacing an existing directory entry.
// The target is data: this operation never resolves or follows it.
func (c *Client) Symlink(ctx context.Context, dir []byte, name, target string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || target == "" || len(target) > 4096 || strings.ContainsRune(target, 0) {
		return errors.New("invalid symbolic link name or target")
	}
	if c.Version() == "2" {
		return errors.New("symbolic link creation requires NFSv3 or NFSv4")
	}
	var e encoder
	if c.v4 != nil {
		e.u32(5) // NF4LNK
		e.str(target)
		e.str(name)
		e = append(e, mode4(0777)...)
		created := false
		err := c.v4.compound(ctx, fh4(dir), op4(6, e, func(d *decoder) {
			created = true
			skipChange4(d)
			readBitmap4(d)
		}), op4(10, nil, func(d *decoder) { d.opaque(128) }))
		if err != nil && created {
			return errors.Join(ErrMutationUncertain, err)
		}
		return mutationResult(err)
	}
	e.opaque(dir)
	e.str(name)
	mode := uint32(0777)
	sattr(&e, &mode, nil)
	e.str(target)
	d, err := c.call(ctx, 10, e)
	if err != nil {
		return mutationResult(err)
	}
	if d.boolean() {
		d.opaque(64)
	}
	postAttr(d)
	wcc(d)
	return mutationResult(d.err)
}
