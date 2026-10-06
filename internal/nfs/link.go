package nfs

import (
	"context"
	"errors"
	"strings"
)

// Link adds a new name for an existing regular file without replacing a name.
func (c *Client) Link(ctx context.Context, source, dir []byte, name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return errors.New("invalid hardlink name")
	}
	if c.Version() == "2" {
		return errors.New("hardlink creation requires NFSv3 or NFSv4")
	}
	var e encoder
	if c.v4 != nil {
		e.str(name)
		return c.v4.compound(ctx, fh4(source), op4(32, nil, nil), fh4(dir), op4(11, e, skipChange4))
	}
	e.opaque(source)
	e.opaque(dir)
	e.str(name)
	d, err := c.call(ctx, 15, e)
	if err != nil {
		return err
	}
	postAttr(d)
	wcc(d)
	return d.err
}
