package nfs

import (
	"bytes"
	"context"
	"errors"
)

// Named attributes are OPENATTR streams, distinct from RFC 8276 xattrs.
// Inspection shares the bounded directory walker with replacement capture,
// but requires no ACL, owner, label, or replacement-policy metadata.
const MaxNamedAttributeValue = 65536
const MaxNamedAttributes = replacementAttributeCount

type NamedAttribute struct {
	Name   string `json:"name"`
	Size   uint64 `json:"size"`
	Change uint64 `json:"change"`
}

func ValidateNamedAttributeName(name string) error {
	if ValidateXattrName(name) != nil || name == "." || name == ".." {
		return errors.New("named attribute name must be 1..255 UTF-8 bytes without NUL or slash, excluding dot and dot-dot")
	}
	return nil
}

func (c *Client) namedAttributeBase(ctx context.Context, fh []byte) (Attr, error) {
	if c.v4 == nil {
		return Attr{}, errors.New("named attributes require NFSv4")
	}
	if len(fh) == 0 || len(fh) > 128 {
		return Attr{}, errors.New("invalid named attribute base handle")
	}
	if err := ctx.Err(); err != nil {
		return Attr{}, err
	}
	a, err := c.v4.getAttr(ctx, fh)
	if err != nil {
		return a, err
	}
	if (a.Type != 1 && a.Type != 2) || !a.HasChange {
		return a, errors.New("named attributes require a regular file or directory with change metadata; symlinks are not followed")
	}
	return a, nil
}

func (c *Client) checkNamedAttributeBase(ctx context.Context, fh []byte, before Attr) error {
	after, err := c.namedAttributeBase(ctx, fh)
	if err != nil {
		return err
	}
	if after.Type != before.Type || after.Change != before.Change {
		return errors.New("named attribute base changed during inspection")
	}
	return ctx.Err()
}

func (c *Client) ListNamedAttributes(ctx context.Context, fh []byte) ([]NamedAttribute, error) {
	before, err := c.namedAttributeBase(ctx, fh)
	if err != nil {
		return nil, err
	}
	dir, err := c.v4.replacementNamedDirectory(ctx, fh, false)
	if errors.Is(err, Status(2)) {
		return []NamedAttribute{}, c.checkNamedAttributeBase(ctx, fh, before)
	}
	if err != nil {
		return nil, err
	}
	entries, err := c.v4.replacementNamedNames(ctx, dir)
	if err != nil {
		return nil, err
	}
	result := make([]NamedAttribute, 0, len(entries))
	for _, entry := range entries {
		a, err := c.v4.getAttr(ctx, entry.Handle)
		if err != nil {
			return nil, err
		}
		if a.Type != 9 || !a.HasSize || !a.HasChange {
			return nil, errors.New("named attribute type/size/change missing")
		}
		result = append(result, NamedAttribute{Name: entry.Name, Size: a.Size, Change: a.Change})
	}
	// Rewalk after metadata reads to detect removal/rebinding of entries.
	after, err := c.v4.replacementNamedNames(ctx, dir)
	if err != nil {
		return nil, err
	}
	if len(after) != len(entries) {
		return nil, errors.New("named attribute list changed during inspection")
	}
	for i := range entries {
		if after[i].Name != entries[i].Name || !bytes.Equal(after[i].Handle, entries[i].Handle) {
			return nil, errors.New("named attribute identity changed during inspection")
		}
	}
	dirAfter, err := c.v4.replacementNamedDirectory(ctx, fh, false)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(dir, dirAfter) {
		return nil, errors.New("named attribute directory changed during inspection")
	}
	if err := c.checkNamedAttributeBase(ctx, fh, before); err != nil {
		return nil, err
	}
	return result, nil
}

// GetNamedAttribute bounds the value at 64 KiB and checks identity, size, and
// change around READ. No remote directory or attribute is ever created.
func (c *Client) GetNamedAttribute(ctx context.Context, fh []byte, name string) ([]byte, error) {
	if err := ValidateNamedAttributeName(name); err != nil {
		return nil, err
	}
	before, err := c.namedAttributeBase(ctx, fh)
	if err != nil {
		return nil, err
	}
	dir, err := c.v4.replacementNamedDirectory(ctx, fh, false)
	if err != nil {
		return nil, err
	}
	da, err := c.v4.getAttr(ctx, dir)
	if err != nil {
		return nil, err
	}
	if da.Type != 8 || !da.HasChange {
		return nil, errors.New("named directory type/change missing")
	}
	entry, err := c.v4.lookup(ctx, dir, name)
	if err != nil {
		return nil, err
	}
	a := entry.Attr
	if a.Type != 9 || !a.HasSize || !a.HasChange {
		return nil, errors.New("named attribute type/size/change missing")
	}
	if a.Size > MaxNamedAttributeValue {
		return nil, errors.New("named attribute exceeds 64 KiB")
	}
	value := &boundedAttributeValue{limit: int(a.Size)}
	if _, err := c.ReadTo(ctx, entry.Handle, value); err != nil {
		return nil, err
	}
	if uint64(value.Len()) != a.Size {
		return nil, errors.New("named attribute EOF differs from captured size")
	}
	after, err := c.v4.lookup(ctx, dir, name)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(entry.Handle, after.Handle) || after.Attr.Type != 9 || !after.Attr.HasChange || !after.Attr.HasSize || a.Change != after.Attr.Change || a.Size != after.Attr.Size {
		return nil, errors.New("named attribute changed during read")
	}
	dirAfter, err := c.v4.replacementNamedDirectory(ctx, fh, false)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(dir, dirAfter) {
		return nil, errors.New("named attribute directory changed during read")
	}
	if err := c.checkNamedAttributeBase(ctx, fh, before); err != nil {
		return nil, err
	}
	return bytes.Clone(value.Bytes()), nil
}
