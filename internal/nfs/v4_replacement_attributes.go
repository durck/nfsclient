package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
)

const replacementAttributeBudget = 1 << 20
const replacementAttributeCount = 64

type replacementNamed struct {
	value  []byte
	policy *V4ReplacementMetadata
}

func sameReplacementAttributes(a, b *V4ReplacementMetadata) bool {
	if a.namedPresent != b.namedPresent || a.xattrsAvailable != b.xattrsAvailable || len(a.xattrs) != len(b.xattrs) || len(a.named) != len(b.named) {
		return false
	}
	for name, value := range a.xattrs {
		other, ok := b.xattrs[name]
		if !ok || !bytes.Equal(value, other) {
			return false
		}
	}
	for name, value := range a.named {
		other, ok := b.named[name]
		if !ok || !bytes.Equal(value.value, other.value) || !sameReplacementPolicy(value.policy, other.policy) {
			return false
		}
	}
	return true
}
func sameReplacementAttributeSources(a, b *V4ReplacementMetadata) bool {
	for name, value := range a.named {
		other, ok := b.named[name]
		if !ok || !bytes.Equal(value.policy.handle, other.policy.handle) || value.policy.attr.Change != other.policy.attr.Change {
			return false
		}
	}
	return true
}

func (v *v4Client) replacementNamedDirectory(ctx context.Context, fh []byte, create bool) ([]byte, error) {
	var e encoder
	if create {
		e.u32(1)
	} else {
		e.u32(0)
	}
	var dir []byte
	err := v.compound(ctx, fh4(fh), op4(19, e, nil), op4(10, nil, func(d *decoder) {
		dir = bytes.Clone(d.opaque(128))
		if len(dir) == 0 {
			d.err = errors.New("empty named attribute directory handle")
		}
	}))
	return dir, err
}

// READDIR is bounded independently of ordinary directory listing. The fixture
// cannot make this snapshot silently skip an entry with missing attributes.
func (v *v4Client) replacementNamedNames(ctx context.Context, dir []byte) ([]Entry, error) {
	before, err := v.getAttr(ctx, dir)
	if err != nil {
		return nil, err
	}
	if before.Type != 8 || !before.HasChange {
		return nil, errors.New("named directory type/change missing")
	}
	var names []Entry
	var cookie uint64
	verifier := make([]byte, 8)
	seenNames := map[string]bool{}
	seenCookies := map[uint64]bool{0: true}
	for page := 0; page < replacementAttributeCount; page++ {
		var e encoder
		e.u64(cookie)
		e = append(e, verifier...)
		limit := uint32(4096)
		if v.channel.Response == 0 && v.maxReplyPayload != 0 {
			limit = min(limit, v.maxReplyPayload)
		}
		if v.channel.Response == 0 && limit < 512 {
			return nil, errors.New("named directory reply budget too small")
		}
		e.u32(limit)
		e.u32(limit)
		bitmap4(&e, 1, 19)
		var part []Entry
		var next uint64
		var eof bool
		err = v.compound(ctx, fh4(dir), op4(26, e, func(d *decoder) {
			start := len(d.b)
			got := d.take(8)
			if cookie != 0 && !bytes.Equal(got, verifier) {
				d.err = errors.New("named attribute cookie verifier changed")
				return
			}
			copy(verifier, got)
			for d.boolean() && d.err == nil {
				if len(names)+len(part) >= replacementAttributeCount {
					d.err = errors.New("named attributes exceed 64 entries")
					return
				}
				next = d.u64()
				name := d.str()
				if ValidateXattrName(name) != nil || name == "." || name == ".." || seenNames[name] {
					d.err = errors.New("invalid or duplicate named attribute")
					return
				}
				seenNames[name] = true
				bits := readBitmap4(d)
				sub := &decoder{b: d.opaque(512)}
				entry := Entry{Name: name}
				if !slices.Equal(bits, []uint32{1, 19}) {
					d.err = errors.New("named entry type/handle omitted")
					return
				}
				entry.Attr.Type = sub.u32()
				entry.Handle = bytes.Clone(sub.opaque(128))
				if sub.err != nil || len(sub.b) != 0 || entry.Attr.Type != 9 || len(entry.Handle) == 0 {
					d.err = errors.New("invalid named attribute entry")
					return
				}
				part = append(part, entry)
			}
			eof = d.boolean()
			if start-len(d.b) > int(limit) {
				d.err = errors.New("named directory exceeds response budget")
			}
		}))
		if err != nil {
			return nil, err
		}
		for _, entry := range part {
			v.remember(entry.Handle, dir, entry.Name)
		}
		names = append(names, part...)
		if eof {
			after, err := v.getAttr(ctx, dir)
			if err != nil {
				return nil, err
			}
			if after.Type != 8 || !after.HasChange || before.Change != after.Change {
				return nil, errors.New("named directory changed during listing")
			}
			sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
			return names, nil
		}
		if len(part) == 0 || seenCookies[next] {
			return nil, errors.New("named attribute listing made no progress")
		}
		seenCookies[next] = true
		cookie = next
	}
	return nil, errors.New("named attribute listing exceeds 64 pages")
}

type boundedAttributeValue struct {
	bytes.Buffer
	limit int
}

func (w *boundedAttributeValue) Write(b []byte) (int, error) {
	if len(b) > w.limit-w.Len() {
		return 0, errors.New("named attribute exceeds snapshot value budget")
	}
	return w.Buffer.Write(b)
}

func (c *Client) captureReplacementAttributes(ctx context.Context, m *V4ReplacementMetadata, budget *int) error {
	if m.xattrsAvailable {
		names, err := c.ListXattrs(ctx, m.handle)
		if err != nil {
			return err
		}
		if len(names) > replacementAttributeCount {
			return errors.New("xattrs exceed 64 names")
		}
		m.xattrs = map[string][]byte{}
		for _, name := range names {
			value, err := c.GetXattr(ctx, m.handle, name)
			if err != nil {
				return err
			}
			if len(value) > *budget {
				return errors.New("replacement attributes exceed 1 MiB")
			}
			*budget -= len(value)
			m.xattrs[name] = value
		}
	}
	if m.namedPresent {
		dir, err := c.v4.replacementNamedDirectory(ctx, m.handle, false)
		if err != nil {
			return err
		}
		names, err := c.v4.replacementNamedNames(ctx, dir)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			return errors.New("named_attr contradicts an empty directory")
		}
		m.named = map[string]replacementNamed{}
		for _, entry := range names {
			policy, err := c.captureReplacement(ctx, entry.Handle, true, budget)
			if err != nil {
				return err
			}
			if !policy.attr.HasSize || policy.attr.Size > MaxXattrValue || policy.attr.Size > uint64(*budget) {
				return errors.New("named attribute exceeds bounded size")
			}
			value := &boundedAttributeValue{limit: min(*budget, MaxXattrValue)}
			if _, err := c.ReadTo(ctx, entry.Handle, value); err != nil {
				return err
			}
			if uint64(value.Len()) != policy.attr.Size {
				return errors.New("named attribute EOF differs from captured size")
			}
			checkBudget := replacementAttributeBudget
			after, err := c.captureReplacement(ctx, entry.Handle, true, &checkBudget)
			if err != nil {
				return err
			}
			if after.attr.Change != policy.attr.Change || after.attr.Size != policy.attr.Size || !sameReplacementPolicy(after, policy) {
				return errors.New("named attribute changed while reading")
			}
			*budget -= value.Len()
			m.named[entry.Name] = replacementNamed{bytes.Clone(value.Bytes()), policy}
		}
		after, err := c.v4.replacementNamedNames(ctx, dir)
		if err != nil {
			return err
		}
		if len(after) != len(names) {
			return errors.New("named attribute list changed during snapshot")
		}
		for i, entry := range after {
			if entry.Name != names[i].Name || !bytes.Equal(entry.Handle, names[i].Handle) {
				return errors.New("named attribute identity changed during snapshot")
			}
		}
	}
	if m.xattrsAvailable || m.namedPresent {
		after, err := c.v4.getAttr(ctx, m.handle)
		if err != nil {
			return err
		}
		if !after.HasChange || after.Change != m.attr.Change {
			return errors.New("object changed during attribute snapshot")
		}
	}
	return nil
}

func (c *Client) applyReplacementAttributes(ctx context.Context, fh []byte, m *V4ReplacementMetadata) error {
	if err := c.checkReplacementProfile(m); err != nil {
		return err
	}
	// Recheck privacy and emptiness immediately before creating attributes.
	if err := c.CheckV4ReplacementStage(ctx, fh, m); err != nil {
		return err
	}
	names := make([]string, 0, len(m.xattrs))
	for name := range m.xattrs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := c.checkReplacementProfile(m); err != nil {
			return err
		}
		if err := c.SetXattr(ctx, fh, name, m.xattrs[name], 1); err != nil {
			return err
		}
	}
	if len(m.named) == 0 {
		return c.checkReplacementProfile(m)
	}
	dir, err := c.v4.replacementNamedDirectory(ctx, fh, true)
	if err != nil {
		return err
	}
	entries, err := c.v4.replacementNamedNames(ctx, dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("new stage named directory is not empty")
	}
	names = names[:0]
	for name := range m.named {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := c.checkReplacementProfile(m); err != nil {
			return err
		}
		original := m.named[name]
		stage, err := c.Create(ctx, dir, name, 0600, false)
		if err != nil {
			return fmt.Errorf("create named attribute %q: %w", name, err)
		}
		if stage.Attr.Type != 9 {
			return errors.New("created attribute is not a named attribute")
		}
		if err := c.CheckV4ReplacementStage(ctx, stage.Handle, original.policy); err != nil {
			return err
		}
		if n, err := c.WriteFrom(ctx, stage.Handle, bytes.NewReader(original.value)); err != nil || n != int64(len(original.value)) {
			return errors.Join(err, io.ErrShortWrite)
		}
		if err := c.ApplyV4Replacement(ctx, stage.Handle, original.policy); err != nil {
			return err
		}
	}
	return c.checkReplacementProfile(m)
}
