package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"
)

type ace4 struct {
	kind, flags, mask uint32
	who               string
}

// V4ReplacementMetadata is an opaque, bounded snapshot of the access policy.
// ACL, DACL/SACL, labels, mode and ownership retain their exact wire values.
type V4ReplacementMetadata struct {
	handle                        []byte
	attr                          Attr
	acl                           []ace4
	dacl, sacl                    *replacementACL
	label                         *SecurityLabel
	stageOwner, stageGroup        string
	stageClient                   *v4Client
	stageAuth                     Auth
	stageIdentity                 string
	attributeFile                 bool
	namedPresent, xattrsAvailable bool
	xattrs                        map[string][]byte
	named                         map[string]replacementNamed
}

type replacementACL struct {
	flags   uint32
	entries []ace4
}

func replacementError(err error) error {
	return fmt.Errorf("NFSv4 ACL-preserving replacement refused: %w", err)
}

func hasBit4(bits []uint32, bit uint32) bool {
	for _, b := range bits {
		if b == bit {
			return true
		}
	}
	return false
}

func validACLWho(s string) bool {
	return s != "" && utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 })
}

func readACL4(d *decoder) []ace4 {
	return readReplacementACEs(d, 12)
}

func readReplacementACEs(d *decoder, bit uint32) []ace4 {
	n := d.u32()
	if n > 1024 {
		d.err = errors.New("ACL exceeds 1024 ACEs")
		return nil
	}
	acl := make([]ace4, 0, n)
	for i := uint32(0); i < n && d.err == nil; i++ {
		a := ace4{d.u32(), d.u32(), d.u32(), d.str()}
		flags := uint32(0x7f)
		if bit != 12 {
			flags |= 0x80
		}
		// RFC 8881 6.2.1.4.1 permits AUDIT/ALARM without event flags.
		// They are not useful, but dropping or rejecting them loses policy.
		if d.err == nil && (a.kind > 3 || bit == 58 && a.kind > 1 || bit == 59 && a.kind < 2 || a.flags & ^flags != 0 || a.kind < 2 && a.flags&0x30 != 0 || a.mask & ^uint32(0x1f01ff) != 0 || !validACLWho(a.who)) {
			d.err = errors.New("unsupported ACL entry type, flags, mask or identity")
		}
		acl = append(acl, a)
	}
	return acl
}

func readReplacementACL(d *decoder, bit uint32) *replacementACL {
	a := &replacementACL{flags: d.u32()}
	if a.flags & ^uint32(7) != 0 {
		d.err = errors.New("unknown DACL/SACL flags")
		return a
	}
	a.entries = readReplacementACEs(d, bit)
	return a
}

func writeACL4(e *encoder, acl []ace4) {
	e.u32(uint32(len(acl)))
	for _, a := range acl {
		e.u32(a.kind)
		e.u32(a.flags)
		e.u32(a.mask)
		e.str(a.who)
	}
}

// CaptureV4Replacement never interprets absent attributes as an empty ACL.
func (c *Client) CaptureV4Replacement(ctx context.Context, fh []byte) (*V4ReplacementMetadata, error) {
	budget := replacementAttributeBudget
	return c.captureReplacement(ctx, fh, false, &budget)
}

func (c *Client) captureReplacement(ctx context.Context, fh []byte, attribute bool, budget *int) (*V4ReplacementMetadata, error) {
	if c.v4 != nil && c.v4.lockFor(fh) != nil {
		return nil, errors.New("replacement would switch the locked inode; unlock the destination first")
	}
	if c.v4 == nil {
		return nil, replacementError(errors.New("requires NFSv4"))
	}
	m := &V4ReplacementMetadata{handle: append([]byte(nil), fh...), attributeFile: attribute}
	wanted := []uint32{0, 1, 3, 7, 12, 13, 33, 36, 37}
	if attribute {
		wanted = append(wanted, 4)
	}
	seen := map[uint32]bool{}
	var supported []uint32
	var aclSupport uint32
	requested := append(slices.Clone(wanted), 58, 59, 80, 82)
	err := c.v4.attrs(ctx, fh, requested, func(bit uint32, d *decoder) {
		if c.v4.channel.Response == 0 && c.v4.maxReplyPayload != 0 && uint32(len(d.b)) > c.v4.maxReplyPayload {
			d.err = errors.New("ACL metadata exceeds the negotiated reply budget")
			return
		}
		seen[bit] = true
		switch bit {
		case 0:
			supported = readBitmap4(d)
		case 12:
			m.acl = readACL4(d)
		case 13:
			aclSupport = d.u32()
		case 7:
			m.namedPresent = d.boolean()
		case 82:
			m.xattrsAvailable = d.boolean()
		case 58:
			m.dacl = readReplacementACL(d, 58)
		case 59:
			m.sacl = readReplacementACL(d, 59)
		case 80:
			m.label = &SecurityLabel{Format: d.u32(), Policy: d.u32(), Data: bytes.Clone(d.opaque(MaxSecurityLabel))}
		default:
			decodeAttr4(&m.attr, bit, d)
		}
	})
	if err != nil {
		return nil, replacementError(err)
	}
	for _, bit := range wanted {
		if !seen[bit] || !hasBit4(supported, bit) {
			return nil, replacementError(fmt.Errorf("server does not expose required attribute %d", bit))
		}
	}
	for _, bit := range []uint32{58, 59, 80, 82} {
		if hasBit4(supported, bit) != seen[bit] {
			return nil, replacementError(fmt.Errorf("missing or unadvertised preservation attribute %d", bit))
		}
	}
	if m.label != nil && c.v4.minor != 2 {
		return nil, replacementError(ErrRequiresV42)
	}
	if (m.dacl != nil || m.sacl != nil) && c.v4.minor < 1 {
		return nil, replacementError(errors.New("DACL/SACL require NFSv4.1 or later"))
	}
	typeOK := m.attr.Type == 1 && !attribute || m.attr.Type == 9 && attribute
	if !typeOK || attribute && m.namedPresent || m.xattrsAvailable && c.v4.minor != 2 || m.attr.Mode & ^uint32(07777) != 0 || !validACLWho(m.attr.Owner) || !validACLWho(m.attr.Group) {
		return nil, replacementError(errors.New("requires a regular file, supported mode and explicit owner/group"))
	}
	if aclSupport & ^uint32(15) != 0 {
		return nil, replacementError(errors.New("unknown ACL support flags"))
	}
	all := slices.Clone(m.acl)
	for _, a := range []*replacementACL{m.dacl, m.sacl} {
		if a != nil {
			all = append(all, a.entries...)
		}
	}
	for _, a := range all {
		if aclSupport&(1<<a.kind) == 0 {
			return nil, replacementError(fmt.Errorf("ACL entry type %d is not advertised by ACL support flags %#x", a.kind, aclSupport))
		}
	}
	if err := c.captureReplacementAttributes(ctx, m, budget); err != nil {
		return nil, replacementError(err)
	}
	return m, nil
}

func sameReplacementPolicy(a, b *V4ReplacementMetadata) bool {
	return a.attributeFile == b.attributeFile && a.attr.Mode == b.attr.Mode && a.attr.Owner == b.attr.Owner && a.attr.Group == b.attr.Group && reflect.DeepEqual(a.acl, b.acl) && reflect.DeepEqual(a.dacl, b.dacl) && reflect.DeepEqual(a.sacl, b.sacl) && reflect.DeepEqual(a.label, b.label) && sameReplacementAttributes(a, b)
}

// CheckV4ReplacementStage runs on the empty staging file before any payload.
// Mode alone is insufficient: refuse any data ALLOW for another identity.
func (c *Client) CheckV4ReplacementStage(ctx context.Context, fh []byte, original *V4ReplacementMetadata) error {
	budget := replacementAttributeBudget
	attribute := original != nil && original.attributeFile
	stage, err := c.captureReplacement(ctx, fh, attribute, &budget)
	if err != nil {
		return err
	}
	if original == nil || stage.attr.Mode != 0600 {
		return replacementError(errors.New("private staging mode was not retained"))
	}
	if len(stage.xattrs) != 0 || len(stage.named) != 0 || stage.xattrsAvailable != original.xattrsAvailable {
		return replacementError(errors.New("private stage contains inherited attributes or differs in xattr support"))
	}
	accessACL := stage.acl
	if stage.dacl != nil {
		accessACL = append(slices.Clone(accessACL), stage.dacl.entries...)
	}
	for _, a := range accessACL {
		if a.kind == 0 && a.mask&0x37 != 0 && a.who != "OWNER@" {
			return replacementError(errors.New("staging ACL grants data access to another identity"))
		}
	}
	if stage.attr.Owner != original.attr.Owner || stage.attr.Group != original.attr.Group {
		access, err := c.CheckAccess(ctx, fh, 63)
		if err != nil {
			return replacementError(err)
		}
		if access.Supported&13 != 13 {
			return replacementError(errors.New("server cannot verify read and write access to the private staging file"))
		}
		if access.Allowed&13 != 13 {
			return replacementError(errors.New("current identity cannot read and write the private staging file"))
		}
	}
	original.stageOwner, original.stageGroup = stage.attr.Owner, stage.attr.Group
	original.stageClient, original.stageAuth, original.stageIdentity = c.v4, c.Auth, c.Identity()
	original.stageAuth.Groups = slices.Clone(c.Auth.Groups)
	return nil
}

func (c *Client) checkReplacementProfile(m *V4ReplacementMetadata) error {
	if m != nil && m.stageClient != nil && (c.v4 != m.stageClient || !sameNLMAuth(c.Auth, m.stageAuth) || c.Identity() != m.stageIdentity) {
		return replacementError(errors.New("replacement client or identity changed"))
	}
	return nil
}

// ApplyV4Replacement sets mode and ACL together, then separately reads them
// back. Separate compounds avoid putting the variable ACL in a mutation cache.
func (c *Client) ApplyV4Replacement(ctx context.Context, fh []byte, original *V4ReplacementMetadata) error {
	if c.v4 == nil || original == nil {
		return replacementError(errors.New("missing NFSv4 metadata snapshot"))
	}
	if err := c.checkReplacementProfile(original); err != nil {
		return err
	}
	if original.xattrsAvailable || original.namedPresent {
		if err := c.applyReplacementAttributes(ctx, fh, original); err != nil {
			return replacementError(err)
		}
	}
	// Ownership is applied before the final mode/ACL operation: chown may clear
	// set-ID bits. No payload write follows this transition.
	if original.stageOwner != "" && (original.stageOwner != original.attr.Owner || original.stageGroup != original.attr.Group) {
		var values encoder
		values.str(original.attr.Owner)
		values.str(original.attr.Group)
		if err := c.setReplacementAttrs(ctx, fh, []uint32{36, 37}, values); err != nil {
			return err
		}
		if err := c.checkReplacementProfile(original); err != nil {
			return err
		}
	}
	var values encoder
	bits := []uint32{33}
	if original.dacl == nil {
		bits = []uint32{12, 33}
		writeACL4(&values, original.acl)
	}
	values.u32(original.attr.Mode)
	for i, a := range []*replacementACL{original.dacl, original.sacl} {
		if a != nil {
			bits = append(bits, uint32(58+i))
			values.u32(a.flags)
			writeACL4(&values, a.entries)
		}
	}
	if original.label != nil {
		bits = append(bits, 80)
		values.u32(original.label.Format)
		values.u32(original.label.Policy)
		values.opaque(original.label.Data)
	}
	if err := c.setReplacementAttrs(ctx, fh, bits, values); err != nil {
		return err
	}
	if err := c.checkReplacementProfile(original); err != nil {
		return err
	}
	budget := replacementAttributeBudget
	got, err := c.captureReplacement(ctx, fh, original.attributeFile, &budget)
	if err != nil {
		return err
	}
	if !sameReplacementPolicy(got, original) {
		return replacementError(errors.New("ACL, mode, label or ownership differs after readback"))
	}
	return c.checkReplacementProfile(original)
}

func (c *Client) setReplacementAttrs(ctx context.Context, fh []byte, bits []uint32, values encoder) error {
	var attrs encoder
	bitmap4(&attrs, bits...)
	attrs.opaque(values)
	budget := uint32(65536)
	if c.v4.channel.Request == 0 && c.v4.maxRequestPayload != 0 {
		budget = min(budget, c.v4.maxRequestPayload)
	}
	if len(attrs) > int(budget) {
		return replacementError(errors.New("ACL exceeds the negotiated request budget"))
	}
	e := make(encoder, 16)
	e = append(e, attrs...)
	op := op4(34, e, func(d *decoder) {
		got := readBitmap4(d)
		if d.err == nil && !slices.Equal(got, bits) {
			d.err = errors.New("server did not acknowledge all replacement attributes")
		}
	})
	op.failure = func(d *decoder) {
		for _, bit := range readBitmap4(d) {
			if !slices.Contains(bits, bit) {
				d.err = errors.New("unsolicited failed replacement attribute")
			}
		}
	}
	err := c.v4.compound(ctx, fh4(fh), op)
	if err != nil {
		return replacementError(err)
	}
	return nil
}

// VerifyV4ReplacementSource detects observable changes, including replacement
// of the pathname. The subsequent RENAME is not an atomic compare-and-swap.
func (c *Client) VerifyV4ReplacementSource(ctx context.Context, parent []byte, name string, original *V4ReplacementMetadata) error {
	if err := c.checkReplacementProfile(original); err != nil {
		return err
	}
	if original == nil {
		return replacementError(errors.New("missing metadata snapshot"))
	}
	n, err := c.Lookup(ctx, parent, name)
	if err != nil {
		return replacementError(err)
	}
	if !bytes.Equal(n.Handle, original.handle) {
		return replacementError(errors.New("destination object changed before publication"))
	}
	current, err := c.CaptureV4Replacement(ctx, n.Handle)
	if err != nil {
		return err
	}
	if current.attr.Change != original.attr.Change || !sameReplacementPolicy(current, original) || !sameReplacementAttributeSources(current, original) {
		return replacementError(errors.New("destination metadata or content changed before publication"))
	}
	return c.checkReplacementProfile(original)
}

// VerifyV4ReplacementStage binds the publication name back to our checked
// handle. This narrows detectable races; it is not a conditional RENAME.
func (c *Client) VerifyV4ReplacementStage(ctx context.Context, parent []byte, name string, fh []byte, original *V4ReplacementMetadata) error {
	if err := c.checkReplacementProfile(original); err != nil {
		return err
	}
	n, err := c.Lookup(ctx, parent, name)
	if err != nil {
		return replacementError(err)
	}
	if !bytes.Equal(n.Handle, fh) {
		return replacementError(errors.New("staging object changed before publication"))
	}
	current, err := c.CaptureV4Replacement(ctx, fh)
	if err != nil {
		return err
	}
	if !sameReplacementPolicy(current, original) {
		return replacementError(errors.New("staging policy changed before publication"))
	}
	return c.checkReplacementProfile(original)
}
