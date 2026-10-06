package nfs

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// NFS4ACE retains protocol values without principal mapping or ACE reordering.
// Type is ALLOW=0, DENY=1, AUDIT=2, ALARM=3 (RFC 8881 section 6.2.1).
type NFS4ACE struct {
	Type  uint32 `json:"type"`
	Flags uint32 `json:"flags"`
	Mask  uint32 `json:"mask"`
	Who   string `json:"who"`
}

// NFS4ACL selects exactly one wire attribute: acl, dacl or sacl. Flags are
// ACL4_AUTO_INHERIT=1, ACL4_PROTECTED=2, ACL4_DEFAULTED=4 for dacl/sacl only.
// Entries is an ordered list, including duplicates and explicit empty ACLs.
type NFS4ACL struct {
	Attribute string    `json:"attribute"`
	Flags     uint32    `json:"flags"`
	Entries   []NFS4ACE `json:"entries"`
}

var ErrNFS4ACLUnavailable = errors.New("NFSv4 ACL attribute unavailable")

func aclAttribute4(attribute string) (uint32, error) {
	switch attribute {
	case "acl":
		return 12, nil
	case "dacl":
		return 58, nil
	case "sacl":
		return 59, nil
	default:
		return 0, errors.New("ACL attribute must be acl, dacl or sacl")
	}
}

// ValidateNFS4ACL rejects unsupported policy rather than dropping its fields.
func ValidateNFS4ACL(acl *NFS4ACL) error {
	if acl == nil || acl.Entries == nil {
		return errors.New("ACL requires an explicit entries array (use [] for an empty ACL)")
	}
	bit, err := aclAttribute4(acl.Attribute)
	if err != nil {
		return err
	}
	if acl.Flags & ^uint32(7) != 0 || bit == 12 && acl.Flags != 0 {
		return errors.New("invalid ACL flags")
	}
	if len(acl.Entries) > 1024 {
		return errors.New("ACL exceeds 1024 ACEs")
	}
	for i, a := range acl.Entries {
		if len(a.Who) > 4096 || !validACLWho(a.Who) {
			return fmt.Errorf("ACE %d has an invalid or oversized identity", i)
		}
	}
	// Share the replacement codec's protocol validation and wire ordering.
	values := encodeNFS4ACL(acl)
	if len(values) > 65536 {
		return errors.New("ACL exceeds 65536 wire bytes")
	}
	d := &decoder{b: values}
	if bit == 12 {
		readACL4(d)
	} else {
		readReplacementACL(d, bit)
	}
	return d.err
}

func encodeNFS4ACL(acl *NFS4ACL) encoder {
	entries := make([]ace4, len(acl.Entries))
	for i, a := range acl.Entries {
		entries[i] = ace4{a.Type, a.Flags, a.Mask, a.Who}
	}
	var values encoder
	if acl.Attribute != "acl" {
		values.u32(acl.Flags)
	}
	writeACL4(&values, entries)
	return values
}

func (c *Client) checkNFS4ACL(attribute string) (uint32, error) {
	bit, err := aclAttribute4(attribute)
	if err != nil {
		return 0, err
	}
	if c.v4 == nil || bit != 12 && c.v4.minor == 0 {
		return 0, ErrNFS4ACLUnavailable
	}
	return bit, nil
}

// GetNFS4ACL reads one ACL with the selected credentials; absent attributes
// are errors, never an empty policy. No identities or ACEs are normalized.
func (c *Client) GetNFS4ACL(ctx context.Context, fh []byte, attribute string) (*NFS4ACL, error) {
	bit, err := c.checkNFS4ACL(attribute)
	if err != nil {
		return nil, err
	}
	auth := c.Auth
	auth.Groups = slices.Clone(auth.Groups)
	acl, _, err := c.getNFS4ACL(ctx, fh, attribute, bit, auth)
	return acl, err
}

func (c *Client) getNFS4ACL(ctx context.Context, fh []byte, attribute string, bit uint32, auth Auth) (*NFS4ACL, uint32, error) {
	acl := &NFS4ACL{Attribute: attribute, Entries: []NFS4ACE{}}
	var support uint32
	var e encoder
	wanted := []uint32{0, 1, 13, bit}
	bitmap4(&e, wanted...)
	seen := map[uint32]bool{}
	var supported []uint32
	var kind uint32
	err := c.v4.compoundAuth(ctx, auth, fh4(fh), op4(9, e, func(d *decoder) {
		bits := readBitmap4(d)
		a := &decoder{b: d.opaque(65536)}
		for _, b := range bits {
			seen[b] = true
			switch b {
			case 0:
				supported = readBitmap4(a)
			case 1:
				kind = a.u32()
			case 13:
				support = a.u32()
			default:
				if b != bit {
					d.err = errors.New("unsolicited ACL attribute")
					return
				}
				var entries []ace4
				if bit == 12 {
					entries = readACL4(a)
				} else {
					policy := readReplacementACL(a, bit)
					acl.Flags, entries = policy.flags, policy.entries
				}
				for _, ace := range entries {
					acl.Entries = append(acl.Entries, NFS4ACE{ace.kind, ace.flags, ace.mask, ace.who})
				}
			}
		}
		if a.err != nil {
			d.err = a.err
		} else if len(a.b) != 0 {
			d.err = errors.New("trailing ACL attribute data")
		}
	}))
	if err != nil {
		return nil, 0, err
	}
	for _, b := range wanted {
		if !seen[b] || !hasBit4(supported, b) {
			return nil, 0, fmt.Errorf("%w: server does not expose attribute %d", ErrNFS4ACLUnavailable, b)
		}
	}
	if kind != 1 && kind != 2 {
		return nil, 0, errors.New("ACL requires a regular file or directory")
	}
	if support & ^uint32(15) != 0 {
		return nil, 0, errors.New("unknown ACL support flags")
	}
	if err := ValidateNFS4ACL(acl); err != nil {
		return nil, 0, err
	}
	for _, a := range acl.Entries {
		if support&(1<<a.Type) == 0 {
			return nil, 0, errors.New("server returned an unadvertised ACE type")
		}
	}
	return acl, support, nil
}

// SetNFS4ACL writes only the selected ACL attribute and verifies exact
// readback. A readback error means the ACL may already have changed; callers
// must inspect it, never retry or roll back automatically. Mode may change as
// a server-defined consequence of the ACL. File data is never written.
func (c *Client) SetNFS4ACL(ctx context.Context, fh []byte, acl *NFS4ACL) error {
	if err := ValidateNFS4ACL(acl); err != nil {
		return err
	}
	bit, err := c.checkNFS4ACL(acl.Attribute)
	if err != nil {
		return err
	}
	want := *acl
	want.Entries = slices.Clone(acl.Entries)
	auth := c.Auth
	auth.Groups = slices.Clone(auth.Groups)
	_, support, err := c.getNFS4ACL(ctx, fh, want.Attribute, bit, auth)
	if err != nil {
		return err
	}
	for _, a := range want.Entries {
		if support&(1<<a.Type) == 0 {
			return fmt.Errorf("%w: ACE type %d is not advertised", ErrNFS4ACLUnavailable, a.Type)
		}
	}
	var attrs encoder
	bitmap4(&attrs, bit)
	attrs.opaque(encodeNFS4ACL(&want))
	e := make(encoder, 16) // Anonymous stateid; ACL-only SETATTR needs no OPEN.
	e = append(e, attrs...)
	if c.v4.channel.Request == 0 && c.v4.maxRequestPayload != 0 && uint64(len(e))+uint64(len(fh))+32 > uint64(c.v4.maxRequestPayload) {
		return errors.New("ACL exceeds the negotiated request budget")
	}
	op := op4(34, e, func(d *decoder) {
		if got := readBitmap4(d); d.err == nil && !slices.Equal(got, []uint32{bit}) {
			d.err = errors.New("server did not acknowledge the ACL attribute")
		}
	})
	op.failure = func(d *decoder) {
		if got := readBitmap4(d); len(got) != 0 {
			d.err = errors.New("failed ACL SETATTR reported a changed attribute; inspect policy")
		}
	}
	if err := c.v4.compoundAuth(ctx, auth, fh4(fh), op); err != nil {
		return fmt.Errorf("ACL SETATTR failed; inspect policy before retrying: %w", err)
	}
	got, _, err := c.getNFS4ACL(ctx, fh, want.Attribute, bit, auth)
	if err != nil {
		return fmt.Errorf("ACL SETATTR succeeded but readback failed; policy may have changed: %w", err)
	}
	if got.Flags != want.Flags || !slices.Equal(got.Entries, want.Entries) {
		return errors.New("ACL SETATTR succeeded but readback differs; server changed policy, inspect before retrying")
	}
	return nil
}
