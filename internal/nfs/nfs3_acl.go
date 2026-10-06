package nfs

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const nfsACLProgram = 100227
const nfsACLMask = 0xf
const nfsACLDefault = 0x1000
const maxNFSACLEntries = 1024
const maxNFSACLReply = 32 << 10

const (
	ACLUserObj  uint32 = 1
	ACLUser     uint32 = 2
	ACLGroupObj uint32 = 4
	ACLGroup    uint32 = 8
	ACLMask     uint32 = 16
	ACLOther    uint32 = 32
)

var ErrNFSACLUnavailable = errors.New("NFS ACL extension unavailable on the selected NFS endpoint")

// NFS3ACLEntry retains numeric wire identities and unmasked permission bits.
// Tag omits the DEFAULT flag because the containing list identifies its scope.
type NFS3ACLEntry struct {
	Tag, ID, Perm uint32
}

// NFS3ACL is a complete, bounded Linux/Solaris NFSACL observation, not an
// access decision or a guarantee that every filesystem policy is represented.
type NFS3ACL struct {
	Attr    Attr
	Access  []NFS3ACLEntry
	Default []NFS3ACLEntry
}

// GetNFS3ACL reads both access and default ACLs over the existing NFS connection
// with its current identity/security. It never discovers another endpoint,
// falls back to AUTH_SYS, edits ACLs or enables legacy upload replacement.
func (c *Client) GetNFS3ACL(ctx context.Context, fh []byte) (*NFS3ACL, error) {
	if c.Version() != "3" {
		return nil, fmt.Errorf("%w: acl inspection currently requires NFSv3", ErrNFSACLUnavailable)
	}
	return c.getLegacyACL(ctx, fh)
}

// GetLegacyACL reads complete NFSv2/v3 ACLs with the current connection and
// selected identity. It never probes another endpoint or changes credentials.
func (c *Client) GetLegacyACL(ctx context.Context, fh []byte) (*NFS3ACL, error) {
	if c.Version() != "2" && c.Version() != "3" {
		return nil, ErrNFSACLUnavailable
	}
	return c.getLegacyACL(ctx, fh)
}

func (c *Client) getLegacyACL(ctx context.Context, fh []byte) (*NFS3ACL, error) {
	if len(fh) == 0 || len(fh) > 64 {
		return nil, errors.New("invalid NFSv3 ACL file handle")
	}
	var e encoder
	if c.Version() == "2" {
		if len(fh) != 32 {
			return nil, errors.New("invalid NFSv2 ACL handle")
		}
		e = append(e, fh...)
	} else {
		e.opaque(fh)
	}
	e.u32(nfsACLMask)
	d, err := c.nfs.call(ctx, nfsACLProgram, c.legacyACLVersion(), 1, &c.Auth, e)
	if err != nil {
		var rpcStatus RPCStatus
		if errors.As(err, &rpcStatus) && rpcStatus >= 1 && rpcStatus <= 3 {
			return nil, fmt.Errorf("%w: %w", ErrNFSACLUnavailable, err)
		}
		return nil, err
	}
	var result *NFS3ACL
	if c.Version() == "2" {
		result, err = decodeNFS2ACL(d)
	} else {
		result, err = decodeNFS3ACL(d)
	}
	if errors.Is(err, Status(10004)) {
		return nil, fmt.Errorf("%w: %w", ErrNFSACLUnavailable, err)
	}
	if err != nil {
		return nil, fmt.Errorf("read NFS ACL: %w", err)
	}
	return result, nil
}

func decodeNFS3ACL(d *decoder) (*NFS3ACL, error) {
	if len(d.b) > maxNFSACLReply {
		return nil, errors.New("ACL reply exceeds 32 KiB")
	}
	status := d.u32()
	if d.err != nil {
		return nil, d.err
	}
	if status != 0 {
		return nil, Status(status)
	}
	a, present := postAttr(d)
	if d.err != nil {
		return nil, d.err
	}
	if !present || (a.Type != 1 && a.Type != 2) {
		return nil, errors.New("ACL reply requires regular-file or directory attributes")
	}
	return decodeLegacyACLBody(d, a)
}

func decodeLegacyACLBody(d *decoder, a Attr) (*NFS3ACL, error) {
	if d.u32() != nfsACLMask || d.err != nil {
		return nil, errors.New("ACL reply omits requested access/default policy or contains unknown mask bits")
	}
	access, err := decodeNFS3ACLList(d, a, false)
	if err != nil {
		return nil, fmt.Errorf("access ACL: %w", err)
	}
	defaults, err := decodeNFS3ACLList(d, a, true)
	if err != nil {
		return nil, fmt.Errorf("default ACL: %w", err)
	}
	if len(d.b) != 0 {
		return nil, errors.New("trailing ACL reply data")
	}
	result := &NFS3ACL{Attr: a, Access: access, Default: defaults}
	if err := validateNFS3ACLMode(result); err != nil {
		return nil, err
	}
	return result, nil
}

func validateNFS3ACLMode(policy *NFS3ACL) error {
	a := policy.Attr
	if a.Type != 1 && a.Type != 2 {
		return errors.New("ACL requires regular-file or directory attributes")
	}
	if a.Type != 2 && len(policy.Default) != 0 {
		return errors.New("regular file has a default ACL")
	}
	for _, entry := range policy.Access {
		var expected uint32
		switch entry.Tag {
		case ACLUserObj:
			expected = (a.Mode >> 6) & 7
		case ACLMask:
			expected = (a.Mode >> 3) & 7
		case ACLOther:
			expected = a.Mode & 7
		default:
			continue
		}
		if entry.Perm != expected {
			return errors.New("access ACL and returned mode disagree; policy may have changed")
		}
	}
	return nil
}

func decodeNFS3ACLList(d *decoder, a Attr, defaults bool) ([]NFS3ACLEntry, error) {
	count, length := d.u32(), d.u32()
	if d.err != nil {
		return nil, d.err
	}
	if count != length || count > maxNFSACLEntries || uint64(count)*12 > uint64(len(d.b)) {
		return nil, errors.New("invalid, incomplete or oversized ACL entry count")
	}
	entries := make([]NFS3ACLEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		tag, id, perm := d.u32(), d.u32(), d.u32()
		if (tag&nfsACLDefault != 0) != defaults {
			return nil, errors.New("wrong default flag")
		}
		entries = append(entries, NFS3ACLEntry{Tag: tag &^ nfsACLDefault, ID: id, Perm: perm})
	}
	return canonicalNFS3ACLList(entries, a, defaults)
}

// Copy before sorting so callers retain their policy and wire order untouched.
func canonicalNFS3ACLList(input []NFS3ACLEntry, a Attr, defaults bool) ([]NFS3ACLEntry, error) {
	if len(input) > maxNFSACLEntries {
		return nil, errors.New("ACL exceeds 1024 entries")
	}
	if len(input) == 0 {
		if !defaults {
			return nil, errors.New("empty access ACL")
		}
		return []NFS3ACLEntry{}, nil
	}
	entries := append([]NFS3ACLEntry(nil), input...)
	seen := make(map[[2]uint32]bool, len(entries))
	base := uint32(0)
	for _, entry := range entries {
		tag, id, perm := entry.Tag, entry.ID, entry.Perm
		if perm > 7 {
			return nil, errors.New("unknown ACL permissions")
		}
		switch tag {
		case ACLUserObj:
			if id != a.UID {
				return nil, errors.New("owner entry does not match attributes")
			}
			base |= tag
		case ACLGroupObj:
			if id != a.GID {
				return nil, errors.New("group entry does not match attributes")
			}
			base |= tag
		case ACLMask, ACLOther:
			if id != 0 {
				return nil, errors.New("nonzero mask/other identifier is unsupported")
			}
			base |= tag
		case ACLUser, ACLGroup:
			if id == ^uint32(0) {
				return nil, errors.New("undefined named ACL identity")
			}
		default:
			return nil, fmt.Errorf("unsupported ACL tag %#x", tag)
		}
		key := [2]uint32{tag, id}
		if seen[key] {
			return nil, errors.New("duplicate ACL entry")
		}
		seen[key] = true
	}
	if base != ACLUserObj|ACLGroupObj|ACLMask|ACLOther {
		return nil, errors.New("ACL requires owner, group, mask and other entries")
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Tag != entries[j].Tag {
			return entries[i].Tag < entries[j].Tag
		}
		return entries[i].ID < entries[j].ID
	})
	return entries, nil
}
