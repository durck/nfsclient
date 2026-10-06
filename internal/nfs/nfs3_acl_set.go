package nfs

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// ErrNFSACLMutationUnverified means a SETACL was attempted but its complete
// result is not verified. Even a server error may follow a partial update.
var ErrNFSACLMutationUnverified = errors.New("NFS ACL update may have been applied; inspect server state before retrying")

// SetNFS3ACL replaces BOTH access and default ACLs, then requires exact GETACL
// readback. Empty Default explicitly clears inherited policy on a directory.
// Only Type, UID, GID and ordinary Mode from policy.Attr describe the desired
// policy; other attributes are not copied. The target must already have the
// same type and owner/group. Use only on caller-owned disposable staging until
// a separate publication contract is implemented. In-place CLI edits use the
// separate EditLegacyACL contract.
//
// SETACL is sent once using the current connection/identity/security. Errors
// after that attempt wrap ErrNFSACLMutationUnverified; no rollback or mutation
// retry is attempted. Preflight/readback are observations, not a lock or CAS.
func (c *Client) SetNFS3ACL(ctx context.Context, fh []byte, policy *NFS3ACL) error {
	if c.Version() != "3" {
		return fmt.Errorf("%w: ACL updates require NFSv3", ErrNFSACLUnavailable)
	}
	return c.setLegacyACL(ctx, fh, policy)
}

func (c *Client) setLegacyACL(ctx context.Context, fh []byte, policy *NFS3ACL) error {
	return c.setLegacyACLSelected(ctx, fh, policy, nil)
}

// EditLegacyACL explicitly edits an existing selected regular file or directory
// on NFSv2/v3. The caller must resolve without following symbolic links and keep
// the selected credentials unchanged throughout resolution and this call.
// Both complete lists are required; an empty Default clears directory defaults.
// Policy type/owner/group must match the target. The selected object's identity,
// size and mtime are checked before the single SETACL and at exact readback.
// These observations do not lock the object or provide atomic compare-and-swap.
// Any failure after SETACL is uncertain: no retry, rollback or reconnect occurs.
// SetNFS3ACL retains its separate disposable-staging contract.
func (c *Client) EditLegacyACL(ctx context.Context, selected Node, policy *NFS3ACL) error {
	if c.Version() != "2" && c.Version() != "3" {
		return ErrNFSACLUnavailable
	}
	if selected.Attr.Type != 1 && selected.Attr.Type != 2 {
		return errors.New("ACL editing requires a regular file or directory; symbolic links are not followed")
	}
	if policy == nil || policy.Default == nil {
		return errors.New("ACL editing requires an explicit default list; use an empty list to clear defaults")
	}
	return c.setLegacyACLSelected(ctx, selected.Handle, policy, &selected.Attr)
}

// ValidateLegacyACL validates both complete policy lists without network I/O.
func ValidateLegacyACL(policy *NFS3ACL) error {
	_, err := prepareNFS3ACLPolicy(policy)
	return err
}

func (c *Client) setLegacyACLSelected(ctx context.Context, fh []byte, policy *NFS3ACL, selected *Attr) error {
	if len(fh) == 0 || len(fh) > 64 {
		return errors.New("invalid NFSv3 ACL file handle")
	}
	want, err := prepareNFS3ACLPolicy(policy)
	if err != nil {
		return err
	}
	before, err := c.getLegacyACL(ctx, fh)
	if err != nil {
		return fmt.Errorf("ACL update preflight: %w", err)
	}
	if before.Attr.Type != want.Attr.Type || before.Attr.UID != want.Attr.UID || before.Attr.GID != want.Attr.GID || before.Attr.Mode&^uint32(0777) != 0 {
		return errors.New("ACL update requires matching target type/owner/group and ordinary mode")
	}
	if selected != nil && !stableNFS3ACLTarget(*selected, before.Attr) {
		return errors.New("ACL target changed since selection or lacks complete identity attributes")
	}
	var args encoder
	if c.Version() == "2" {
		if len(fh) != 32 {
			return errors.New("invalid NFSv2 ACL handle")
		}
		args = append(args, fh...)
	} else {
		args.opaque(fh)
	}
	args.u32(5) // NFS_ACL | NFS_DFACL; both complete lists, never patch semantics.
	for i, entries := range [][]NFS3ACLEntry{want.Access, want.Default} {
		args.u32(uint32(len(entries)))
		args.u32(uint32(len(entries)))
		for _, entry := range entries {
			tag := entry.Tag
			if i == 1 {
				tag |= nfsACLDefault
			}
			args.u32(tag)
			args.u32(entry.ID)
			args.u32(entry.Perm)
		}
	}
	if len(args) > maxNFSACLReply {
		return errors.New("ACL request exceeds 32 KiB")
	}
	d, err := c.nfs.call(ctx, nfsACLProgram, c.legacyACLVersion(), 2, &c.Auth, args)
	if err != nil {
		var status RPCStatus
		if errors.As(err, &status) && status >= 1 && status <= 3 {
			err = fmt.Errorf("%w: %w", ErrNFSACLUnavailable, err)
		}
		return unverifiedNFS3ACL(err)
	}
	var a Attr
	var present bool
	if c.Version() == "2" {
		a, present, err = decodeNFS2ACLSet(d)
	} else {
		a, present, err = decodeNFS3ACLSet(d)
	}
	if err != nil {
		if errors.Is(err, Status(10004)) {
			err = fmt.Errorf("%w: %w", ErrNFSACLUnavailable, err)
		}
		return unverifiedNFS3ACL(err)
	}
	if present && (!stableNFS3ACLTarget(before.Attr, a) || a.Mode != want.Attr.Mode) {
		return unverifiedNFS3ACL(errors.New("SETACL attributes differ from expected target or mode"))
	}
	observed, err := c.getLegacyACL(ctx, fh)
	if err != nil {
		return unverifiedNFS3ACL(fmt.Errorf("ACL readback: %w", err))
	}
	if !stableNFS3ACLTarget(before.Attr, observed.Attr) || observed.Attr.Mode != want.Attr.Mode ||
		!slices.Equal(want.Access, observed.Access) || !slices.Equal(want.Default, observed.Default) {
		return unverifiedNFS3ACL(errors.New("ACL readback differs from requested policy or target"))
	}
	return nil
}

func unverifiedNFS3ACL(err error) error {
	return fmt.Errorf("%w: %w", ErrNFSACLMutationUnverified, err)
}

func prepareNFS3ACLPolicy(policy *NFS3ACL) (*NFS3ACL, error) {
	if policy == nil {
		return nil, errors.New("missing complete ACL policy")
	}
	if policy.Attr.Mode&^uint32(0777) != 0 {
		return nil, errors.New("ACL update does not support special or unknown mode bits")
	}
	a := &NFS3ACL{Attr: policy.Attr}
	var err error
	if a.Access, err = canonicalNFS3ACLList(policy.Access, a.Attr, false); err != nil {
		return nil, fmt.Errorf("access ACL: %w", err)
	}
	if a.Default, err = canonicalNFS3ACLList(policy.Default, a.Attr, true); err != nil {
		return nil, fmt.Errorf("default ACL: %w", err)
	}
	if err := validateNFS3ACLMode(a); err != nil {
		return nil, err
	}
	return a, nil
}

func decodeNFS3ACLSet(d *decoder) (Attr, bool, error) {
	if len(d.b) > 92 { // nfsstat3 + optional fattr3, never an ACL array.
		return Attr{}, false, errors.New("oversized SETACL reply")
	}
	status := d.u32()
	a, present := postAttr(d)
	if d.err != nil || len(d.b) != 0 {
		err := d.err
		if err == nil {
			err = errors.New("trailing SETACL reply data")
		}
		if status != 0 {
			err = errors.Join(Status(status), err)
		}
		return Attr{}, false, err
	}
	if status != 0 {
		return Attr{}, false, Status(status)
	}
	return a, present, nil
}

// ACL writes change ctime and mode. Content or identity changes are not accepted
// as successful policy restoration. A concurrent change can still race checks.
func stableNFS3ACLTarget(before, after Attr) bool {
	return before.Type == after.Type && before.UID == after.UID && before.GID == after.GID &&
		before.HasFSID && after.HasFSID && before.FSID == after.FSID &&
		before.HasFileID && after.HasFileID && before.FileID == after.FileID &&
		before.HasSize && after.HasSize && before.Size == after.Size &&
		before.HasMTime && after.HasMTime && before.MTime.Equal(after.MTime)
}
