package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// ErrNFS3StageUnverified means CREATE was attempted but a private empty stage
// was not verified. The name may exist even after an explicit server error.
// Inspect server state before retrying; this API never removes or adopts it.
var ErrNFS3StageUnverified = errors.New("NFSv3 staging creation unverified; inspect server state before retrying")

// CreateNFS3ReplacementStage creates one empty 0600 sibling of the captured
// source and verifies its name, identity and complete exposed ACL. The caller
// supplies a fresh staging basename, distinct from the source's basename.
// Inherited raw nonowner rights and server-suppressed owner permissions refuse;
// this method does not normalize ACLs, change identity, write data or publish.
//
// One GUARDED CREATE is attempted, without replay, LOOKUP adoption or cleanup.
// Every error after that attempt wraps ErrNFS3StageUnverified and returns no
// usable Node. A successful Node is an observation, not a lock or authorization
// to skip later source/stage checks. Serial Client use remains required.
func (c *Client) CreateNFS3ReplacementStage(ctx context.Context, name string, original *NFS3ReplacementMetadata) (Node, error) {
	if err := original.checkClient(c); err != nil {
		return Node{}, nfs3ReplacementError(err)
	}
	if err := validateReplacementPath3(original.parent, name); err != nil {
		return Node{}, nfs3ReplacementError(err)
	}
	if name == original.name {
		return Node{}, nfs3ReplacementError(errors.New("staging name must differ from the source name"))
	}
	if err := c.VerifyNFS3ReplacementSource(ctx, original); err != nil {
		return Node{}, err
	}
	if err := ctx.Err(); err != nil {
		return Node{}, nfs3ReplacementError(err)
	}
	var args encoder
	args.opaque(original.parent)
	args.str(name)
	args.u32(1) // GUARDED: a competing name must never be truncated or adopted.
	mode, size := uint32(0600), uint64(0)
	sattr(&args, &mode, &size) // No requested UID/GID or client timestamps.
	d, err := c.nfs.call(ctx, nfsProgram, 3, 8, &c.Auth, args)
	if err != nil {
		return Node{}, unverifiedNFS3Stage(name, err)
	}
	created, err := decodeNFS3StageCreate(d)
	if err != nil {
		return Node{}, unverifiedNFS3Stage(name, err)
	}
	a, b := created.Attr, original.policy.Attr
	if err := validateNFS3ReplacementAttr(a); err != nil {
		return Node{}, unverifiedNFS3Stage(name, err)
	}
	if bytes.Equal(created.Handle, original.handle) || a.FileID == b.FileID || a.FSID != b.FSID ||
		a.UID != b.UID || a.GID != b.GID || a.Mode != 0600 || a.Size != 0 {
		return Node{}, unverifiedNFS3Stage(name, errors.New("CREATE did not acknowledge a distinct, empty private file with matching filesystem and ownership"))
	}
	if err := c.CheckNFS3ReplacementStage(ctx, original.parent, name, created.Handle, original); err != nil {
		return Node{}, unverifiedNFS3Stage(name, err)
	}
	// Compare with CREATE, not just a self-consistent later observation: a
	// substituted or modified object must not become the creation baseline.
	observed, err := c.CaptureNFS3Replacement(ctx, original.parent, name)
	if err != nil {
		return Node{}, unverifiedNFS3Stage(name, err)
	}
	if !bytes.Equal(created.Handle, observed.handle) || !sameNFS3ReplacementAttr(created.Attr, observed.policy.Attr) {
		return Node{}, unverifiedNFS3Stage(name, errors.New("staging identity or metadata changed after CREATE"))
	}
	// Recheck raw privacy on the final observation too; hidden grants could
	// change without an observable timestamp between the two ACL reads.
	for _, entry := range observed.policy.Access {
		if entry.Tag != ACLUserObj && entry.Perm != 0 {
			return Node{}, unverifiedNFS3Stage(name, errors.New("staging ACL gained nonowner rights, including masked-off rights"))
		}
	}
	return Node{Handle: bytes.Clone(created.Handle), Attr: created.Attr}, nil
}

func unverifiedNFS3Stage(name string, err error) error {
	return fmt.Errorf("%w: temporary file %q may remain: %w", ErrNFS3StageUnverified, name, nfs3ReplacementError(err))
}

func decodeNFS3StageCreate(d *decoder) (Node, error) {
	// nfsstat3 + post_op_fh3 (64 bytes) + post_op_attr + full wcc_data.
	if len(d.b) > 280 {
		return Node{}, errors.New("oversized staging CREATE reply")
	}
	status := d.u32()
	var n Node
	var handlePresent, attrPresent bool
	if status == 0 {
		handlePresent = d.boolean()
		if handlePresent {
			n.Handle = bytes.Clone(d.opaque(64))
		}
		n.Attr, attrPresent = postAttr(d)
	}
	// WCC's before attributes contain size, mtime and ctime. Its optional
	// directory observations are parsed, never used as file-ownership proof.
	if d.boolean() {
		d.u64()
		for i := 0; i < 2; i++ {
			d.u32()
			if d.u32() >= 1e9 {
				d.err = errors.New("invalid staging CREATE directory timestamp")
			}
		}
	}
	postAttr(d)
	if d.err != nil || len(d.b) != 0 {
		err := d.err
		if err == nil {
			err = errors.New("trailing staging CREATE reply data")
		}
		if status != 0 {
			err = errors.Join(Status(status), err)
		}
		return Node{}, err
	}
	if status != 0 {
		return Node{}, Status(status)
	}
	if !handlePresent || !validReplacementHandle3(n.Handle) || !attrPresent {
		return Node{}, errors.New("staging CREATE requires a nonempty acknowledged handle and complete object attributes")
	}
	return n, nil
}
