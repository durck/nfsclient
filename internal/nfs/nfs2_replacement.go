package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
)

var ErrNFS2PublishUncertain = errors.New("NFSv2 publication outcome unknown; inspect destination and stage before retrying")

func (c *Client) legacyACLVersion() uint32 {
	if c.Version() == "2" {
		return 2
	}
	return 3
}

// NFSv2 fattr carries type bits in mode; the shared ACL policy uses permissions.
func replacementAttr2(a Attr) (Attr, error) {
	typ := uint32(0)
	if a.Type == 1 {
		typ = 0100000
	} else if a.Type == 2 {
		typ = 0040000
	} else {
		return Attr{}, errors.New("replacement requires a regular file or directory")
	}
	if a.Mode&^uint32(0177777) != 0 || a.Mode&0170000 != 0 && a.Mode&0170000 != typ {
		return Attr{}, errors.New("invalid NFSv2 mode/type")
	}
	a.Mode &= 07777
	if a.Size > maxV2File {
		return Attr{}, errors.New("NFSv2 file exceeds 2 GiB minus one byte")
	}
	return a, nil
}

func decodeNFS2ACL(d *decoder) (*NFS3ACL, error) {
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
	a := attr2(d)
	if d.err != nil {
		return nil, d.err
	}
	a, err := replacementAttr2(a)
	if err != nil {
		return nil, err
	}
	return decodeLegacyACLBody(d, a)
}

func decodeNFS2ACLSet(d *decoder) (Attr, bool, error) {
	status := d.u32()
	if d.err != nil {
		return Attr{}, false, d.err
	}
	if status != 0 {
		return Attr{}, false, Status(status)
	}
	a := attr2(d)
	if d.err != nil {
		return Attr{}, false, d.err
	}
	if len(d.b) != 0 {
		return Attr{}, false, errors.New("trailing NFSv2 SETACL reply data")
	}
	a, err := replacementAttr2(a)
	return a, err == nil, err
}

func (c *Client) lookupReplacement2(ctx context.Context, parent []byte, name string) (Node, error) {
	e, err := handle2(parent)
	if err != nil {
		return Node{}, err
	}
	e.str(name)
	d, err := c.call(ctx, 4, e)
	if err != nil {
		return Node{}, err
	}
	n := Node{Handle: bytes.Clone(d.take(32)), Attr: attr2(d)}
	if d.err != nil {
		return Node{}, d.err
	}
	if len(d.b) != 0 {
		return Node{}, errors.New("trailing NFSv2 LOOKUP reply")
	}
	n.Attr, err = replacementAttr2(n.Attr)
	if err != nil {
		return Node{}, err
	}
	if err := validateNFS3ReplacementAttr(n.Attr); err != nil {
		return Node{}, err
	}
	return n, nil
}

func privateLegacyACL(p *NFS3ACL) bool {
	for _, entry := range p.Access {
		if entry.Tag != ACLUserObj && entry.Perm != 0 {
			return false
		}
	}
	return len(p.Default) == 0
}

// ReplaceNFS2 preserves the destination's exposed POSIX policy using NFSACL v2.
// CREATE is restricted to a freshly acknowledged private directory. Source and
// stage are checked again before one atomic RENAME, without compare-and-swap.
// Concurrent namespace writers, hidden labels/xattrs and power loss are outside
// this bounded contract. Failed stages are retained for explicit inspection.
func (c *Client) ReplaceNFS2(ctx context.Context, parent []byte, name string, input io.Reader, size int64, progress func(uint64)) (count int64, resultErr error) {
	if c.Version() != "2" || size < 0 || size > maxV2File {
		return 0, errors.New("NFSv2 replacement requires a source of at most 2 GiB minus one byte")
	}
	if _, err := handle2(parent); err != nil {
		return 0, err
	}
	if err := validateReplacementPath3(parent, name); err != nil {
		return 0, err
	}
	if len(c.Locks()) != 0 {
		return 0, ErrLocksHeld
	}
	parent = bytes.Clone(parent)
	original, err := c.captureLegacyReplacement(ctx, parent, name)
	if err != nil {
		return 0, err
	}
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return 0, err
	}
	stageName := ".nfs-replace-" + hex.EncodeToString(token[:])
	published, publishAttempted := false, false
	defer func() {
		if resultErr != nil {
			state := "destination was not published by this operation"
			if publishAttempted {
				state = "publication outcome unknown; do not retry"
			}
			if published {
				state = "destination published; do not retry"
			}
			resultErr = fmt.Errorf("%s; inspect staging directory %q: %w", state, stageName, resultErr)
		}
	}()
	dir, err := c.create2(ctx, parent, stageName, 0700, true)
	if err != nil {
		return 0, err
	}
	policy, err := c.getLegacyACL(ctx, dir.Handle)
	if err != nil {
		return 0, err
	}
	dir.Attr, err = replacementAttr2(dir.Attr)
	if err != nil {
		return 0, err
	}
	a, b := policy.Attr, original.policy.Attr
	if a.Type != 2 || a.Mode != 0700 || a.UID != b.UID || a.GID != b.GID || a.FSID != b.FSID || !stableNFS3ACLTarget(dir.Attr, a) || !privateLegacyACL(policy) {
		return 0, errors.New("staging directory lacks private policy or matching ownership/filesystem")
	}
	directoryAttr := a
	checkDir := func() error {
		n, err := c.lookup2(ctx, parent, stageName)
		if err != nil {
			return err
		}
		p, err := c.getLegacyACL(ctx, dir.Handle)
		if err != nil {
			return err
		}
		if !bytes.Equal(n.Handle, dir.Handle) || p.Attr.Type != 2 || p.Attr.FSID != directoryAttr.FSID || p.Attr.FileID != directoryAttr.FileID || p.Attr.UID != directoryAttr.UID || p.Attr.GID != directoryAttr.GID || p.Attr.Mode != 0700 || !privateLegacyACL(p) {
			return errors.New("staging directory identity/privacy changed")
		}
		return original.checkClient(c)
	}
	if err := checkDir(); err != nil {
		return 0, err
	}
	e, _ := handle2(dir.Handle)
	e.str("payload")
	e.u32(0600)
	e.u32(^uint32(0))
	e.u32(^uint32(0))
	e.u32(0)
	for range 4 {
		e.u32(^uint32(0))
	}
	d, err := c.call(ctx, 9, e)
	if err != nil {
		return 0, err
	}
	file := Node{Handle: bytes.Clone(d.take(32)), Attr: attr2(d)}
	if d.err != nil {
		return 0, d.err
	}
	if len(d.b) != 0 {
		return 0, errors.New("trailing staging CREATE reply")
	}
	file.Attr, err = replacementAttr2(file.Attr)
	if err != nil {
		return 0, err
	}
	stage, err := c.captureLegacyReplacement(ctx, dir.Handle, "payload")
	if err != nil {
		return 0, err
	}
	a = stage.policy.Attr
	if !bytes.Equal(file.Handle, stage.handle) || !sameNFS3ReplacementAttr(file.Attr, a) || bytes.Equal(file.Handle, original.handle) || a.FileID == b.FileID || a.FSID != b.FSID || a.UID != b.UID || a.GID != b.GID || a.Mode != 0600 || a.Size != 0 || !privateLegacyACL(stage.policy) {
		return 0, errors.New("payload stage is not distinct, empty and private with matching ownership")
	}
	count, err = c.write2(ctx, file.Handle, io.LimitReader(input, size), progress)
	if err != nil {
		return count, err
	}
	if count != size {
		return count, errors.New("replacement source ended before declared size")
	}
	var extra [1]byte
	n, err := input.Read(extra[:])
	if n != 0 {
		return count, errors.New("replacement source grew")
	}
	if err != io.EOF {
		if err == nil {
			err = io.ErrNoProgress
		}
		return count, err
	}
	if err := original.checkClient(c); err != nil {
		return count, err
	}
	written, err := c.captureLegacyReplacement(ctx, dir.Handle, "payload")
	if err != nil {
		return count, err
	}
	wa := written.policy.Attr
	if !bytes.Equal(file.Handle, written.handle) || wa.FileID != a.FileID || wa.FSID != a.FSID || wa.UID != a.UID || wa.GID != a.GID || wa.Mode != 0600 || wa.Size != uint64(size) || !privateLegacyACL(written.policy) {
		return count, errors.New("written stage changed identity, policy or size")
	}
	if err := c.VerifyNFS3ReplacementSource(ctx, original); err != nil {
		return count, err
	}
	if err := c.setLegacyACL(ctx, file.Handle, original.policy); err != nil {
		return count, err
	}
	restored, err := c.captureLegacyReplacement(ctx, dir.Handle, "payload")
	if err != nil {
		return count, err
	}
	if !bytes.Equal(restored.handle, file.Handle) || !stableNFS3ACLTarget(wa, restored.policy.Attr) || restored.policy.Attr.Mode != b.Mode || !slices.Equal(restored.policy.Access, original.policy.Access) || !slices.Equal(restored.policy.Default, original.policy.Default) {
		return count, errors.New("restored stage differs from written data or destination policy")
	}
	if err := checkDir(); err != nil {
		return count, err
	}
	if err := c.VerifyNFS3ReplacementSource(ctx, original); err != nil {
		return count, err
	}
	if err := c.VerifyNFS3ReplacementSource(ctx, restored); err != nil {
		return count, err
	}
	if err := ctx.Err(); err != nil {
		return count, err
	}
	publishAttempted = true
	if err := c.Rename(ctx, dir.Handle, "payload", parent, name); err != nil {
		// Even explicit errors retain the stage; never replay an uncertain publish.
		return count, fmt.Errorf("%w: %w", ErrNFS2PublishUncertain, err)
	}
	published = true
	if err := checkDir(); err != nil {
		return count, err
	}
	if err := c.rmdir2(ctx, parent, stageName); err != nil {
		return count, err
	}
	return count, nil
}
