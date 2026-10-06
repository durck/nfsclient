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

var ErrNFS3PublishUncertain = errors.New("NFSv3 replacement publication outcome unknown; inspect both names before retrying")

// ReplaceNFS3 implements bounded, complete exposed POSIX ACL preservation.
// It requires NFSACL, one link, ordinary mode, equal owner/group, a private
// acknowledged stage, stable writes, exact policy readback and final pathname
// checks. It never performs in-place writes or replays uncertain mutations.
// RENAME is atomic, but its final check is not compare-and-swap. Arbitrary
// xattrs/security labels and concurrent namespace writers are outside scope.
// On error an acknowledged stage is retained by name rather than risking a
// racy REMOVE of a substituted object. Use serially with a fixed identity.
func (c *Client) ReplaceNFS3(ctx context.Context, parent []byte, name string, input io.Reader, size int64, progress func(uint64)) (count int64, resultErr error) {
	if size < 0 {
		return 0, errors.New("negative replacement size")
	}
	original, err := c.CaptureNFS3Replacement(ctx, parent, name)
	if err != nil {
		return 0, err
	}
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return 0, err
	}
	stageName := ".nfs-upload-" + hex.EncodeToString(token[:])
	stage, err := c.CreateNFS3ReplacementStage(ctx, stageName, original)
	if err != nil {
		return 0, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("replacement staging file %q may remain: %w", stageName, resultErr)
		}
	}()
	count, err = c.WriteFromProgress(ctx, stage.Handle, io.LimitReader(input, size), progress)
	if err != nil {
		return count, err
	}
	if count != size {
		return count, errors.New("replacement source ended before its declared size")
	}
	var extra [1]byte
	n, err := input.Read(extra[:])
	if n != 0 {
		return count, errors.New("replacement source grew beyond its declared size")
	}
	if err != io.EOF {
		if err == nil {
			err = io.ErrNoProgress
		}
		return count, err
	}
	private, err := c.CaptureNFS3Replacement(ctx, parent, stageName)
	if err != nil {
		return count, err
	}
	a, b := private.policy.Attr, original.policy.Attr
	if !bytes.Equal(private.handle, stage.Handle) || a.FSID != b.FSID || a.FileID != stage.Attr.FileID ||
		a.UID != b.UID || a.GID != b.GID || a.Size != uint64(size) || a.Mode != 0600 {
		return count, nfs3ReplacementError(errors.New("written stage changed identity, size, ownership or privacy"))
	}
	for _, entry := range private.policy.Access {
		if entry.Tag != ACLUserObj && entry.Perm != 0 {
			return count, nfs3ReplacementError(errors.New("written stage gained raw nonowner rights"))
		}
	}
	if err := c.VerifyNFS3ReplacementSource(ctx, original); err != nil {
		return count, err
	}
	if err := c.SetNFS3ACL(ctx, stage.Handle, original.policy); err != nil {
		return count, err
	}
	restored, err := c.CaptureNFS3Replacement(ctx, parent, stageName)
	if err != nil {
		return count, err
	}
	a = restored.policy.Attr
	if !bytes.Equal(restored.handle, stage.Handle) || a.FileID != private.policy.Attr.FileID || a.FSID != b.FSID ||
		a.UID != b.UID || a.GID != b.GID || a.Size != uint64(size) || !a.MTime.Equal(private.policy.Attr.MTime) || a.Mode != b.Mode ||
		!slices.Equal(restored.policy.Access, original.policy.Access) || !slices.Equal(restored.policy.Default, original.policy.Default) {
		return count, nfs3ReplacementError(errors.New("restored stage differs from the written file or original policy"))
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
	if err := original.checkClient(c); err != nil {
		return count, nfs3ReplacementError(err)
	}
	if err := c.Rename(ctx, parent, stageName, parent, name); err != nil {
		return count, fmt.Errorf("%w: %w", ErrNFS3PublishUncertain, err)
	}
	return count, nil
}
