package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

var ErrNFS3ReplacementRefused = errors.New("legacy replacement preflight refused")

// NFS3ReplacementMetadata is an opaque observation of a single-link regular
// file's path, identity and complete exposed POSIX ACL. It is not a lock,
// authorization decision, content snapshot or complete filesystem metadata.
// Serial use of the capturing client is required, as with other Client APIs.
type NFS3ReplacementMetadata struct {
	client              *Client
	connection          *rpcClient
	transport           net.Conn
	auth                Auth
	security, principal string
	version             string
	parent, handle      []byte
	name                string
	policy              *NFS3ACL
}

func nfs3ReplacementError(err error) error {
	return fmt.Errorf("%w: %w", ErrNFS3ReplacementRefused, err)
}

func validReplacementHandle3(fh []byte) bool { return len(fh) > 0 && len(fh) <= 64 }

func validateReplacementPath3(parent []byte, name string) error {
	if !validReplacementHandle3(parent) || len(name) == 0 || len(name) > 255 ||
		name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return errors.New("requires a valid parent handle and a single name of 1..255 bytes")
	}
	return nil
}

func validateNFS3ReplacementAttr(a Attr) error {
	if a.Type != 1 || a.Mode&^uint32(0777) != 0 || !a.HasNLink || a.NLink != 1 {
		return errors.New("requires a single-link regular file with ordinary mode bits")
	}
	if !a.HasSize || !a.HasFSID || !a.HasFileID || !a.HasMTime || !a.HasCTime {
		return errors.New("requires complete file identity, size and timestamp observations")
	}
	return nil
}

func sameNFS3ReplacementAttr(a, b Attr) bool {
	return validateNFS3ReplacementAttr(a) == nil && validateNFS3ReplacementAttr(b) == nil &&
		a.Type == b.Type && a.Mode == b.Mode && a.NLink == b.NLink && a.UID == b.UID && a.GID == b.GID &&
		a.Size == b.Size && a.FSID == b.FSID && a.FileID == b.FileID && a.MTime.Equal(b.MTime) && a.CTime.Equal(b.CTime)
}

func (m *NFS3ReplacementMetadata) checkClient(c *Client) error {
	if m == nil || c == nil || m.client != c || m.connection == nil || m.connection != c.nfs ||
		m.transport == nil || m.transport != c.nfs.conn ||
		c.Version() != m.version || c.v4 != nil || m.security != c.Security() || m.principal != c.principal ||
		m.auth.UID != c.Auth.UID || m.auth.GID != c.Auth.GID || !slices.Equal(m.auth.Groups, c.Auth.Groups) {
		return errors.New("missing snapshot or capturing client, connection or identity changed")
	}
	return nil
}

// lookupReplacement3 deliberately requires object postattrs rather than using
// general Lookup's GETATTR fallback. Every accepted observation has exactly
// LOOKUP -> GETACL -> LOOKUP framing; optional directory attrs are still parsed.
func (c *Client) lookupReplacement3(ctx context.Context, parent []byte, name string) (Node, error) {
	if c.Version() == "2" {
		return c.lookupReplacement2(ctx, parent, name)
	}
	var args encoder
	args.opaque(parent)
	args.str(name)
	d, err := c.call(ctx, 3, args)
	if err != nil {
		return Node{}, err
	}
	fh := d.opaque(64)
	a, present := postAttr(d)
	postAttr(d)
	if d.err != nil {
		return Node{}, d.err
	}
	if !validReplacementHandle3(fh) || !present || len(d.b) != 0 {
		return Node{}, errors.New("LOOKUP requires a nonempty handle, object attributes and no trailing data")
	}
	if err := validateNFS3ReplacementAttr(a); err != nil {
		return Node{}, err
	}
	return Node{Handle: bytes.Clone(fh), Attr: a}, nil
}

// CaptureNFS3Replacement brackets GETACL with same-name LOOKUP observations.
// ACL-only changes are retained even when hidden by a zero mask. This read-only
// prerequisite does not enable upload replacement or preserve xattrs/labels.
func (c *Client) CaptureNFS3Replacement(ctx context.Context, parent []byte, name string) (*NFS3ReplacementMetadata, error) {
	if c == nil || c.Version() != "3" {
		return nil, nfs3ReplacementError(errors.New("requires NFSv3"))
	}
	return c.captureLegacyReplacement(ctx, parent, name)
}

func (c *Client) captureLegacyReplacement(ctx context.Context, parent []byte, name string) (*NFS3ReplacementMetadata, error) {
	if c == nil || (c.Version() != "3" && c.Version() != "2") || c.v4 != nil || c.nfs == nil || c.nfs.conn == nil {
		return nil, nfs3ReplacementError(errors.New("requires an existing NFSv2/v3 connection"))
	}
	if err := validateReplacementPath3(parent, name); err != nil {
		return nil, nfs3ReplacementError(err)
	}
	m := &NFS3ReplacementMetadata{client: c, connection: c.nfs, transport: c.nfs.conn, auth: c.Auth,
		version: c.Version(), security: c.Security(), principal: c.principal, parent: bytes.Clone(parent), name: name}
	m.auth.Groups = slices.Clone(c.Auth.Groups)
	first, err := c.lookupReplacement3(ctx, m.parent, name)
	if err != nil {
		return nil, nfs3ReplacementError(err)
	}
	policy, err := c.getLegacyACL(ctx, first.Handle)
	if err != nil {
		return nil, nfs3ReplacementError(err)
	}
	if !sameNFS3ReplacementAttr(first.Attr, policy.Attr) {
		return nil, nfs3ReplacementError(errors.New("file metadata changed during ACL observation"))
	}
	last, err := c.lookupReplacement3(ctx, m.parent, name)
	if err != nil {
		return nil, nfs3ReplacementError(err)
	}
	if !bytes.Equal(first.Handle, last.Handle) || !sameNFS3ReplacementAttr(last.Attr, policy.Attr) {
		return nil, nfs3ReplacementError(errors.New("pathname or file metadata changed during ACL observation"))
	}
	if err := m.checkClient(c); err != nil {
		return nil, nfs3ReplacementError(err)
	}
	m.handle = bytes.Clone(first.Handle)
	m.policy = &NFS3ACL{Attr: policy.Attr, Access: slices.Clone(policy.Access), Default: slices.Clone(policy.Default)}
	return m, nil
}

// VerifyNFS3ReplacementSource rechecks the original captured name, handle,
// attributes and raw ACL using the same client/identity. NFSv3 timestamps can
// miss same-tick/ABA changes, and a later RENAME is not compare-and-swap.
func (c *Client) VerifyNFS3ReplacementSource(ctx context.Context, original *NFS3ReplacementMetadata) error {
	if err := original.checkClient(c); err != nil {
		return nfs3ReplacementError(err)
	}
	if original.policy == nil || !validReplacementHandle3(original.handle) {
		return nfs3ReplacementError(errors.New("missing captured file policy or handle"))
	}
	current, err := c.captureLegacyReplacement(ctx, original.parent, original.name)
	if err != nil {
		return err
	}
	if !bytes.Equal(current.handle, original.handle) || !sameNFS3ReplacementAttr(current.policy.Attr, original.policy.Attr) ||
		!slices.Equal(current.policy.Access, original.policy.Access) || !slices.Equal(current.policy.Default, original.policy.Default) {
		return nfs3ReplacementError(errors.New("source identity, metadata or ACL changed"))
	}
	return nil
}

// CheckNFS3ReplacementStage binds the caller's created file handle to its name
// and checks an empty, private, same-filesystem/owner/group file before payload.
// It deliberately refuses raw masked-off nonowner permissions too. It performs
// no CREATE, WRITE, SETACL, RENAME or cleanup and is not a publication check.
func (c *Client) CheckNFS3ReplacementStage(ctx context.Context, parent []byte, name string, fh []byte, original *NFS3ReplacementMetadata) error {
	if err := original.checkClient(c); err != nil {
		return nfs3ReplacementError(err)
	}
	if original.policy == nil || !validReplacementHandle3(original.handle) || !validReplacementHandle3(fh) {
		return nfs3ReplacementError(errors.New("missing source policy or valid staging handle"))
	}
	stage, err := c.CaptureNFS3Replacement(ctx, parent, name)
	if err != nil {
		return err
	}
	a, b := stage.policy.Attr, original.policy.Attr
	if !bytes.Equal(stage.handle, fh) || bytes.Equal(stage.handle, original.handle) || a.FileID == b.FileID ||
		a.FSID != b.FSID || a.UID != b.UID || a.GID != b.GID || a.Mode != 0600 || a.Size != 0 {
		return nfs3ReplacementError(errors.New("stage must be the created, distinct, empty private file with matching filesystem and ownership"))
	}
	for _, entry := range stage.policy.Access {
		if entry.Tag != ACLUserObj && entry.Perm != 0 {
			return nfs3ReplacementError(errors.New("staging ACL contains nonowner rights, including masked-off rights"))
		}
	}
	return nil
}
