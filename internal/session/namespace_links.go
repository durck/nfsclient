package session

import (
	"context"
	"errors"
	"strings"

	"nfsclient/internal/nfs"
)

func (s *Session) namespaceEntry(ctx context.Context, name string) (nfs.Node, error) {
	// A trailing slash would cause Resolve to follow the final symlink.
	if name == "" || strings.ContainsRune(name, 0) || name != "/" && strings.HasSuffix(name, "/") {
		return nfs.Node{}, errors.New("an exact path without a trailing slash is required")
	}
	n, _, err := s.Resolve(ctx, name, false)
	return n, err
}

// Link creates an exact destination name. Intermediate symlinks are followed;
// the source itself must be a regular file, never a final symlink.
func (s *Session) Link(ctx context.Context, source, destination string) error {
	restore, err := s.namespaceIdentity()
	if err != nil {
		return err
	}
	defer restore()
	if s.Client.Version() == "2" {
		return errors.New("hardlink creation requires NFSv3 or NFSv4")
	}
	n, err := s.namespaceEntry(ctx, source)
	if err != nil {
		return err
	}
	if n.Attr.Type != 1 {
		return errors.New("hardlink source must be a regular file; final symlinks are not followed")
	}
	parent, leaf, _, err := s.namespaceParent(ctx, destination)
	if err != nil {
		return err
	}
	return s.Client.Link(ctx, n.Handle, parent.Handle, leaf)
}

// Symlink stores target verbatim, including relative or dangling targets.
func (s *Session) Symlink(ctx context.Context, target, link string) error {
	restore, err := s.namespaceIdentity()
	if err != nil {
		return err
	}
	defer restore()
	if s.Client.Version() == "2" {
		return errors.New("symbolic link creation requires NFSv3 or NFSv4")
	}
	if target == "" || len(target) > 4096 || strings.ContainsRune(target, 0) {
		return errors.New("invalid symbolic link target")
	}
	parent, leaf, _, err := s.namespaceParent(ctx, link)
	if err != nil {
		return err
	}
	return s.Client.Symlink(ctx, parent.Handle, leaf, target)
}

// Readlink returns only the final link's stored target, without resolving it.
func (s *Session) Readlink(ctx context.Context, name string) (string, error) {
	restore := s.pinNamespaceIdentity()
	defer restore()
	n, err := s.namespaceEntry(ctx, name)
	if err != nil {
		return "", err
	}
	if n.Attr.Type != 5 {
		return "", errors.New("readlink requires a symbolic link")
	}
	return s.Client.Readlink(ctx, n.Handle)
}

// Chown changes requested ownership with the currently selected RPC identity.
// Final symlinks are rejected; directory ownership may be changed explicitly.
func (s *Session) Chown(ctx context.Context, name string, owner, group *string) error {
	if err := nfs.ValidateOwnership(s.Client.Version(), owner, group); err != nil {
		return err
	}
	restore, err := s.namespaceIdentity()
	if err != nil {
		return err
	}
	defer restore()
	n, err := s.namespaceEntry(ctx, name)
	if err != nil {
		return err
	}
	if n.Attr.Type == 5 {
		return errors.New("ownership changes reject final symbolic links")
	}
	return s.Client.SetOwnership(ctx, n.Handle, owner, group)
}
