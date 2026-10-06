package session

import (
	"context"
	"errors"
	"path"
	"strings"

	"nfs-viewer/internal/nfs"
)

// Namespace mutations pin the current identity instead of choosing a different
// owner while resolving source and destination parents. Existing lock paths
// must remain stable until the caller explicitly unlocks them.
func (s *Session) namespaceIdentity() (func(), error) {
	if len(s.Client.Locks()) != 0 {
		return nil, nfs.ErrLocksHeld
	}
	auto, auth := s.AutoUID, s.Client.Auth
	s.AutoUID = false
	return func() { s.AutoUID, s.Client.Auth = auto, auth }, nil
}

func (s *Session) namespaceParent(ctx context.Context, name string) (nfs.Node, string, string, error) {
	dir, leaf, err := splitDestination(name)
	if err != nil {
		return nfs.Node{}, "", "", err
	}
	parent, resolved, err := s.Resolve(ctx, dir, true)
	if err != nil {
		return nfs.Node{}, "", "", err
	}
	if parent.Attr.Type != 2 {
		return nfs.Node{}, "", "", errors.New("parent is not a directory")
	}
	return parent, leaf, path.Join(resolved, leaf), nil
}

func containsNamespacePath(parent, child string) bool {
	return parent == child || strings.HasPrefix(child, parent+"/")
}

// Remove unlinks one non-directory entry, without following its final symlink.
func (s *Session) Remove(ctx context.Context, name string) error {
	return s.removeNamespace(ctx, name, false)
}

// Rmdir removes one empty directory. Recursive removal is not implicit.
func (s *Session) Rmdir(ctx context.Context, name string) error {
	return s.removeNamespace(ctx, name, true)
}

func (s *Session) removeNamespace(ctx context.Context, name string, directory bool) error {
	restore, err := s.namespaceIdentity()
	if err != nil {
		return err
	}
	defer restore()
	parent, leaf, resolved, err := s.namespaceParent(ctx, name)
	if err != nil {
		return err
	}
	node, err := s.Client.Lookup(ctx, parent.Handle, leaf)
	if err != nil {
		return err
	}
	if (node.Attr.Type == 2) != directory {
		return errors.New("rm requires a non-directory; rmdir requires a directory")
	}
	if directory && containsNamespacePath(resolved, s.CWD) {
		return errors.New("cannot remove the current directory or its ancestor")
	}
	if directory {
		return s.Client.Rmdir(ctx, parent.Handle, leaf)
	}
	return s.Client.Remove(ctx, parent.Handle, leaf)
}

// RenameReplace uses server RENAME semantics with exact destination naming.
// The destination may be replaced atomically. NFS supplies no atomic no-replace
// flag; callers authorize replacement by invoking this operation.
func (s *Session) RenameReplace(ctx context.Context, from, to string) error {
	restore, err := s.namespaceIdentity()
	if err != nil {
		return err
	}
	defer restore()
	source, oldName, oldPath, err := s.namespaceParent(ctx, from)
	if err != nil {
		return err
	}
	destination, newName, newPath, err := s.namespaceParent(ctx, to)
	if err != nil {
		return err
	}
	node, err := s.Client.Lookup(ctx, source.Handle, oldName)
	if err != nil {
		return err
	}
	if oldPath == newPath {
		return nil
	}
	if containsNamespacePath(newPath, s.CWD) || node.Attr.Type == 2 && (containsNamespacePath(oldPath, s.CWD) || containsNamespacePath(oldPath, newPath)) {
		return errors.New("cannot rename over the current directory, move its ancestor, or move a directory into itself")
	}
	return s.Client.Rename(ctx, source.Handle, oldName, destination.Handle, newName)
}
