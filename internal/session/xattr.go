package session

import (
	"context"
	"errors"

	"nfsclient/internal/nfs"
)

func (s *Session) xattrTarget(ctx context.Context, remote string, write bool) (nfs.Node, error) {
	if s.Client.Version() != "4.2" {
		return nfs.Node{}, nfs.ErrRequiresV42
	}
	if write && (s.AutoUID || s.AutoEscape || s.Escaped) {
		return nfs.Node{}, errors.New("xattr changes require a fixed identity and export")
	}
	n, _, err := s.Resolve(ctx, remote, false)
	if err == nil && n.Attr.Type != 1 && n.Attr.Type != 2 {
		err = errors.New("xattrs require a regular file or directory; links and special files are refused")
	}
	return n, err
}

func (s *Session) GetXattr(ctx context.Context, remote, name string) ([]byte, error) {
	if err := nfs.ValidateXattrName(name); err != nil {
		return nil, err
	}
	n, err := s.xattrTarget(ctx, remote, false)
	if err != nil {
		return nil, err
	}
	return s.Client.GetXattr(ctx, n.Handle, name)
}
func (s *Session) ListXattrs(ctx context.Context, remote string) ([]string, error) {
	n, err := s.xattrTarget(ctx, remote, false)
	if err != nil {
		return nil, err
	}
	return s.Client.ListXattrs(ctx, n.Handle)
}
func (s *Session) SetXattr(ctx context.Context, remote, name string, value []byte, option uint32) error {
	if err := nfs.ValidateXattrName(name); err != nil {
		return err
	}
	if len(value) > nfs.MaxXattrValue || option > 2 {
		return errors.New("invalid xattr value length or option")
	}
	n, err := s.xattrTarget(ctx, remote, true)
	if err != nil {
		return err
	}
	return s.Client.SetXattr(ctx, n.Handle, name, value, option)
}
func (s *Session) RemoveXattr(ctx context.Context, remote, name string) error {
	if err := nfs.ValidateXattrName(name); err != nil {
		return err
	}
	n, err := s.xattrTarget(ctx, remote, true)
	if err != nil {
		return err
	}
	return s.Client.RemoveXattr(ctx, n.Handle, name)
}
