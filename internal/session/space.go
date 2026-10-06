package session

import (
	"context"
	"errors"
	"nfs-viewer/internal/nfs"
)

func (s *Session) spaceFile(ctx context.Context, remote string) (nfs.Node, error) {
	if s.Client.Version() != "4.2" {
		return nfs.Node{}, nfs.ErrRequiresV42
	}
	n, _, err := s.Resolve(ctx, remote, false)
	if err == nil && n.Attr.Type != 1 {
		err = errors.New("space operations require a regular file, not a symbolic link or directory")
	}
	return n, err
}

func (s *Session) Seek(ctx context.Context, remote string, offset uint64, hole bool) (nfs.SeekResult, error) {
	n, err := s.spaceFile(ctx, remote)
	if err != nil {
		return nfs.SeekResult{}, err
	}
	return s.Client.Seek(ctx, n.Handle, offset, hole)
}

func (s *Session) Allocate(ctx context.Context, remote string, offset, length uint64) error {
	if err := nfs.ValidateSpaceRange(offset, length); err != nil {
		return err
	}
	n, err := s.spaceFile(ctx, remote)
	if err != nil {
		return err
	}
	return s.Client.Allocate(ctx, n.Handle, offset, length)
}

func (s *Session) Deallocate(ctx context.Context, remote string, offset, length uint64) error {
	if err := nfs.ValidateSpaceRange(offset, length); err != nil {
		return err
	}
	n, err := s.spaceFile(ctx, remote)
	if err != nil {
		return err
	}
	return s.Client.Deallocate(ctx, n.Handle, offset, length)
}
