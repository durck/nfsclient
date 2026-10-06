package session

import (
	"bytes"
	"context"
	"errors"

	"nfs-viewer/internal/nfs"
)

// TestLock checks the resolved regular file with a fixed identity. Verify the
// path again before reporting; this is an observation, not namespace isolation.
func (s *Session) TestLock(ctx context.Context, remote string, write bool, offset, length uint64) (*nfs.LockConflict, error) {
	if err := nfs.ValidateLockRange(offset, length); err != nil {
		return nil, err
	}
	auto, auth := s.AutoUID, s.Client.Auth
	s.AutoUID = false
	defer func() { s.AutoUID, s.Client.Auth = auto, auth }()
	n, name, err := s.Resolve(ctx, remote, false)
	if err != nil {
		return nil, err
	}
	if n.Attr.Type != 1 {
		return nil, errors.New("locktest requires a regular file without a final symlink")
	}
	conflict, err := s.Client.TestLock(ctx, n.Handle, write, offset, length)
	if err != nil {
		return nil, err
	}
	final, _, err := s.Resolve(ctx, name, false)
	if err != nil {
		return nil, err
	}
	if final.Attr.Type != 1 || !bytes.Equal(n.Handle, final.Handle) {
		return nil, errors.New("locktest target changed during inspection")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return conflict, nil
}

// Lock resolves a regular file without following its final symbolic link.
func (s *Session) Lock(ctx context.Context, remote string, write bool) (uint64, error) {
	return s.LockRange(ctx, remote, write, 0, nfs.LockToEOF)
}

func (s *Session) LockRange(ctx context.Context, remote string, write bool, offset, length uint64) (uint64, error) {
	if err := nfs.ValidateLockRange(offset, length); err != nil {
		return 0, err
	}
	if s.Client == nil {
		return 0, errors.New("no NFS connection")
	}
	if (s.Client.Version() == "2" || s.Client.Version() == "3") && (s.AutoUID || s.AutoEscape || s.Escaped) {
		return 0, errors.New("retained NLM locks require a fixed identity and selected export")
	}
	n, name, err := s.Resolve(ctx, remote, false)
	if err != nil {
		return 0, err
	}
	if n.Attr.Type != 1 {
		return 0, errors.New("only regular files can be locked")
	}
	id, err := s.Client.LockRangeNamed(ctx, n.Handle, name, write, offset, length)
	if id != 0 {
		if s.LockPaths == nil {
			s.LockPaths = make(map[uint64]string)
		}
		s.LockPaths[id] = name
	}
	return id, err
}
