package session

import (
	"context"
	"errors"
	"strings"
)

func (s *Session) ReconcileOffload(ctx context.Context, journal, id, remote string) error {
	if s.AutoUID || s.AutoEscape || s.Escaped || s.Export == "" || len(s.Client.Locks()) != 0 {
		return errors.New("offload reconciliation requires a fixed export and identity without locks")
	}
	g := captureReadSession(s)
	if err := g.check(s); err != nil {
		return err
	}
	if !strings.HasPrefix(remote, "/") {
		remote = strings.TrimSuffix(s.CWD, "/") + "/" + remote
	}
	n, err := resolveSavedLockPath(ctx, s, remote)
	if err != nil {
		return err
	}
	if n.Attr.Type != 1 {
		return errors.New("offload reconciliation target must be a regular file")
	}
	if err := g.check(s); err != nil {
		return err
	}
	if err := s.Client.ReconcileOffload(ctx, journal, id, n.Handle); err != nil {
		return err
	}
	return g.check(s)
}
