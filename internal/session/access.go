package session

import (
	"context"
	"nfsclient/internal/nfs"
)

// AccessPath observes server permissions under the current identity, even when
// automatic owner selection is enabled for other interactive operations.
func (s *Session) AccessPath(ctx context.Context, name string) (nfs.Node, string, nfs.AccessReport, error) {
	auto, auth := s.AutoUID, s.Client.Auth
	s.AutoUID = false
	defer func() { s.AutoUID, s.Client.Auth = auto, auth }()
	n, resolved, err := s.Resolve(ctx, name, false)
	if err != nil {
		return n, resolved, nfs.AccessReport{Identity: s.Client.Identity(), Error: err.Error()}, err
	}
	r, err := s.Client.CheckAccess(ctx, n.Handle, 63)
	return n, resolved, r, err
}
