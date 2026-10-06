package session

import (
	"context"
	"nfs-viewer/internal/nfs"
)

func (s *Session) Advise(ctx context.Context, remote string, offset, length uint64, hints uint32) (nfs.AdviceResult, error) {
	if err := nfs.ValidateAdvice(offset, length, hints); err != nil {
		return nfs.AdviceResult{}, err
	}
	n, err := s.spaceFile(ctx, remote)
	if err != nil {
		return nfs.AdviceResult{}, err
	}
	return s.Client.Advise(ctx, n.Handle, offset, length, hints)
}
