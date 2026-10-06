package session

import (
	"context"
	"errors"
	"fmt"

	"nfs-viewer/internal/nfs"
)

func (s *Session) labelTarget(ctx context.Context, remote string) (nfs.Node, error) {
	if s.Client.Version() != "4.2" {
		return nfs.Node{}, nfs.ErrRequiresV42
	}
	n, _, err := s.Resolve(ctx, remote, false)
	if err == nil && n.Attr.Type != 1 && n.Attr.Type != 2 {
		err = errors.New("security labels require a regular file or directory; links and special files are refused")
	}
	return n, err
}

func (s *Session) GetSecurityLabel(ctx context.Context, remote string) (nfs.SecurityLabel, error) {
	n, err := s.labelTarget(ctx, remote)
	if err != nil {
		return nfs.SecurityLabel{}, err
	}
	return s.Client.GetSecurityLabel(ctx, n.Handle)
}

func (s *Session) SetSecurityLabel(ctx context.Context, remote string, label nfs.SecurityLabel) error {
	if len(label.Data) > nfs.MaxSecurityLabel {
		return fmt.Errorf("security label exceeds %d bytes", nfs.MaxSecurityLabel)
	}
	if s.AutoUID || s.AutoEscape || s.Escaped {
		return errors.New("label changes require a fixed identity and export")
	}
	n, err := s.labelTarget(ctx, remote)
	if err != nil {
		return err
	}
	return s.Client.SetSecurityLabel(ctx, n.Handle, label)
}
