package session

import (
	"bytes"
	"context"
	"errors"

	"nfsclient/internal/nfs"
)

func (s *Session) inspectNamedAttributes(ctx context.Context, remote string, inspect func([]byte) error) error {
	if s.Client == nil {
		return errors.New("no NFS connection")
	}
	// Use a copy so inspection cannot persist changed session identity/options.
	fixed := *s
	fixed.AutoUID, fixed.AutoUIDScan, fixed.AutoEscape = false, false, false
	n, path, err := fixed.Resolve(ctx, remote, false)
	if err != nil {
		return err
	}
	if n.Attr.Type != 1 && n.Attr.Type != 2 {
		return errors.New("named attributes require a regular file or directory; final symlinks are not followed")
	}
	if err := inspect(n.Handle); err != nil {
		return err
	}
	after, _, err := fixed.Resolve(ctx, path, false)
	if err != nil {
		return err
	}
	if n.Attr.Type != after.Attr.Type || !bytes.Equal(n.Handle, after.Handle) {
		return errors.New("named attribute target changed during inspection")
	}
	return ctx.Err()
}

func (s *Session) ListNamedAttributes(ctx context.Context, remote string) ([]nfs.NamedAttribute, error) {
	var result []nfs.NamedAttribute
	err := s.inspectNamedAttributes(ctx, remote, func(fh []byte) (err error) {
		result, err = s.Client.ListNamedAttributes(ctx, fh)
		return
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Session) GetNamedAttribute(ctx context.Context, remote, name string) ([]byte, error) {
	if err := nfs.ValidateNamedAttributeName(name); err != nil {
		return nil, err
	}
	var result []byte
	err := s.inspectNamedAttributes(ctx, remote, func(fh []byte) (err error) {
		result, err = s.Client.GetNamedAttribute(ctx, fh, name)
		return
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
