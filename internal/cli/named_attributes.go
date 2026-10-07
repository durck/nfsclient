package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
)

func (s *Shell) inspectNamedAttributes(ctx context.Context, remote string) error {
	attrs, err := s.Session.ListNamedAttributes(ctx, remote)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(s.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(attrs)
}

func (s *Shell) exportNamedAttribute(ctx context.Context, remote, name, local string) (resultErr error) {
	path := s.local(local)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, f.Close())
		if resultErr != nil {
			resultErr = errors.Join(resultErr, os.Remove(path))
		}
	}()
	value, err := s.Session.GetNamedAttribute(ctx, remote, name)
	if err != nil {
		return err
	}
	n, err := f.Write(value)
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return err
}
