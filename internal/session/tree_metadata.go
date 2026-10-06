package session

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"nfs-viewer/internal/nfs"
)

func (o TreeOptions) validate() error {
	if o.Mode && runtime.GOOS == "windows" {
		return errors.New("POSIX mode preservation requires a Unix client; Windows ACLs are not POSIX modes")
	}
	return nil
}

func (o TreeOptions) localMetadata(root *os.Root, name string, a nfs.Attr) error {
	if o.MTime {
		if !a.HasMTime {
			return errors.New("server omitted mtime")
		}
		if err := root.Chtimes(name, time.Time{}, a.MTime); err != nil {
			return err
		}
		info, err := root.Stat(name)
		if err != nil {
			return err
		}
		if !info.ModTime().Equal(a.MTime) {
			return errors.New("local filesystem did not preserve mtime exactly")
		}
	}
	if o.Mode {
		if err := root.Chmod(name, os.FileMode(a.Mode&0777)); err != nil {
			return err
		}
		info, err := root.Stat(name)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != os.FileMode(a.Mode&0777) {
			return errors.New("local filesystem did not preserve POSIX permissions")
		}
	}
	return nil
}

func (s *Session) remoteTreeMetadata(ctx context.Context, node nfs.Node, info os.FileInfo, o TreeOptions) error {
	if !o.Mode && !o.MTime {
		return nil
	}
	s.identity(node)
	if o.MTime {
		if err := s.Client.SetMTime(ctx, node.Handle, info.ModTime()); err != nil {
			return err
		}
	}
	if o.Mode {
		if err := s.Client.Chmod(ctx, node.Handle, uint32(info.Mode().Perm())); err != nil {
			return err
		}
		a, err := s.Client.GetAttr(ctx, node.Handle)
		if err != nil {
			return err
		}
		if a.Mode&0777 != uint32(info.Mode().Perm()) {
			return errors.New("server did not preserve POSIX permissions")
		}
	}
	return nil
}
