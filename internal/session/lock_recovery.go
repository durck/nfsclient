package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"

	"nfsclient/internal/nfs"
)

func resolveSavedLockPath(ctx context.Context, s *Session, path string) (nfs.Node, error) {
	parts, err := referralPath(path)
	if err != nil {
		return nfs.Node{}, err
	}
	n, loc, err := resolveReferral(ctx, s, parts)
	if err != nil {
		return nfs.Node{}, err
	}
	if loc != nil {
		return nfs.Node{}, errors.New("saved namespace moved again")
	}
	return n, nil
}

func (s *Session) SaveLocks(path string) error {
	if s.AutoUID || s.AutoEscape || s.Escaped || s.Export == "" || !bytes.Equal(s.Root.Handle, s.ExportRoot.Handle) || !s.ExportRoot.Attr.HasFSID || !s.ExportRoot.Attr.HasFileID || s.BaseAuth.UID != s.Client.Auth.UID || s.BaseAuth.GID != s.Client.Auth.GID || !slices.Equal(s.BaseAuth.Groups, s.Client.Auth.Groups) {
		return errors.New("save locks requires fixed confirmed export and base identity")
	}
	paths := map[uint64]string{}
	for _, l := range s.Client.Locks() {
		if s.LockPaths[l.ID] == "" {
			return errors.New("lock pathname unavailable")
		}
		paths[l.ID] = s.LockPaths[l.ID]
	}
	return s.Client.SaveLocks(path, nfs.LockNamespace{Export: s.Export, CWD: s.CWD, Root: bytes.Clone(s.ExportRoot.Handle), FSID: s.ExportRoot.Attr.FSID, FSIDMinor: s.ExportRoot.Attr.FSIDMinor, FileID: s.ExportRoot.Attr.FileID, Paths: paths})
}

// RecoverLocks restores a fixed saved namespace only after protocol state tests.
func RecoverLocks(ctx context.Context, cfg nfs.Config, path string, notice io.Writer) (*Session, error) {
	var recovered *Session
	c, err := nfs.RecoverLocks(ctx, cfg, path, func(c *nfs.Client, ns nfs.LockNamespace) error {
		s := New(c, cfg.Host, false, false, notice)
		root, err := c.Mount(ctx, ns.Export)
		if err != nil {
			return err
		}
		if root.Attr.Type != 2 || !bytes.Equal(root.Handle, ns.Root) || !root.Attr.HasFSID || !root.Attr.HasFileID || root.Attr.FSID != ns.FSID || root.Attr.FSIDMinor != ns.FSIDMinor || root.Attr.FileID != ns.FileID {
			return errors.New("saved export handle or identity changed")
		}
		s.Root, s.ExportRoot, s.Export = root, cloneRoot(root), ns.Export
		cwd, err := resolveSavedLockPath(ctx, s, ns.CWD)
		if err != nil || cwd.Attr.Type != 2 {
			return errors.New("saved working directory changed")
		}
		s.CWD = ns.CWD
		s.LockPaths = map[uint64]string{}
		for _, l := range c.Locks() {
			h, err := c.LockedFileHandle(l.ID)
			if err != nil {
				return err
			}
			n, err := resolveSavedLockPath(ctx, s, ns.Paths[l.ID])
			if err != nil || n.Attr.Type != 1 || !bytes.Equal(n.Handle, h) {
				return errors.New("saved lock path/handle changed")
			}
			s.LockPaths[l.ID] = ns.Paths[l.ID]
		}
		recovered = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	recovered.Client = c
	return recovered, nil
}
