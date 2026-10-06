package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"nfsclient/internal/nfs"
)

var ErrResumeLockChanged = errors.New("protected download lock or session changed")

// GetResumeReclaim permits one server-restart reclaim after a failed protected
// read. It never substitutes a new lock or retries an uncertain reclaim.
func (s *Session) GetResumeReclaim(ctx context.Context, remote, local string, progress TransferProgress) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !s.Client.LockReclaimEnabled() || s.AutoUID || s.AutoEscape || s.Escaped {
		return 0, errors.New("automatic reclaim requires NFSv4 or --nlm-reclaim and a fixed identity/export")
	}
	g, err := s.captureResumeLocks()
	if err != nil {
		return 0, err
	}
	unlock, err := lockResume(local)
	if err != nil {
		return 0, err
	}
	defer unlock()
	source := resumeSource{guard: g.check}
	count, err := s.getResume(ctx, remote, local, progress, &source)
	if err == nil || ctx.Err() != nil || !source.set || !protectedReadRecoveryError(err) {
		return count, err
	}
	// Ignore only lost-state uncertainty here. Inventory, credentials and
	// namespace must still match before any recovery RPC is permitted.
	if checkErr := g.check(nil, "", false); checkErr != nil {
		return count, errors.Join(err, checkErr)
	}
	fmt.Fprintf(s.Notice, "Resume recovery: one server-restart lock reclaim: %v\n", err)
	if checkErr := g.check(nil, "", false); checkErr != nil {
		return count, errors.Join(err, checkErr)
	}
	if reclaimErr := s.Reclaim(ctx); reclaimErr != nil {
		return count, fmt.Errorf("protected download reclaim failed; no retry: %w", errors.Join(err, reclaimErr))
	}
	g.client = s.Client
	if checkErr := g.check(nil, "", true); checkErr != nil {
		return count, checkErr
	}
	count, err = s.getResume(ctx, remote, local, progress, &source)
	if err != nil {
		return count, fmt.Errorf("protected download failed after its one reclaim: %w", err)
	}
	return count, nil
}

type resumeLocks struct {
	s                           *Session
	client                      *nfs.Client
	auth                        nfs.Auth
	identity, host, export, cwd string
	root, exportRoot            []byte
	locks                       []nfs.LockInfo
	paths                       map[uint64]string
	handles                     map[uint64][]byte
}

func (s *Session) captureResumeLocks() (*resumeLocks, error) {
	g := &resumeLocks{s: s, client: s.Client, auth: s.Client.Auth, identity: s.Client.Identity(), host: s.Host, export: s.Export, cwd: s.CWD,
		root: bytes.Clone(s.Root.Handle), exportRoot: bytes.Clone(s.ExportRoot.Handle), locks: s.Client.Locks(), paths: make(map[uint64]string), handles: make(map[uint64][]byte)}
	g.auth.Groups = slices.Clone(g.auth.Groups)
	if len(g.locks) == 0 {
		return nil, errors.New("automatic reclaim requires an existing confirmed whole-file source lock")
	}
	for _, l := range g.locks {
		if l.Uncertain {
			return nil, nfs.ErrLockUncertain
		}
		fh, err := s.Client.LockedFileHandle(l.ID)
		if err != nil || s.LockPaths[l.ID] == "" {
			return nil, ErrResumeLockChanged
		}
		g.paths[l.ID], g.handles[l.ID] = s.LockPaths[l.ID], fh
	}
	return g, nil
}

func (g *resumeLocks) check(fh []byte, path string, confirmed bool) error {
	s := g.s
	if s.Client != g.client || s.AutoUID || s.AutoEscape || s.Escaped || s.Host != g.host || s.Export != g.export || s.CWD != g.cwd ||
		!bytes.Equal(s.Root.Handle, g.root) || !bytes.Equal(s.ExportRoot.Handle, g.exportRoot) || s.Client.Identity() != g.identity ||
		s.Client.Auth.UID != g.auth.UID || s.Client.Auth.GID != g.auth.GID || !slices.Equal(s.Client.Auth.Groups, g.auth.Groups) {
		return ErrResumeLockChanged
	}
	locks := s.Client.Locks()
	if len(locks) != len(g.locks) {
		return ErrResumeLockChanged
	}
	covered := fh == nil
	for i, l := range locks {
		uncertain := l.Uncertain
		l.Uncertain = false
		handle, err := s.Client.LockedFileHandle(l.ID)
		if l != g.locks[i] || err != nil || !bytes.Equal(handle, g.handles[l.ID]) || s.LockPaths[l.ID] != g.paths[l.ID] {
			return ErrResumeLockChanged
		}
		if confirmed && uncertain {
			return nfs.ErrLockUncertain
		}
		if bytes.Equal(fh, handle) && path == g.paths[l.ID] && l.Offset == 0 && l.Length == nfs.LockToEOF {
			covered = true
		}
	}
	if !covered {
		return errors.New("automatic reclaim requires the original whole-file lock on the source path")
	}
	return nil
}

// Keep ordinary unprotected retry policy unchanged. Every joined failure must
// qualify, including when the held-I/O cleanup also reports lost lock state.
func protectedReadRecoveryError(err error) bool {
	if err == nfs.ErrLockUncertain {
		return true
	}
	if e, ok := err.(interface{ Unwrap() []error }); ok {
		children := e.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !protectedReadRecoveryError(child) {
				return false
			}
		}
		return true
	}
	if readRecoveryError(err) {
		return true
	}
	// Do not unwrap local filesystem errors into recoverable network errors.
	if e, ok := err.(interface{ Unwrap() error }); ok {
		if _, local := err.(*os.PathError); local {
			return false
		}
		if _, local := err.(*os.LinkError); local {
			return false
		}
		return protectedReadRecoveryError(e.Unwrap())
	}
	return false
}
