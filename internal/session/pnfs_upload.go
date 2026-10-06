package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"nfs-viewer/internal/nfs"
)

// PutPNFS creates a new destination with guarded CREATE, then writes through
// approved pNFS servers or block images under a temporary whole-file write lock. Like
// ordinary new-file put, a failed transfer may leave a partial destination.
// Unknown acquisitions/writes remain in LockPaths for explicit recovery.
func (s *Session) PutPNFS(ctx context.Context, local, remote string, options nfs.PNFSOptions, progress TransferProgress) (written int64, resultErr error) {
	if s.Client == nil {
		return 0, errors.New("no NFS connection")
	}
	client := s.Client
	if options.BlockResume {
		return 0, errors.New("resume an existing block destination with putrangepnfs and a fresh whole-file lock")
	}
	if s.AutoUID || s.AutoEscape || s.Escaped {
		return 0, errors.New("pNFS upload requires a fixed identity and selected export")
	}
	if len(client.Locks()) != 0 {
		return 0, nfs.ErrLocksHeld
	}
	options.Extend = true
	if err := client.ValidatePNFSWriteOptions(options); err != nil {
		return 0, err
	}
	info, err := os.Lstat(local)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("pNFS upload source must be a regular file")
	}
	f, err := os.Open(local)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !os.SameFile(info, opened) || info.Size() != opened.Size() || !info.ModTime().Equal(opened.ModTime()) {
		return 0, ErrUploadSourceChanged
	}
	var blockGuard func() error
	if options.Layout == "block" {
		blockGuard, err = s.blockSourceGuard(ctx, local, f, opened, options)
		if err != nil {
			return 0, err
		}
	}
	parent, name, resolved, err := s.namespaceParent(ctx, remote)
	if err != nil {
		return 0, err
	}
	if progress != nil {
		progress(0, uint64(opened.Size()))
	}
	if blockGuard != nil {
		if err := blockGuard(); err != nil {
			return 0, err
		}
		if len(client.Locks()) != 0 {
			return 0, nfs.ErrLocksHeld
		}
	}
	node, err := client.Create(ctx, parent.Handle, name, 0644, false)
	if err != nil {
		if errors.Is(err, nfs.Status(17)) {
			return 0, fmt.Errorf("%w: %s", ErrDestinationExists, remote)
		}
		return 0, fmt.Errorf("pNFS upload CREATE %q failed; an unacknowledged file may remain: %w", remote, err)
	}
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("pNFS upload %q incomplete; acknowledged or uncertain bytes may remain: %w", remote, resultErr)
		}
	}()
	reader := &uploadReader{f: f, before: opened, remaining: opened.Size()}
	var input io.Reader = reader
	if blockGuard != nil {
		if err := blockGuard(); err != nil {
			return 0, err
		}
		input = guardedRangeSource{reader, blockGuard}
	}
	if opened.Size() > 0 {
		id, err := client.Lock(ctx, node.Handle, true)
		if id != 0 {
			if s.LockPaths == nil {
				s.LockPaths = map[uint64]string{}
			}
			s.LockPaths[id] = resolved
		}
		if err != nil {
			return 0, err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := client.Unlock(cleanup, id); err != nil {
				resultErr = errors.Join(resultErr, err)
			} else {
				delete(s.LockPaths, id)
			}
		}()
		written, err = client.WritePNFSRangeFromProgress(ctx, node.Handle, 0, uint64(opened.Size()), input, options, func(done uint64) {
			if progress != nil {
				progress(done, uint64(opened.Size()))
			}
		})
		if err != nil {
			return written, err
		}
	}
	// A finite-range reader stops at the declared size. Trigger uploadReader's
	// EOF metadata check explicitly before declaring the new file complete.
	if n, err := reader.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		return written, errors.Join(ErrUploadSourceChanged, err)
	}
	if blockGuard != nil {
		if err := blockGuard(); err != nil {
			return written, err
		}
	}
	named, _, err := s.Resolve(ctx, resolved, false)
	if err != nil {
		return written, err
	}
	if !bytes.Equal(node.Handle, named.Handle) || named.Attr.Type != 1 || !named.Attr.HasSize || named.Attr.Size != uint64(opened.Size()) {
		return written, errors.New("pNFS upload destination identity or size changed")
	}
	return written, ctx.Err()
}
