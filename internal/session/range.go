package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"nfs-viewer/internal/nfs"
)

type transferRange struct{ offset, length uint64 }

// GetRange publishes a bounded, verified read to a new local filename.
func (s *Session) GetRange(ctx context.Context, remote, local string, offset, length uint64, progress TransferProgress) (int64, error) {
	if s.AutoUID || s.AutoEscape || s.Escaped {
		return 0, errors.New("range I/O requires a fixed identity and selected export")
	}
	return s.getWithOptions(ctx, remote, local, TransferOptions{Progress: progress, readRange: &transferRange{offset, length}}, false, nil)
}

// PutRange modifies bytes in place under a confirmed write lock. It never
// truncates, replaces, rolls back or automatically retries the destination.
func (s *Session) PutRange(ctx context.Context, local, remote string, offset uint64, progress TransferProgress) (int64, error) {
	return s.putRange(ctx, local, remote, offset, nil, progress)
}

// PutPNFSRange writes a finite range through approved data servers.
// Growth requires options.Extend; parallelism is bounded to distinct endpoints.
// The caller must already hold a whole-file write lock on the destination.
func (s *Session) PutPNFSRange(ctx context.Context, local, remote string, offset uint64, options nfs.PNFSOptions, progress TransferProgress) (int64, error) {
	return s.putRange(ctx, local, remote, offset, &options, progress)
}

func (s *Session) putRange(ctx context.Context, local, remote string, offset uint64, pnfs *nfs.PNFSOptions, progress TransferProgress) (int64, error) {
	if s.AutoUID || s.AutoEscape || s.Escaped {
		return 0, errors.New("range I/O requires a fixed identity and selected export")
	}
	var blockGuard func() error
	var source io.Reader
	info, err := os.Lstat(local)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return 0, errors.New("range upload source must be a nonempty regular file")
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
	source = f
	if pnfs != nil && (pnfs.Layout == "block" || pnfs.Layout == "object") {
		blockGuard, err = s.blockSourceGuard(ctx, local, f, opened, *pnfs)
		if err != nil {
			return 0, err
		}
		source = guardedRangeSource{f, blockGuard}
	}
	node, resolved, err := s.Resolve(ctx, remote, false)
	if err != nil {
		return 0, err
	}
	if node.Attr.Type != 1 || !node.Attr.HasSize {
		return 0, errors.New("range upload requires an existing regular file with known size")
	}
	length := uint64(opened.Size())
	if err := s.Client.RequireRangeLock(node.Handle, offset, length, true); err != nil {
		return 0, err
	}
	if progress != nil {
		progress(0, length)
	}
	if blockGuard != nil {
		if err := blockGuard(); err != nil {
			return 0, err
		}
	}
	update := func(done uint64) {
		if progress != nil {
			progress(done, length)
		}
	}
	var n int64
	if pnfs != nil {
		n, err = s.Client.WritePNFSRangeFromProgress(ctx, node.Handle, offset, length, source, *pnfs, update)
	} else {
		n, err = s.Client.WriteRangeFromProgress(ctx, node.Handle, offset, length, f, update)
	}
	if err != nil {
		return n, fmt.Errorf("range upload incomplete; acknowledged or uncertain writes may remain: %w", err)
	}
	if blockGuard != nil {
		if err := blockGuard(); err != nil {
			return n, err
		}
	}
	after, err := f.Stat()
	if err != nil {
		return n, err
	}
	if !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return n, ErrUploadSourceChanged
	}
	named, _, err := s.Resolve(ctx, resolved, false)
	if err != nil {
		return n, err
	}
	if !bytes.Equal(named.Handle, node.Handle) || !named.Attr.HasSize || named.Attr.Size != max(node.Attr.Size, offset+length) {
		return n, errors.New("range was written but destination identity or size changed")
	}
	if err := s.Client.RequireRangeLock(node.Handle, offset, length, true); err != nil {
		return n, err
	}
	return n, nil
}

type guardedRangeSource struct {
	source io.Reader
	guard  func() error
}

func (r guardedRangeSource) Read(p []byte) (int, error) {
	if err := r.guard(); err != nil {
		return 0, err
	}
	n, err := r.source.Read(p)
	return n, errors.Join(err, r.guard())
}

func (r guardedRangeSource) Check() error { return r.guard() }

func (s *Session) blockSourceGuard(ctx context.Context, local string, f *os.File, before os.FileInfo, o nfs.PNFSOptions) (func() error, error) {
	pinned := captureReadSession(s)
	if o.BlockJournal != "" {
		journal, e := os.Stat(o.BlockJournal)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		if e == nil && os.SameFile(before, journal) {
			return nil, errors.New("block journal aliases upload source")
		}
	}
	for _, path := range o.BlockVolumes {
		volume, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if os.SameFile(before, volume) {
			return nil, errors.New("block upload source aliases a volume image")
		}
	}
	guard := func() error {
		if err := errors.Join(ctx.Err(), pinned.checkProfile(s)); err != nil {
			return err
		}
		current, err := f.Stat()
		if err != nil {
			return err
		}
		named, err := os.Lstat(local)
		if err != nil {
			return err
		}
		if !named.Mode().IsRegular() || !os.SameFile(before, named) || !os.SameFile(before, current) || current.Size() != before.Size() || !current.ModTime().Equal(before.ModTime()) {
			return ErrUploadSourceChanged
		}
		return nil
	}
	return guard, guard()
}
