package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var ErrUploadPrefix = errors.New("remote partial upload does not match the local source prefix")

type uploadPrefixWriter struct {
	r         io.Reader
	remaining uint64
}

func (w *uploadPrefixWriter) Write(p []byte) (int, error) {
	if uint64(len(p)) > w.remaining {
		return 0, ErrUploadPrefix
	}
	buf := make([]byte, len(p))
	if _, err := io.ReadFull(w.r, buf); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUploadPrefix, err)
	}
	if !bytes.Equal(p, buf) {
		return 0, ErrUploadPrefix
	}
	w.remaining -= uint64(len(p))
	return len(p), nil
}

// PutResume verifies the entire existing remote prefix before appending bytes.
// A retained whole-file write lock is required. The file stays visible, partial
// data is not rolled back, and reconnect/reacquisition are always explicit.
func (s *Session) PutResume(ctx context.Context, local, remote string, progress TransferProgress) (int64, error) {
	if s.AutoUID || s.AutoEscape || s.Escaped {
		return 0, errors.New("upload resume requires a fixed identity and selected export")
	}
	info, err := os.Lstat(local)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("upload resume source must be a regular file, not a symbolic link")
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
	if !os.SameFile(info, opened) {
		return 0, ErrUploadSourceChanged
	}
	info = opened
	if s.Client.Version() == "2" && info.Size() > 1<<31-1 {
		return 0, errors.New("NFSv2 upload limit is 2 GiB minus one byte")
	}
	node, resolved, err := s.Resolve(ctx, remote, false)
	if err != nil {
		return 0, err
	}
	if node.Attr.Type != 1 {
		return 0, errors.New("upload resume destination must be a regular file")
	}
	if err := s.Client.RequireWriteLock(node.Handle); err != nil {
		return 0, err
	}
	if err := downloadSourceReady(node.Attr, s.Client.Version()); err != nil {
		return 0, err
	}
	if !node.Attr.HasFSID || !node.Attr.HasFileID || !strings.HasPrefix(s.Client.Version(), "4.") && (!node.Attr.HasMTime || !node.Attr.HasCTime) {
		return 0, errors.New("upload resume requires remote filesystem/file identity and legacy timestamps")
	}
	if node.Attr.Size > uint64(info.Size()) {
		return 0, ErrUploadPrefix
	}
	if progress != nil {
		progress(0, uint64(info.Size()))
	}
	w := &uploadPrefixWriter{r: f, remaining: node.Attr.Size}
	verified, err := s.Client.ReadToProgress(ctx, node.Handle, w, func(done uint64) {
		if progress != nil {
			progress(done, uint64(info.Size()))
		}
	})
	if err != nil {
		return 0, err
	}
	if uint64(verified) != node.Attr.Size || w.remaining != 0 {
		return 0, ErrUploadPrefix
	}
	after, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || !os.SameFile(info, after) {
		return 0, ErrUploadSourceChanged
	}
	named, _, err := s.Resolve(ctx, resolved, false)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(node.Handle, named.Handle) || verifyDownloadSource(node.Attr, named.Attr) != nil {
		return 0, errors.New("remote partial changed during prefix verification; append refused")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	reader := &uploadReader{f: f, before: info, remaining: info.Size() - verified}
	report := func(done uint64) {
		if progress != nil {
			progress(node.Attr.Size+done, uint64(info.Size()))
		}
	}
	var appended int64
	if strings.HasPrefix(s.Client.Version(), "4.") {
		appended, err = s.Client.AppendFromProgress(ctx, node.Handle, node.Attr.Size, node.Attr.Change, reader, report)
	} else {
		appended, err = s.Client.AppendLegacyFromProgress(ctx, node.Handle, node.Attr, reader, report)
	}
	count := verified + appended
	if err != nil {
		return count, fmt.Errorf("upload resume incomplete; remote partial remains, verify again before continuing: %w", err)
	}
	if count != info.Size() {
		return count, ErrUploadSourceChanged
	}
	final, _, err := s.Resolve(ctx, resolved, false)
	if err != nil {
		return count, fmt.Errorf("upload appended but final destination could not be verified: %w", err)
	}
	if !bytes.Equal(node.Handle, final.Handle) || !final.Attr.HasSize || final.Attr.Size != uint64(info.Size()) {
		return count, errors.New("upload appended but final destination identity or size changed")
	}
	return count, nil
}
