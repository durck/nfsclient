package session

import (
	"context"
	"errors"
	"io"
	"os"
)

// Replace is explicit opt-in to the bounded ACL-preserving replacement
// contract. Existing put collision behavior remains unchanged on legacy NFS.
func (s *Session) Replace(ctx context.Context, local, remote string, progress TransferProgress) (int64, error) {
	if s.Client.Version() != "3" && s.Client.Version() != "2" {
		return s.PutWithOptions(ctx, local, remote, TransferOptions{Overwrite: true, Progress: progress})
	}
	if s.AutoUID || s.Client.Version() == "2" && (s.AutoEscape || s.Escaped) {
		return 0, errors.New("legacy replacement requires a fixed identity and selected export")
	}
	f, err := os.Open(local)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("only regular files can be uploaded")
	}
	p, name, err := splitDestination(remote)
	if err != nil {
		return 0, err
	}
	parent, _, err := s.Resolve(ctx, p, true)
	if err != nil {
		return 0, err
	}
	if progress != nil {
		progress(0, uint64(info.Size()))
	}
	replace := s.Client.ReplaceNFS3
	if s.Client.Version() == "2" {
		replace = s.Client.ReplaceNFS2
	}
	return replace(ctx, parent.Handle, name, &uploadReader{f: f, before: info, remaining: info.Size()}, info.Size(), func(done uint64) {
		if progress != nil {
			progress(done, uint64(info.Size()))
		}
	})
}

var ErrUploadSourceChanged = errors.New("local upload source changed during transfer")

// Bound the stream to its initial size and validate observable source metadata
// at EOF, before a replacement can publish. This is not a filesystem snapshot.
type uploadReader struct {
	f         *os.File
	before    os.FileInfo
	remaining int64
}

func (r *uploadReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		after, err := r.f.Stat()
		if err != nil {
			return 0, err
		}
		if after.Size() != r.before.Size() || !after.ModTime().Equal(r.before.ModTime()) || !os.SameFile(r.before, after) {
			return 0, ErrUploadSourceChanged
		}
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.f.Read(p)
	r.remaining -= int64(n)
	if errors.Is(err, io.EOF) {
		if r.remaining != 0 {
			return n, ErrUploadSourceChanged
		}
		// Force the final metadata check on the next call.
		err = nil
	}
	return n, err
}
