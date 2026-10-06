package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"nfsclient/internal/nfs"
)

var ErrResumePrefix = errors.New("partial download does not match the current remote file")

// resumeWriter verifies every retained byte before accepting the remote suffix.
// Partial data is always read-only; fresh data goes into a private temporary.
type resumeWriter struct {
	previous  io.Reader
	remaining int64
	w         io.Writer
}

func (w *resumeWriter) Write(p []byte) (int, error) {
	check := min(int64(len(p)), w.remaining)
	if check > 0 {
		b := make([]byte, int(check))
		if _, err := io.ReadFull(w.previous, b); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrResumePrefix, err)
		}
		if !bytes.Equal(b, p[:check]) {
			return 0, ErrResumePrefix
		}
		w.remaining -= check
	}
	return w.w.Write(p)
}

// GetResume retains LOCAL.nfs-part on interrupted downloads. Each invocation
// rereads and compares the complete prefix, so this saves progress across
// restarts but does not save prefix network traffic. Neither timestamps nor a
// saved file handle can prove that a prefix still matches a remote file.
// Like Get, use a trusted local destination directory; concurrent outside
// namespace mutation is not supported. Existing final destinations are refused.
func (s *Session) GetResume(ctx context.Context, remote, local string, progress TransferProgress) (count int64, resultErr error) {
	unlock, err := lockResume(local)
	if err != nil {
		return 0, err
	}
	defer unlock()
	return s.getResume(ctx, remote, local, progress, nil)
}

func lockResume(local string) (func(), error) {
	if _, err := os.Lstat(local); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrDestinationExists, local)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	part := local + ".nfs-part"
	lock, err := os.OpenFile(part+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("acquire resume lock (after a crash, remove only when no transfer is running): %w", err)
	}
	if err := lock.Close(); err != nil {
		os.Remove(lock.Name())
		return nil, err
	}
	return func() { os.Remove(lock.Name()) }, nil
}

type resumeSource struct {
	attr  nfs.Attr
	path  string
	set   bool
	guard func([]byte, string, bool) error
}

// The caller owns the destination lock, including between recovery attempts.
func (s *Session) getResume(ctx context.Context, remote, local string, progress TransferProgress, expected *resumeSource) (count int64, resultErr error) {
	part := local + ".nfs-part"
	var previous *os.File
	var size int64
	if info, err := os.Lstat(part); err == nil {
		if !info.Mode().IsRegular() {
			return 0, errors.New("resume partial must be a regular file, not a link")
		}
		previous, err = os.Open(part)
		if err != nil {
			return 0, err
		}
		defer previous.Close()
		opened, err := previous.Stat()
		if err != nil {
			return 0, err
		}
		if !os.SameFile(info, opened) {
			return 0, errors.New("resume partial changed identity")
		}
		size = opened.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	node, resolved, err := s.Resolve(ctx, remote, true)
	if err != nil {
		return 0, err
	}
	if node.Attr.Type != 1 {
		return 0, errors.New("only regular files can be downloaded")
	}
	if err := downloadSourceReady(node.Attr, s.Client.Version()); err != nil {
		return 0, err
	}
	if expected != nil {
		if expected.guard != nil {
			if err := expected.guard(node.Handle, resolved, true); err != nil {
				return 0, err
			}
		}
		if !node.Attr.HasFSID || !node.Attr.HasFileID {
			return 0, errors.New("automatic resume requires filesystem and file identity attributes")
		}
		if expected.set {
			if expected.path != resolved {
				return 0, ErrDownloadSourceChanged
			}
			if err := verifyDownloadSource(expected.attr, node.Attr); err != nil {
				return 0, err
			}
		} else {
			expected.attr, expected.path, expected.set = node.Attr, resolved, true
		}
	}
	if uint64(size) > node.Attr.Size {
		return 0, ErrResumePrefix
	}
	f, err := os.CreateTemp(filepath.Dir(local), ".nfs-resume-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	w := &resumeWriter{previous: previous, remaining: size, w: f}
	if progress != nil {
		progress(0, node.Attr.Size)
	}
	checkGuard := func(confirmed bool) error {
		if expected != nil && expected.guard != nil {
			return expected.guard(node.Handle, resolved, confirmed)
		}
		return nil
	}
	if err := checkGuard(true); err != nil {
		return 0, err
	}
	readCtx, cancelRead := context.WithCancel(ctx)
	defer cancelRead()
	var guardErr error
	count, err = s.Client.ReadToProgress(readCtx, node.Handle, &downloadWriter{w: w, remaining: node.Attr.Size}, func(done uint64) {
		if progress != nil {
			progress(done, node.Attr.Size)
		}
		if guardErr = checkGuard(false); guardErr != nil {
			cancelRead()
		}
	})
	err = errors.Join(err, guardErr)
	// Always flush the accepted prefix. Never replace an older, longer partial
	// or a mismatching prefix. No RPC is repeated after a failed operation.
	if err != nil {
		if count > size && w.remaining == 0 && !errors.Is(err, ErrResumePrefix) && !errors.Is(err, ErrDownloadSourceChanged) {
			if previous != nil {
				previous.Close()
			}
			if saveErr := f.Sync(); saveErr != nil {
				return count, errors.Join(err, saveErr)
			}
			if saveErr := f.Close(); saveErr != nil {
				return count, errors.Join(err, saveErr)
			}
			if saveErr := os.Rename(f.Name(), part); saveErr != nil {
				return count, errors.Join(err, saveErr)
			}
			return count, fmt.Errorf("partial download saved as %q; reconnect and repeat reget: %w", part, err)
		}
		return count, err
	}
	if uint64(count) != node.Attr.Size || w.remaining != 0 {
		return count, ErrDownloadSourceChanged
	}
	after, err := s.Client.GetAttr(ctx, node.Handle)
	if err != nil {
		return count, err
	}
	if err := verifyDownloadSource(node.Attr, after); err != nil {
		return count, err
	}
	named, _, err := s.Resolve(ctx, resolved, true)
	if err != nil {
		return count, err
	}
	if !bytes.Equal(node.Handle, named.Handle) {
		return count, ErrDownloadSourceChanged
	}
	if err := verifyDownloadSource(node.Attr, named.Attr); err != nil {
		return count, err
	}
	if err := f.Sync(); err != nil {
		return count, err
	}
	if err := f.Close(); err != nil {
		return count, err
	}
	if err := ctx.Err(); err != nil {
		return count, err
	}
	if err := checkGuard(true); err != nil {
		return count, err
	}
	if err := publishDownload(f.Name(), local); err != nil {
		if errors.Is(err, os.ErrExist) {
			return count, fmt.Errorf("%w: %s", ErrDestinationExists, local)
		}
		return count, err
	}
	if previous != nil {
		previous.Close()
		if err := os.Remove(part); err != nil {
			return count, fmt.Errorf("download published, but partial cleanup failed: %w", err)
		}
	}
	return count, nil
}
