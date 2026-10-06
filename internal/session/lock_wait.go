package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"nfs-viewer/internal/nfs"
)

// LockWait polls only fully acknowledged DENIED results whose OPEN/owner
// cleanup succeeded. It never retries uncertain acquisitions or cleanup errors.
// The resolved file handle remains pinned across attempts.
func (s *Session) LockWait(ctx context.Context, remote string, write bool, offset, length uint64, wait time.Duration) (uint64, error) {
	return s.lockWait(ctx, remote, write, offset, length, wait, false)
}

// LockNativeWait waits for an NLM server grant without polling LOCK requests.
func (s *Session) LockNativeWait(ctx context.Context, remote string, write bool, offset, length uint64, wait time.Duration) (uint64, error) {
	return s.lockWait(ctx, remote, write, offset, length, wait, true)
}

func (s *Session) lockWait(ctx context.Context, remote string, write bool, offset, length uint64, wait time.Duration, native bool) (uint64, error) {
	if wait <= 0 || wait > 24*time.Hour {
		return 0, errors.New("lock wait must be positive and at most 24h")
	}
	if err := nfs.ValidateLockRange(offset, length); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.Client == nil {
		return 0, errors.New("no NFS connection")
	}
	if native && s.Client.Version() != "2" && s.Client.Version() != "3" {
		return 0, errors.New("native NLM wait requires NFSv2/v3")
	}
	if (s.Client.Version() == "2" || s.Client.Version() == "3") && (s.AutoUID || s.AutoEscape || s.Escaped) {
		return 0, errors.New("retained NLM locks require a fixed identity and selected export")
	}
	initial, resolved, err := s.Resolve(ctx, remote, false)
	if err != nil {
		return 0, err
	}
	if initial.Attr.Type != 1 {
		return 0, errors.New("only regular files can be locked")
	}
	delay := 100 * time.Millisecond
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		current, _, err := s.Resolve(ctx, resolved, false)
		if err != nil {
			return 0, err
		}
		if !bytes.Equal(initial.Handle, current.Handle) {
			return 0, errors.New("lock target changed while waiting")
		}
		var id uint64
		if native {
			id, err = s.Client.LockRangeNativeWait(ctx, initial.Handle, write, offset, length, wait)
		} else {
			id, err = s.Client.LockRange(ctx, initial.Handle, write, offset, length)
		}
		if id != 0 {
			if s.LockPaths == nil {
				s.LockPaths = make(map[uint64]string)
			}
			s.LockPaths[id] = resolved
		}
		if err == nil {
			verifyErr := ctx.Err()
			if verifyErr == nil {
				current, _, verifyErr = s.Resolve(ctx, resolved, false)
			}
			if verifyErr == nil {
				verifyErr = ctx.Err()
			}
			if verifyErr == nil && bytes.Equal(initial.Handle, current.Handle) {
				return id, nil
			}
			if verifyErr == nil {
				verifyErr = errors.New("lock target changed during acquisition")
			}
			cleanup, cancelCleanup := context.WithTimeout(context.Background(), time.Second)
			unlockErr := s.Client.Unlock(cleanup, id)
			cancelCleanup()
			if unlockErr == nil {
				delete(s.LockPaths, id)
				return 0, verifyErr
			}
			return id, errors.Join(verifyErr, fmt.Errorf("lock %d cleanup failed; inspect locks before continuing: %w", id, unlockErr))
		}
		// A joined DENIED + cleanup error is deliberately not retryable.
		if native || id != 0 || err != nfs.Status(10010) && err != nfs.NLMStatus(1) {
			return id, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
		delay = min(2*delay, time.Second)
	}
}
