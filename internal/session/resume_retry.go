package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"nfsclient/internal/nfs"
)

var recoveryNetworkCodes = []syscall.Errno{syscall.ECONNRESET, syscall.ECONNREFUSED, syscall.ECONNABORTED, syscall.EPIPE, syscall.ETIMEDOUT, syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTUNREACH}

// GetResumeRetry permits at most retries fresh connections after failed reads.
// Each attempt verifies source identity/metadata and the entire saved prefix.
// The budget includes failed connections and never resets after progress.
// Context bounds the total duration; individual RPCs retain their timeout.
func (s *Session) GetResumeRetry(ctx context.Context, remote, local string, retries int, progress TransferProgress) (int64, error) {
	if retries < 0 || retries > 30 {
		return 0, errors.New("resume retries must be between 0 and 30")
	}
	if retries == 0 {
		return s.GetResume(ctx, remote, local, progress)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(s.Client.Locks()) != 0 {
		return 0, nfs.ErrLocksHeld
	}
	if s.AutoUID || s.AutoEscape || s.Escaped {
		return 0, errors.New("automatic resume requires auto-uid off, auto-escape off and the selected export root")
	}
	unlock, err := lockResume(local)
	if err != nil {
		return 0, err
	}
	defer unlock()
	g := captureReadSession(s)
	source := resumeSource{guard: func(_ []byte, _ string, _ bool) error { return g.check(s) }}
	count, err := s.getResume(ctx, remote, local, progress, &source)
	delay := time.Second
	for attempt := 1; err != nil && attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		if !readRecoveryError(err) {
			return count, err
		}
		if checkErr := g.check(s); checkErr != nil {
			return count, errors.Join(err, checkErr)
		}
		fmt.Fprintf(s.Notice, "Resume recovery %d/%d in %s: %v\n", attempt, retries, delay, err)
		if checkErr := g.check(s); checkErr != nil {
			return count, errors.Join(err, checkErr)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return count, ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, 8*time.Second)
		if checkErr := g.check(s); checkErr != nil {
			return count, errors.Join(err, checkErr)
		}
		if err = s.Reconnect(ctx); err != nil {
			continue
		}
		g.client, g.host = s.Client, s.Host
		g.root, g.exportRoot = bytes.Clone(s.Root.Handle), bytes.Clone(s.ExportRoot.Handle)
		if checkErr := g.check(s); checkErr != nil {
			return count, checkErr
		}
		count, err = s.getResume(ctx, remote, local, progress, &source)
	}
	if err != nil && ctx.Err() != nil {
		return count, ctx.Err()
	}
	if err != nil && readRecoveryError(err) {
		return count, fmt.Errorf("download recovery budget exhausted (%d reconnect attempts): %w", retries, err)
	}
	return count, err
}

// Only observations made by this download may trigger a fresh session. Never
// reuse this policy for WRITE, RENAME, LOCK or another mutation. Joined errors
// must ALL be recoverable, so a failed local partial save cannot be hidden.
func readRecoveryError(err error) bool {
	if err == nil {
		return false
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		children := e.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !readRecoveryError(child) {
				return false
			}
		}
		return true
	case *os.PathError, *os.LinkError:
		return false
	case *nfs.ConnectionLostError:
		return true
	case nfs.Status:
		switch e {
		case 70, 10008, 10011, 10013, 10022, 10023, 10052, 10055, 10078:
			return true
		}
		return false
	case *net.OpError:
		if errors.Is(e, net.ErrClosed) {
			return true
		}
		var dns *net.DNSError
		if errors.As(e.Err, &dns) {
			return dns.IsTimeout || dns.IsTemporary
		}
		if e.Op != "dial" && e.Op != "read" && e.Op != "write" {
			return false
		}
		if e.Timeout() {
			return true
		}
		for _, code := range recoveryNetworkCodes {
			if errors.Is(e, code) {
				return true
			}
		}
		return false
	}
	if err == nfs.ErrConnectionLost || err == net.ErrClosed || err == os.ErrDeadlineExceeded || err == context.DeadlineExceeded {
		return true
	}
	if e, ok := err.(interface{ Unwrap() error }); ok {
		return readRecoveryError(e.Unwrap())
	}
	return false
}
