package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"nfsclient/internal/nfs"
)

func TestLockWaitLocalRefusals(t *testing.T) {
	s := new(Session) // Local refusal must precede every RPC.
	for _, wait := range []time.Duration{0, -1, 24*time.Hour + 1} {
		if _, err := s.LockWait(context.Background(), "file", true, 0, nfs.LockToEOF, wait); err == nil {
			t.Fatal("invalid deadline accepted", wait)
		}
	}
	for _, r := range [][2]uint64{{0, 0}, {nfs.LockToEOF, 2}} {
		if _, err := s.LockWait(context.Background(), "file", true, r[0], r[1], time.Second); err == nil {
			t.Fatal("invalid range accepted", r)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.LockWait(ctx, "file", true, 0, nfs.LockToEOF, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
