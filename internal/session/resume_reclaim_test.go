package session

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"nfs-viewer/internal/nfs"
)

func TestProtectedReadRecoveryError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nfs.ErrLockUncertain, true},
		{errors.Join(nfs.ErrConnectionLost, nfs.ErrLockUncertain), true},
		{fmt.Errorf("saved partial: %w", errors.Join(nfs.Status(10052), nfs.ErrLockUncertain)), true},
		{errors.Join(nfs.ErrLockUncertain, ErrResumeLockChanged), false},
		{errors.Join(nfs.ErrLockUncertain, ErrResumePrefix), false},
		{errors.Join(nfs.ErrLockUncertain, ErrDownloadSourceChanged), false},
		{&os.PathError{Op: "sync", Err: nfs.ErrLockUncertain}, false},
		{&os.LinkError{Op: "rename", Err: nfs.ErrConnectionLost}, false},
		{nil, false},
	} {
		if got := protectedReadRecoveryError(tc.err); got != tc.want {
			t.Fatalf("%v: %v, want %v", tc.err, got, tc.want)
		}
	}
	if readRecoveryError(nfs.ErrLockUncertain) {
		t.Fatal("unprotected policy accepts locks")
	}
}
