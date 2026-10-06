package session

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"nfs-viewer/internal/nfs"
)

// This is a detectable-change guard, not a snapshot or a content hash.
var ErrDownloadSourceChanged = errors.New("remote file changed during download; destination not published")

func downloadSourceReady(a nfs.Attr, version string) error {
	if !a.HasSize {
		return errors.New("cannot verify download: server omitted file size")
	}
	if a.Size > math.MaxInt64 {
		return errors.New("download exceeds supported local file size")
	}
	if strings.HasPrefix(version, "4.") && !a.HasChange {
		return errors.New("cannot verify download: server omitted NFSv4 change attribute")
	}
	return nil
}

func verifyDownloadSource(before, after nfs.Attr) error {
	if after.Type != before.Type || !after.HasSize || after.Size != before.Size ||
		before.HasChange && (!after.HasChange || after.Change != before.Change) ||
		before.HasMTime && (!after.HasMTime || !after.MTime.Equal(before.MTime)) ||
		before.HasCTime && (!after.HasCTime || !after.CTime.Equal(before.CTime)) ||
		before.HasFSID && (!after.HasFSID || after.FSID != before.FSID || after.FSIDMinor != before.FSIDMinor) ||
		before.HasFileID && (!after.HasFileID || after.FileID != before.FileID) {
		return ErrDownloadSourceChanged
	}
	return nil
}

// Only call after strict verification of the completed, synced read while its
// layout was still held, followed by successful layout/OPEN cleanup. FreeBSD
// updates an MDS xattr during LAYOUTRETURN, advancing ctime independently of
// DS change/size/mtime. The read-time ctime check is never skipped. This second
// check detects content/identity changes during cleanup without attributing its
// ctime-only metadata refresh to the already verified bytes.
func verifyPNFSReturnedSource(before, after nfs.Attr) error {
	if !before.HasChange || !after.HasChange {
		return ErrDownloadSourceChanged
	}
	if before.HasCTime && after.HasCTime {
		before.CTime = after.CTime
	}
	return verifyDownloadSource(before, after)
}

// Never consume unlimited disk space when a remote file grows while reading.
// Refuse an overflowing chunk entirely; the unpublished temporary is removed.
type downloadWriter struct {
	w         io.Writer
	remaining uint64
}

func (w *downloadWriter) Write(p []byte) (int, error) {
	if uint64(len(p)) > w.remaining {
		return 0, fmt.Errorf("%w: data exceeds initial size", ErrDownloadSourceChanged)
	}
	n, err := w.w.Write(p)
	w.remaining -= uint64(n)
	return n, err
}
