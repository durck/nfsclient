package session

import "golang.org/x/sys/unix"

// Renameat2 publishes atomically without requiring hard-link support. Fail
// explicitly on old kernels/filesystems lacking this guarantee.
func publishDownload(source, destination string) error {
	return unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE)
}
