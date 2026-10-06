package session

import "golang.org/x/sys/windows"

// MoveFileEx without REPLACE_EXISTING supports both NTFS and FAT/exFAT.
func publishDownload(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, 0)
}
