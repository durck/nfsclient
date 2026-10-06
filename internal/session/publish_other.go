//go:build !linux && !windows

package session

import "os"

func publishDownload(source, destination string) error {
	return os.Link(source, destination)
}
