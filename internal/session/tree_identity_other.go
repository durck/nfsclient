//go:build !linux && !windows

package session

import (
	"errors"
	"os"
)

func treeFileID(f *os.File) (string, error) {
	return "", errors.New("hardlink preservation requires a Windows or Linux client")
}
