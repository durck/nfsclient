//go:build !unix && !windows

package nfs

import (
	"errors"
	"os"
)

func lockNSMFile(*os.File) error {
	return errors.New("durable NSM state locking is unsupported on this platform")
}
