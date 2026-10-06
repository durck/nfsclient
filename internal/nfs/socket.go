//go:build !windows

package nfs

import (
	"errors"
	"syscall"
)

func isAddressInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
