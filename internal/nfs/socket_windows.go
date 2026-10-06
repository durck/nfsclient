package nfs

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Winsock returns WSAEADDRINUSE; syscall.EADDRINUSE is a different Windows
// errno. Only a local address collision permits trying the next reserved port.
func isAddressInUse(err error) bool { return errors.Is(err, windows.WSAEADDRINUSE) }
