package nfs

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsReservedPortCollision(t *testing.T) {
	for _, code := range []windows.Errno{windows.WSAEADDRINUSE, windows.WSAEACCES, windows.WSAECONNREFUSED, windows.WSAEADDRNOTAVAIL} {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "bind", Err: code}}
		if got := isAddressInUse(err); got != (code == windows.WSAEADDRINUSE) {
			t.Errorf("Winsock error %d: collision=%t", code, got)
		}
	}
}
