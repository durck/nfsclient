package session

import "golang.org/x/sys/windows"

func init() {
	// Go's portable syscall.ECONN* values are not Winsock's WSAECONN*.
	recoveryNetworkCodes = append(recoveryNetworkCodes, windows.WSAECONNRESET,
		windows.WSAECONNREFUSED, windows.WSAECONNABORTED, windows.WSAETIMEDOUT,
		windows.WSAENETDOWN, windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH)
}
