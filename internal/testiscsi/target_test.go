package testiscsi

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestExpectedDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		allow, want bool
	}{
		{name: "success", want: true},
		{name: "eof", err: io.EOF, want: true},
		{name: "closed", err: net.ErrClosed, want: true},
		{name: "unexpected-reset", err: syscall.ECONNRESET},
		{name: "expected-reset", err: syscall.ECONNRESET, allow: true, want: true},
		{name: "unexpected-windows-abort", err: syscall.Errno(10053)},
		{name: "expected-windows-abort", err: syscall.Errno(10053), allow: true, want: runtime.GOOS == "windows"},
		{name: "expected-windows-reset", err: syscall.Errno(10054), allow: true, want: runtime.GOOS == "windows"},
		{name: "unexpected-windows-reset", err: syscall.Errno(10054)},
		{name: "timeout", err: os.ErrDeadlineExceeded, allow: true},
		{name: "protocol-error", err: errors.New("incorrect solicited Data-Out"), allow: true},
		{name: "not-a-socket-error", err: errors.New("wsarecv: An established connection was aborted by the software in your host machine."), allow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := expectedDisconnect(tc.err, tc.allow); got != tc.want {
				t.Fatalf("plain error: got %v, want %v", got, tc.want)
			}
			if tc.err != nil {
				wrapped := &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "socket", Err: tc.err}}
				if got := expectedDisconnect(wrapped, tc.allow); got != tc.want {
					t.Fatalf("wrapped error: got %v, want %v", got, tc.want)
				}
			}
		})
	}
}
