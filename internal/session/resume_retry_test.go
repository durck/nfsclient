package session

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"nfsclient/internal/nfs"
)

func TestReadRecoveryError(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"closed", nfs.ErrConnectionLost, true},
		{"truncated_record", &nfs.ConnectionLostError{Err: io.ErrUnexpectedEOF}, true},
		{"reset", reset, true},
		{"dial_refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"dial_denied", &net.OpError{Op: "dial", Err: syscall.EACCES}, false},
		{"timeout", os.ErrDeadlineExceeded, true},
		{"rpc_deadline", context.DeadlineExceeded, true},
		{"cancel", context.Canceled, false},
		{"bad_xdr", io.ErrUnexpectedEOF, false},
		{"unmarked_eof", io.EOF, false},
		{"auth", nfs.RPCDenied(1), false},
		{"permission", nfs.Status(13), false},
		{"missing", nfs.Status(2), false},
		{"grace", nfs.Status(10013), true},
		{"session_lost", nfs.Status(10052), true},
		{"sequence_bug", nfs.Status(10026), false},
		{"tls_certificate", &net.OpError{Op: "read", Err: x509.UnknownAuthorityError{}}, false},
		{"no_dns_name", &net.OpError{Op: "dial", Err: &net.DNSError{IsNotFound: true}}, false},
		{"dns_timeout", &net.OpError{Op: "dial", Err: &net.DNSError{IsTimeout: true}}, true},
		{"save_failed", errors.Join(reset, &os.PathError{Op: "sync", Err: syscall.ENOSPC}), false},
		{"prefix_changed", fmt.Errorf("%w: %w", ErrResumePrefix, reset), false},
		{"source_changed", errors.Join(reset, ErrDownloadSourceChanged), false},
		{"connect_wrapped", fmt.Errorf("connect: %w", errors.Join(reset)), true},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := readRecoveryError(tc.err); got != tc.want {
				t.Fatalf("retry=%v want=%v: %v", got, tc.want, tc.err)
			}
		})
	}
}
