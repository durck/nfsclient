//go:build linux

package gssapi

import (
	stdcontext "context"
	"errors"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func kcmPlatform() error { return nil }
func dialKCM(ctx stdcontext.Context, path string) (_ net.Conn, resultErr error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSocket == 0 || before.Mode()&os.ModeSymlink != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("KCM socket must be owned by root or the current user")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			conn.Close()
		}
	}()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, credErr
	}
	if cred == nil || (cred.Uid != 0 && cred.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("KCM peer must be root or the current user")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("KCM socket changed while connecting")
	}
	return conn, nil
}
