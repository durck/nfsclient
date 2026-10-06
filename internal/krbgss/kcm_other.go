//go:build !linux

package gssapi

import (
	stdcontext "context"
	"errors"
	"net"
)

func kcmPlatform() error                                   { return errors.New("KCM socket credentials are supported only on Linux") }
func dialKCM(stdcontext.Context, string) (net.Conn, error) { return nil, kcmPlatform() }
