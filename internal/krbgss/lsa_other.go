//go:build !windows

package gssapi

import (
	stdcontext "context"
	"errors"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

func lsaPlatform() error {
	return errors.New("explicit MSLSA current-logon credentials are supported only on Windows")
}
func readLSACCache(stdcontext.Context, string) (*credentials.CCache, error) {
	return nil, lsaPlatform()
}
