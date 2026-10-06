//go:build !linux

package gssapi

import (
	stdcontext "context"
	"errors"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

func keyringPlatform() error { return errors.New("KEYRING credentials are supported only on Linux") }
func readKernelCCache(stdcontext.Context, string) (*credentials.CCache, error) {
	return nil, keyringPlatform()
}
