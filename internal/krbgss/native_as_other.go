//go:build !linux

package gssapi

import (
	stdcontext "context"
	"errors"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

func nativeASPlatform() error {
	return errors.New("native AS helper is supported only on Linux")
}
func runRequiredFAST(stdcontext.Context, string, string, string, string, string) (*credentials.CCache, error) {
	return nil, nativeASPlatform()
}

func runPKINIT(stdcontext.Context, string, string, string, PKINITFiles) (*credentials.CCache, error) {
	return nil, nativeASPlatform()
}
