//go:build !windows

package sspi

func Available() bool                    { return false }
func newBackend(string) (backend, error) { return nil, ErrUnsupported }
