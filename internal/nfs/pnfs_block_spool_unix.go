//go:build !windows

package nfs

import "os"

func newBlockSpool() (*os.File, error) {
	f, err := os.CreateTemp("", "nfs-block-source-*")
	if err != nil {
		return nil, err
	}
	if err = os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
