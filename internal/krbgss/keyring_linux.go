//go:build linux

package gssapi

import (
	stdcontext "context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"golang.org/x/sys/unix"
)

func keyringPlatform() error { return nil }

type kernelKeyring struct{}

func (kernelKeyring) persistent(uid uint32) (int, error) {
	if uint32(os.Geteuid()) != uid {
		return 0, errors.New("persistent KEYRING UID changed")
	}
	// GET_PERSISTENT links only this UID's anchor into this process keyring.
	// It may create the anchor, but never creates a Kerberos collection/cache.
	// No user-anchor fallback: that could select different credentials.
	return unix.KeyctlInt(unix.KEYCTL_GET_PERSISTENT, int(uid), unix.KEY_SPEC_PROCESS_KEYRING, 0, 0)
}

func (kernelKeyring) anchor(name string) (int, error) {
	id := map[string]int{"session": unix.KEY_SPEC_SESSION_KEYRING, "process": unix.KEY_SPEC_PROCESS_KEYRING, "user": unix.KEY_SPEC_USER_KEYRING}[name]
	return unix.KeyctlGetKeyringID(id, false)
}
func keyringBuffer(op, id, limit int) ([]byte, error) {
	n, err := unix.KeyctlBuffer(op, id, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("KEYRING keyctl: %w", err)
	}
	if n < 0 || n > limit {
		return nil, errors.New("KEYRING key payload exceeds budget")
	}
	b := make([]byte, n)
	after, err := unix.KeyctlBuffer(op, id, b, 0)
	if err != nil || after != n {
		clear(b)
		return nil, fmt.Errorf("KEYRING key changed/unreadable: %v", err)
	}
	return b, nil
}
func (kernelKeyring) list(id, limit int) ([]int, error) {
	b, err := keyringBuffer(unix.KEYCTL_READ, id, limit*4)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	if len(b)%4 != 0 {
		return nil, errors.New("KEYRING invalid keyring membership")
	}
	ids := make([]int, len(b)/4)
	for i := range ids {
		ids[i] = int(int32(binary.NativeEndian.Uint32(b[i*4:])))
	}
	return ids, nil
}
func (kernelKeyring) describe(id int) (kernelKeyDescription, error) {
	b, err := keyringBuffer(unix.KEYCTL_DESCRIBE, id, 1024)
	if err != nil {
		return kernelKeyDescription{}, err
	}
	defer clear(b)
	if len(b) == 0 || b[len(b)-1] != 0 {
		return kernelKeyDescription{}, errors.New("KEYRING malformed key description")
	}
	p := strings.SplitN(string(b[:len(b)-1]), ";", 5)
	if len(p) != 5 {
		return kernelKeyDescription{}, errors.New("KEYRING malformed key description")
	}
	uid, err := strconv.ParseUint(p[1], 10, 32)
	if err != nil {
		return kernelKeyDescription{}, err
	}
	return kernelKeyDescription{p[0], p[4], uint32(uid)}, nil
}
func (kernelKeyring) read(id int) ([]byte, error) {
	return keyringBuffer(unix.KEYCTL_READ, id, maxCCacheSize)
}

func readKernelCCache(ctx stdcontext.Context, name string) (*credentials.CCache, error) {
	selection, err := parseKeyringName(name)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = stdcontext.Background()
	}
	ctx, cancel := stdcontext.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Keep the inherited session/process anchor stable across all syscalls.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return readKeyringSnapshot(ctx, kernelKeyring{}, selection, uint32(os.Geteuid()))
}
