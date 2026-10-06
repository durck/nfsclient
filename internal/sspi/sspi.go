// Package sspi uses Windows Kerberos security handles without exporting keys.
package sspi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/gssapi"
)

var ErrUnsupported = errors.New("SSPI Kerberos requires Windows")

const (
	requestMutual          uint32 = 0x2
	requestConfidentiality uint32 = 0x10
	requestConnection      uint32 = 0x800
	requestIntegrity       uint32 = 0x10000
	maxToken                      = 1 << 20
	maxMessage                    = 8 << 20
)

type sizes struct{ MaxToken, MaxSignature, BlockSize, SecurityTrailer uint32 }
type stepResult struct {
	token                          []byte
	more                           bool
	flags                          uint32
	principal, server, packageName string
	expiry                         time.Time
	sizes                          sizes
}
type backend interface {
	step(string, []byte, uint32) (stepResult, error)
	sign([]byte) ([]byte, error)
	verify([]byte, []byte) error
	seal([]byte) ([]byte, error)
	unseal([]byte) ([]byte, error)
	close() error
}

// Initiator owns one credential/context pair. A cancelled native setup call
// finishes in its worker and releases its handles there: Close never deletes a
// context concurrently with an outstanding InitializeSecurityContext call.
type Initiator struct {
	mu                                 sync.Mutex
	network                            context.Context
	native                             backend
	principal, spn                     string
	started, busy, established, closed bool
	flags                              uint32
	expiry                             time.Time
	sizes                              sizes
}

func New(ctx context.Context, principal, spn string) (*Initiator, error) {
	if err := ValidateNames(principal, spn); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	native, err := newBackend(principal)
	if err != nil {
		return nil, err
	}
	return &Initiator{network: ctx, native: native, principal: principal, spn: spn}, nil
}

func ValidateNames(principal, spn string) error {
	user, realm, ok := strings.Cut(principal, "@")
	if !ok || user == "" || realm == "" || strings.ContainsAny(principal, "\x00\\") || strings.Contains(realm, "@") {
		return errors.New("SSPI requires an explicit client NAME@REALM")
	}
	if !strings.HasPrefix(spn, "nfs/") || len(spn) <= 4 || strings.ContainsAny(spn, "\x00@\\") || strings.Contains(spn[4:], "/") {
		return errors.New("SSPI requires an explicit nfs/server-hostname SPN")
	}
	return nil
}

func samePrincipal(a, b string) bool {
	au, ar, aok := strings.Cut(a, "@")
	bu, br, bok := strings.Cut(b, "@")
	return aok && bok && au == bu && strings.EqualFold(ar, br)
}

func (i *Initiator) closeLocked() error {
	i.closed = true
	i.established = false
	if i.busy || i.native == nil {
		return nil
	}
	err := i.native.close()
	i.native = nil
	return err
}

func (i *Initiator) Initiate(spn string, flags int, input []byte) ([]byte, bool, error) {
	i.mu.Lock()
	if i.closed || i.busy || i.established || spn != i.spn || flags & ^(gssapi.ContextFlagMutual|gssapi.ContextFlagInteg|gssapi.ContextFlagConf) != 0 || flags&(gssapi.ContextFlagMutual|gssapi.ContextFlagInteg) != (gssapi.ContextFlagMutual|gssapi.ContextFlagInteg) || len(input) > maxToken || i.started != (len(input) > 0) {
		i.mu.Unlock()
		return nil, false, errors.New("invalid SSPI context setup transition or profile")
	}
	if err := i.network.Err(); err != nil {
		i.closeLocked()
		i.mu.Unlock()
		return nil, false, err
	}
	wanted := requestMutual | requestIntegrity | requestConnection
	if flags&gssapi.ContextFlagConf != 0 {
		wanted |= requestConfidentiality
	}
	if i.started && wanted != i.flags {
		i.mu.Unlock()
		return nil, false, errors.New("SSPI context flags changed")
	}
	first := !i.started
	i.started = true
	i.flags = wanted
	i.busy = true
	native := i.native
	token := append([]byte(nil), input...)
	i.mu.Unlock()
	type result struct {
		token []byte
		more  bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		r, err := native.step(spn, token, wanted)
		clear(token)
		i.mu.Lock()
		i.busy = false
		if err == nil {
			err = i.network.Err()
		}
		if err == nil && i.closed {
			err = errors.New("SSPI context closed during setup")
		}
		if err == nil && (len(r.token) > maxToken || first && (!r.more || len(r.token) == 0) || !first && (r.more || len(r.token) != 0)) {
			err = errors.New("SSPI Kerberos did not complete the two-leg mutual exchange")
		}
		if err == nil && !r.more {
			server, _, _ := strings.Cut(r.server, "@")
			if r.packageName != "Kerberos" || !samePrincipal(r.principal, i.principal) || server != i.spn || r.flags&wanted != wanted || r.flags&1 != 0 || !time.Now().Before(r.expiry) || r.sizes.MaxSignature == 0 || r.sizes.MaxSignature > 400 || r.sizes.SecurityTrailer > 65536 || r.sizes.BlockSize > 65536 {
				err = errors.New("SSPI negotiated identity, service, flags, lifetime or token bounds differ from the selected profile")
			}
			if err == nil {
				i.established = true
				i.expiry = r.expiry
				i.sizes = r.sizes
			}
		}
		if err != nil {
			clear(r.token)
			i.closeLocked()
		}
		i.mu.Unlock()
		done <- result{r.token, r.more, err}
	}()
	select {
	case r := <-done:
		if err := i.network.Err(); err != nil {
			i.Close()
			clear(r.token)
			return nil, false, err
		}
		return r.token, r.more, r.err
	case <-i.network.Done():
		i.Close()
		return nil, false, i.network.Err()
	}
}

func (i *Initiator) Close() error { i.mu.Lock(); defer i.mu.Unlock(); return i.closeLocked() }
func (i *Initiator) Established() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.established && !i.closed && time.Now().Before(i.expiry)
}
func (i *Initiator) Expiry() time.Time { i.mu.Lock(); defer i.mu.Unlock(); return i.expiry }
func (i *Initiator) readyLocked(conf bool) error {
	if i.closed || !i.established || i.busy || !time.Now().Before(i.expiry) {
		return errors.New("SSPI context is unavailable or expired")
	}
	if conf && i.flags&requestConfidentiality == 0 {
		return errors.New("SSPI confidentiality was not established")
	}
	return nil
}
func (i *Initiator) CanSeal() error { i.mu.Lock(); defer i.mu.Unlock(); return i.readyLocked(true) }
func (i *Initiator) TokenSizes() (int, int, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.readyLocked(false); err != nil {
		return 0, 0, err
	}
	return int(i.sizes.MaxSignature), int(i.sizes.SecurityTrailer + i.sizes.BlockSize), nil
}
func (i *Initiator) MakeSignature(message []byte) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.readyLocked(false); err != nil {
		return nil, err
	}
	if len(message) > maxMessage {
		return nil, errors.New("SSPI message exceeds limit")
	}
	return i.native.sign(message)
}
func (i *Initiator) VerifySignature(message, signature []byte) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.readyLocked(false); err != nil {
		return err
	}
	if len(message) > maxMessage || len(signature) == 0 || len(signature) > 400 {
		return errors.New("SSPI MIC bounds invalid")
	}
	return i.native.verify(message, signature)
}
func (i *Initiator) Seal(message []byte) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.readyLocked(true); err != nil {
		return nil, err
	}
	if len(message) > maxMessage {
		return nil, errors.New("SSPI message exceeds limit")
	}
	return i.native.seal(message)
}
func (i *Initiator) Unseal(token []byte) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.readyLocked(true); err != nil {
		return nil, err
	}
	if len(token) == 0 || len(token) > maxMessage+131072 {
		return nil, errors.New("SSPI wrap bounds invalid")
	}
	return i.native.unseal(token)
}
