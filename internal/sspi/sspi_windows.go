package sspi

import (
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ABI mirrors sspi.h. Package selection is literal Kerberos, never Negotiate.
type secHandle struct{ lower, upper uintptr }
type secBuffer struct {
	size, kind uint32
	data       *byte
}
type secBufferDesc struct {
	version, count uint32
	buffers        *secBuffer
}
type nativeNames struct{ client, server *uint16 }
type packageInfo struct {
	capabilities   uint32
	version, rpcID uint16
	maxToken       uint32
	name, comment  *uint16
}
type lifespan struct{ start, expiry int64 }

var secur32 = windows.NewLazySystemDLL("secur32.dll")
var acquireCredentials = secur32.NewProc("AcquireCredentialsHandleW")
var initializeContext = secur32.NewProc("InitializeSecurityContextW")
var completeAuth = secur32.NewProc("CompleteAuthToken")
var queryContext = secur32.NewProc("QueryContextAttributesW")
var freeContextBuffer = secur32.NewProc("FreeContextBuffer")
var deleteContext = secur32.NewProc("DeleteSecurityContext")
var freeCredentials = secur32.NewProc("FreeCredentialsHandle")
var makeSignature = secur32.NewProc("MakeSignature")
var verifySignature = secur32.NewProc("VerifySignature")
var encryptMessage = secur32.NewProc("EncryptMessage")
var decryptMessage = secur32.NewProc("DecryptMessage")

func Available() bool                              { return true }
func newBackend(principal string) (backend, error) { return &windowsBackend{principal: principal}, nil }

type windowsBackend struct {
	call                        func(*windows.LazyProc, ...uintptr) (uintptr, uintptr, error)
	logon                       func() (string, error)
	principal                   string
	credential, context         secHandle
	haveCredential, haveContext bool
	sizes                       sizes
}

func statusError(operation string, status uintptr) error {
	if uint32(status) == 0 {
		return nil
	}
	return fmt.Errorf("SSPI %s failed (status 0x%08x)", operation, uint32(status))
}

func buffer(kind uint32, data []byte) secBuffer {
	b := secBuffer{size: uint32(len(data)), kind: kind}
	if len(data) > 0 {
		b.data = &data[0]
	}
	return b
}
func descriptor(buffers []secBuffer) secBufferDesc {
	return secBufferDesc{count: uint32(len(buffers)), buffers: &buffers[0]}
}

func (b *windowsBackend) acquire() error {
	// Resolve and acquire on one OS thread, so thread impersonation cannot change
	// the selected current logon between the identity check and handle creation.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := currentLogonPrincipal(b.logon)
	if err != nil {
		return err
	}
	if !samePrincipal(current, b.principal) {
		return errors.New("SSPI current logon differs from the explicit principal")
	}
	pkg, _ := windows.UTF16PtrFromString("Kerberos")
	var expiry int64
	status, _, _ := b.invoke(acquireCredentials, 0, uintptr(unsafe.Pointer(pkg)), 2, 0, 0, 0, 0, uintptr(unsafe.Pointer(&b.credential)), uintptr(unsafe.Pointer(&expiry)))
	if err := statusError("AcquireCredentialsHandle", status); err != nil {
		return err
	}
	b.haveCredential = true
	return nil
}

func (b *windowsBackend) step(target string, input []byte, flags uint32) (stepResult, error) {
	var out stepResult
	if !b.haveCredential {
		if err := b.acquire(); err != nil {
			return out, err
		}
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return out, err
	}
	storage := make([]byte, maxToken)
	outputs := []secBuffer{buffer(2, storage)}
	output := descriptor(outputs)
	inputs := []secBuffer{buffer(2, input)}
	in := descriptor(inputs)
	var old, ip unsafe.Pointer
	if b.haveContext {
		old = unsafe.Pointer(&b.context)
	}
	if len(input) > 0 {
		ip = unsafe.Pointer(&in)
	}
	var returned uint32
	var expiry int64
	status, _, _ := b.invoke(initializeContext, uintptr(unsafe.Pointer(&b.credential)), uintptr(old), uintptr(unsafe.Pointer(name)), uintptr(flags), 0, 0, uintptr(ip), 0, uintptr(unsafe.Pointer(&b.context)), uintptr(unsafe.Pointer(&output)), uintptr(unsafe.Pointer(&returned)), uintptr(unsafe.Pointer(&expiry)))
	runtime.KeepAlive(input)
	runtime.KeepAlive(inputs)
	runtime.KeepAlive(name)
	// A valid partially formed context belongs to us even if a later leg fails.
	if b.context.lower != 0 || b.context.upper != 0 {
		b.haveContext = true
	}
	code := uint32(status)
	if code == 0x90313 || code == 0x90314 {
		completed, _, _ := b.invoke(completeAuth, uintptr(unsafe.Pointer(&b.context)), uintptr(unsafe.Pointer(&output)))
		if err := statusError("CompleteAuthToken", completed); err != nil {
			return out, err
		}
		if code == 0x90313 {
			code = 0
		} else {
			code = 0x90312
		}
	}
	if code != 0 && code != 0x90312 {
		return out, statusError("InitializeSecurityContext", uintptr(code))
	}
	if outputs[0].kind != 2 {
		return out, errors.New("SSPI setup returned an unexpected buffer type")
	}
	out.token, err = copyOwnedBuffer(outputs[0], storage)
	clear(storage)
	if err != nil {
		return out, err
	}
	out.more = code == 0x90312
	out.flags = returned
	if out.more {
		return out, nil
	}
	if err = b.query(14, unsafe.Pointer(&out.flags)); err != nil {
		return out, err
	}
	var names nativeNames
	if err = b.query(13, unsafe.Pointer(&names)); err != nil {
		return out, err
	}
	if names.client != nil {
		out.principal = windows.UTF16PtrToString(names.client)
		b.invoke(freeContextBuffer, uintptr(unsafe.Pointer(names.client)))
	}
	if names.server != nil {
		out.server = windows.UTF16PtrToString(names.server)
		b.invoke(freeContextBuffer, uintptr(unsafe.Pointer(names.server)))
	}
	var pkg *packageInfo
	if err = b.query(10, unsafe.Pointer(&pkg)); err != nil {
		return out, err
	}
	if pkg != nil {
		out.packageName = windows.UTF16PtrToString(pkg.name)
		b.invoke(freeContextBuffer, uintptr(unsafe.Pointer(pkg)))
	}
	var life lifespan
	if err = b.query(2, unsafe.Pointer(&life)); err != nil {
		return out, err
	}
	out.expiry, err = sspiFileTime(life.expiry)
	if err != nil {
		return out, err
	}
	if err = b.query(0, unsafe.Pointer(&out.sizes)); err != nil {
		return out, err
	}
	b.sizes = out.sizes
	return out, nil
}

func sspiFileTime(ticks int64) (time.Time, error) {
	const epoch int64 = 116444736000000000
	if ticks <= epoch || ticks == int64(^uint64(0)>>1) {
		return time.Time{}, errors.New("SSPI context has no finite expiration")
	}
	ticks -= epoch
	return time.Unix(ticks/10000000, (ticks%10000000)*100).UTC(), nil
}

func (b *windowsBackend) query(attribute uint32, out unsafe.Pointer) error {
	s, _, _ := b.invoke(queryContext, uintptr(unsafe.Pointer(&b.context)), uintptr(attribute), uintptr(out))
	return statusError("QueryContextAttributes", s)
}

// Per-message calls may move a data pointer within caller-owned storage. Do
// not trust returned lengths/pointers or expose any plaintext before success.
func copyOwnedBuffer(b secBuffer, owner []byte) ([]byte, error) {
	if b.size == 0 {
		return []byte{}, nil
	}
	if len(owner) == 0 || b.data == nil {
		return nil, errors.New("SSPI returned an invalid buffer")
	}
	first := uintptr(unsafe.Pointer(&owner[0]))
	at := uintptr(unsafe.Pointer(b.data))
	if at < first || at-first > uintptr(len(owner)) || uintptr(b.size) > uintptr(len(owner))-(at-first) {
		return nil, errors.New("SSPI returned a buffer outside its allocation")
	}
	result := append([]byte(nil), owner[at-first:at-first+uintptr(b.size)]...)
	runtime.KeepAlive(owner)
	return result, nil
}

func (b *windowsBackend) sign(message []byte) ([]byte, error) {
	data := append([]byte(nil), message...)
	defer clear(data)
	token := make([]byte, b.sizes.MaxSignature)
	bufs := []secBuffer{buffer(1, data), buffer(2, token)}
	desc := descriptor(bufs)
	s, _, _ := b.invoke(makeSignature, uintptr(unsafe.Pointer(&b.context)), 0, uintptr(unsafe.Pointer(&desc)), 0)
	runtime.KeepAlive(data)
	if err := statusError("MakeSignature", s); err != nil {
		return nil, err
	}
	if bufs[1].kind != 2 {
		return nil, errors.New("SSPI MIC buffer type changed")
	}
	return copyOwnedBuffer(bufs[1], token)
}
func (b *windowsBackend) verify(message, signature []byte) error {
	data := append([]byte(nil), message...)
	defer clear(data)
	token := append([]byte(nil), signature...)
	bufs := []secBuffer{buffer(1, data), buffer(2, token)}
	desc := descriptor(bufs)
	var qop uint32
	s, _, _ := b.invoke(verifySignature, uintptr(unsafe.Pointer(&b.context)), uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&qop)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(token)
	if err := statusError("VerifySignature", s); err != nil {
		return err
	}
	if qop != 0 {
		return errors.New("SSPI MIC quality of protection changed")
	}
	return nil
}
func (b *windowsBackend) seal(message []byte) ([]byte, error) {
	data := append([]byte(nil), message...)
	defer clear(data)
	token := make([]byte, b.sizes.SecurityTrailer)
	padding := make([]byte, b.sizes.BlockSize)
	bufs := []secBuffer{buffer(2, token), buffer(1, data), buffer(9, padding)}
	desc := descriptor(bufs)
	s, _, _ := b.invoke(encryptMessage, uintptr(unsafe.Pointer(&b.context)), 0, uintptr(unsafe.Pointer(&desc)), 0)
	if err := statusError("EncryptMessage", s); err != nil {
		return nil, err
	}
	var result []byte
	for n, owner := range [][]byte{token, data, padding} {
		if bufs[n].kind != []uint32{2, 1, 9}[n] {
			return nil, errors.New("SSPI privacy buffer type changed")
		}
		part, err := copyOwnedBuffer(bufs[n], owner)
		if err != nil {
			return nil, err
		}
		result = append(result, part...)
		clear(part)
	}
	return result, nil
}
func (b *windowsBackend) unseal(token []byte) ([]byte, error) {
	stream := append([]byte(nil), token...)
	defer clear(stream)
	bufs := []secBuffer{buffer(10, stream), buffer(1, nil)}
	desc := descriptor(bufs)
	var qop uint32
	s, _, _ := b.invoke(decryptMessage, uintptr(unsafe.Pointer(&b.context)), uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&qop)))
	if err := statusError("DecryptMessage", s); err != nil {
		return nil, err
	}
	if qop != 0 || bufs[1].kind != 1 {
		return nil, errors.New("SSPI privacy was not encrypted or returned invalid data")
	}
	return copyOwnedBuffer(bufs[1], stream)
}
func (b *windowsBackend) close() error {
	var result error
	if b.haveContext {
		s, _, _ := b.invoke(deleteContext, uintptr(unsafe.Pointer(&b.context)))
		result = errors.Join(result, statusError("DeleteSecurityContext", s))
		b.haveContext = false
		b.context = secHandle{}
	}
	if b.haveCredential {
		s, _, _ := b.invoke(freeCredentials, uintptr(unsafe.Pointer(&b.credential)))
		result = errors.Join(result, statusError("FreeCredentialsHandle", s))
		b.haveCredential = false
		b.credential = secHandle{}
	}
	return result
}

//go:uintptrescapes
func (b *windowsBackend) invoke(p *windows.LazyProc, args ...uintptr) (uintptr, uintptr, error) {
	if b.call != nil {
		return b.call(p, args...)
	}
	return p.Call(args...)
}
func currentLogonPrincipal(selected func() (string, error)) (string, error) {
	if selected != nil {
		return selected()
	}
	user := make([]uint16, 32768)
	size := uint32(len(user))
	if err := windows.GetUserNameEx(windows.NameUserPrincipal, &user[0], &size); err != nil {
		return "", fmt.Errorf("SSPI current-logon principal unavailable: %w", err)
	}
	return windows.UTF16ToString(user), nil
}
