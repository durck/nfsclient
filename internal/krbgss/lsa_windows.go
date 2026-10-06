//go:build windows

package gssapi

import (
	"bytes"
	stdcontext "context"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"golang.org/x/sys/windows"
)

const lsaRetrieveEncoded = 8
const lsaCacheOnly = 2

var lsaDLL = windows.NewLazySystemDLL("secur32.dll")
var lsaConnect = lsaDLL.NewProc("LsaConnectUntrusted")
var lsaLookup = lsaDLL.NewProc("LsaLookupAuthenticationPackage")
var lsaCall = lsaDLL.NewProc("LsaCallAuthenticationPackage")
var lsaFree = lsaDLL.NewProc("LsaFreeReturnBuffer")
var lsaClose = lsaDLL.NewProc("LsaDeregisterLogonProcess")

type nativeLSAString struct {
	length, maximum uint16
	buffer          *uint16
}
type nativeLSARequest struct {
	message, low        uint32
	high                int32
	target              nativeLSAString
	flags, cacheOptions uint32
	etype               int32
	lower, upper        uintptr
}
type nativeLSA struct {
	handle    uintptr
	packageID uint32
}

func lsaPlatform() error { return nil }
func (p *nativeLSA) close() {
	if p.handle != 0 {
		lsaClose.Call(p.handle)
		p.handle = 0
	}
}
func (p *nativeLSA) invoke(ctx stdcontext.Context, request unsafe.Pointer, size uintptr) (lsaBuffer, error) {
	if err := ctx.Err(); err != nil {
		return lsaBuffer{}, err
	}
	var result *byte
	var length, protocol uint32
	status, _, _ := lsaCall.Call(p.handle, uintptr(p.packageID), uintptr(request), size, uintptr(unsafe.Pointer(&result)), uintptr(unsafe.Pointer(&length)), uintptr(unsafe.Pointer(&protocol)))
	if result != nil {
		defer lsaFree.Call(uintptr(unsafe.Pointer(result)))
	}
	if length > maxCCacheSize {
		return lsaBuffer{}, fmt.Errorf("LSA response exceeds 4 MiB")
	}
	var allocation []byte
	if result != nil {
		allocation = unsafe.Slice(result, int(length))
		defer clear(allocation)
	}
	if uint32(status) != 0 || protocol != 0 {
		return lsaBuffer{}, fmt.Errorf("LSA cache-only request refused (status=%08x protocol=%08x); no fallback", uint32(status), protocol)
	}
	if err := ctx.Err(); err != nil {
		return lsaBuffer{}, err
	}
	if result == nil || length == 0 {
		return lsaBuffer{}, fmt.Errorf("empty LSA response")
	}
	return lsaBuffer{b: bytes.Clone(allocation), base: uintptr(unsafe.Pointer(result)), width: int(unsafe.Sizeof(uintptr(0)))}, nil
}
func (p *nativeLSA) query(ctx stdcontext.Context) (lsaBuffer, error) {
	// LogonId remains zero: no account enumeration, privilege registration or
	// access to other logon sessions. Ex (not Ex2) supports an untrusted handle.
	r := [3]uint32{lsaQueryCacheEx, 0, 0}
	return p.invoke(ctx, unsafe.Pointer(&r), unsafe.Sizeof(r))
}
func (p *nativeLSA) retrieve(ctx stdcontext.Context, target string) (lsaBuffer, error) {
	text, err := windows.UTF16FromString(target)
	if err != nil {
		return lsaBuffer{}, err
	}
	if len(text) > 2048 {
		return lsaBuffer{}, fmt.Errorf("LSA target exceeds its bound")
	}
	r := nativeLSARequest{message: lsaRetrieveEncoded, target: nativeLSAString{length: uint16(2 * (len(text) - 1)), maximum: uint16(2 * len(text)), buffer: &text[0]}, cacheOptions: lsaCacheOnly}
	b, err := p.invoke(ctx, unsafe.Pointer(&r), unsafe.Sizeof(r))
	runtime.KeepAlive(text)
	return b, err
}
func openNativeLSA() (*nativeLSA, error) {
	for _, proc := range []*windows.LazyProc{lsaConnect, lsaLookup, lsaCall, lsaFree, lsaClose} {
		if err := proc.Find(); err != nil {
			return nil, err
		}
	}
	p := new(nativeLSA)
	status, _, _ := lsaConnect.Call(uintptr(unsafe.Pointer(&p.handle)))
	if uint32(status) != 0 {
		return nil, fmt.Errorf("LSA untrusted connection refused (%08x)", uint32(status))
	}
	name := []byte("Kerberos\x00")
	// LSA_STRING uses the same native layout as UNICODE_STRING, but byte counts.
	s := struct {
		length, maximum uint16
		buffer          *byte
	}{8, 9, &name[0]}
	status, _, _ = lsaLookup.Call(p.handle, uintptr(unsafe.Pointer(&s)), uintptr(unsafe.Pointer(&p.packageID)))
	runtime.KeepAlive(name)
	if uint32(status) != 0 {
		p.close()
		return nil, fmt.Errorf("LSA Kerberos package unavailable (%08x)", uint32(status))
	}
	return p, nil
}
func readLSACCache(ctx stdcontext.Context, principal string) (*credentials.CCache, error) {
	if ctx == nil {
		ctx = stdcontext.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err == nil {
		token.Close()
		return nil, fmt.Errorf("LSA current-logon profile refuses thread impersonation")
	} else if err != windows.ERROR_NO_TOKEN {
		return nil, err
	}
	p, err := openNativeLSA()
	if err != nil {
		return nil, err
	}
	return readLSAWith(ctx, principal, p)
}
