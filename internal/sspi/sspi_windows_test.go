package sspi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSSPIWindowsABIAndBufferBounds(t *testing.T) {
	if unsafe.Sizeof(secHandle{}) != 2*unsafe.Sizeof(uintptr(0)) || unsafe.Offsetof(secBuffer{}.data) != 8 || unsafe.Sizeof(sizes{}) != 16 || unsafe.Sizeof(lifespan{}) != 16 {
		t.Fatal("sspi.h ABI mismatch")
	}
	data := []byte("native-buffer")
	b := buffer(1, data)
	b.data = &data[3]
	b.size = 4
	got, err := copyOwnedBuffer(b, data)
	if err != nil || string(got) != "ive-" {
		t.Fatal(got, err)
	}
	b.size = 100
	if _, err = copyOwnedBuffer(b, data); err == nil {
		t.Fatal("native out-of-bounds buffer accepted")
	}
}

type nativeOracle struct {
	t                             *testing.T
	legs, deleted, freed, buffers int
	names                         nativeNames
	pkg                           packageInfo
	strings                       [][]uint16
	badQOP                        bool
}

func (o *nativeOracle) wide(s string) *uint16 {
	b, _ := windows.UTF16FromString(s)
	o.strings = append(o.strings, b)
	return &b[0]
}
func nativeMAC(b []byte) []byte {
	h := hmac.New(sha256.New, []byte("independent-native-API-test-key"))
	h.Write(b)
	return h.Sum(nil)
}

// All arguments originate from invoke's pinned, live Go allocations. Reinterpret
// the ABI word as a pointer without pointer arithmetic; no wire bytes reach it.
func oracleAddress(word uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&word)) }

// The oracle emulates the documented sspi.h ABI at the actual native-call
// boundary. uintptr values represent FFI addresses, as in a Windows DLL call.
//
//go:nocheckptr
func (o *nativeOracle) call(p *windows.LazyProc, a ...uintptr) (uintptr, uintptr, error) {
	o.t.Helper()
	runtime.GC() // Also exercise pinning across native-call setup.
	success := func() (uintptr, uintptr, error) { return 0, 0, nil }
	fail := func(text string) (uintptr, uintptr, error) { o.t.Error(text); return 0x80090308, 0, nil }
	desc := func(at uintptr) []secBuffer {
		d := (*secBufferDesc)(oracleAddress(at))
		if d.version != 0 || d.count > 4 {
			o.t.Fatal("descriptor ABI changed")
		}
		return unsafe.Slice(d.buffers, d.count)
	}
	data := func(b secBuffer) []byte {
		if b.size == 0 {
			return nil
		}
		return unsafe.Slice(b.data, b.size)
	}
	switch p.Name {
	case "AcquireCredentialsHandleW":
		if a[0] != 0 || windows.UTF16PtrToString((*uint16)(oracleAddress(a[1]))) != "Kerberos" || a[2] != 2 || a[3] != 0 || a[4] != 0 || a[5] != 0 || a[6] != 0 {
			return fail("credential acquisition selected other logon, package or auth data")
		}
		*(*secHandle)(oracleAddress(a[7])) = secHandle{11, 12}
		return success()
	case "InitializeSecurityContextW":
		if windows.UTF16PtrToString((*uint16)(oracleAddress(a[2]))) != "nfs/server.test" || uint32(a[3]) != requestMutual|requestIntegrity|requestConnection|requestConfidentiality || a[4] != 0 || a[5] != 0 || a[7] != 0 {
			return fail("context target/flags/ABI changed")
		}
		out := desc(a[9])
		if len(out) != 1 || out[0].kind != 2 || out[0].size < 100 {
			return fail("setup output bounds changed")
		}
		*(*secHandle)(oracleAddress(a[8])) = secHandle{21, 22}
		*(*uint32)(oracleAddress(a[10])) = uint32(a[3])
		o.legs++
		if o.legs == 1 {
			if a[1] != 0 || a[6] != 0 {
				return fail("first context used input/old handle")
			}
			copy(data(out[0]), "ap-request")
			out[0].size = 10
			return 0x90312, 0, nil
		}
		if a[1] == 0 || a[6] == 0 {
			return fail("second context lost old handle/input")
		}
		in := desc(a[6])
		if len(in) != 1 || in[0].kind != 2 || string(data(in[0])) != "ap-reply" {
			return fail("server token changed")
		}
		out[0].size = 0
		return success()
	case "QueryContextAttributesW":
		switch a[1] {
		case 0:
			*(*sizes)(oracleAddress(a[2])) = sizes{MaxToken: 65536, MaxSignature: 32, BlockSize: 16, SecurityTrailer: 32}
		case 2:
			*(*lifespan)(oracleAddress(a[2])) = lifespan{expiry: time.Now().Add(time.Hour).Unix()*10000000 + 116444736000000000}
		case 10:
			o.pkg.name = o.wide("Kerberos")
			*(**packageInfo)(oracleAddress(a[2])) = &o.pkg
		case 13:
			o.names = nativeNames{o.wide("user@EXAMPLE.TEST"), o.wide("nfs/server.test@EXAMPLE.TEST")}
			*(*nativeNames)(oracleAddress(a[2])) = o.names
		case 14:
			*(*uint32)(oracleAddress(a[2])) = requestMutual | requestIntegrity | requestConnection | requestConfidentiality
		default:
			return fail("unexpected native query, possibly key export")
		}
		return success()
	case "FreeContextBuffer":
		o.buffers++
		return success()
	case "MakeSignature":
		if a[1] != 0 || a[3] != 0 {
			return fail("MIC QoP/sequence changed")
		}
		v := desc(a[2])
		if len(v) != 2 || v[0].kind != 1 || v[1].kind != 2 {
			return fail("MIC buffer ABI changed")
		}
		mic := nativeMAC(data(v[0]))
		copy(data(v[1]), mic)
		v[1].size = uint32(len(mic))
		return success()
	case "VerifySignature":
		if a[2] != 0 {
			return fail("MIC receive sequence changed")
		}
		v := desc(a[1])
		if len(v) != 2 || v[0].kind != 1 || v[1].kind != 2 {
			return fail("MIC verify buffer ABI changed")
		}
		if !hmac.Equal(data(v[1]), nativeMAC(data(v[0]))) {
			return 0x8009030f, 0, nil
		}
		*(*uint32)(oracleAddress(a[3])) = 0
		return success()
	case "EncryptMessage":
		if a[1] != 0 || a[3] != 0 {
			return fail("privacy disabled or sequence changed")
		}
		v := desc(a[2])
		if len(v) != 3 || v[0].kind != 2 || v[1].kind != 1 || v[2].kind != 9 {
			return fail("GSS wrap buffer order changed")
		}
		copy(data(v[0]), "HEADER")
		v[0].size = 6
		for n := range data(v[1]) {
			data(v[1])[n] ^= 0x5a
		}
		copy(data(v[2]), "PAD")
		v[2].size = 3
		return success()
	case "DecryptMessage":
		if a[2] != 0 {
			return fail("privacy receive sequence changed")
		}
		v := desc(a[1])
		if len(v) != 2 || v[0].kind != 10 || v[1].kind != 1 || v[1].size != 0 || v[1].data != nil {
			return fail("GSS unwrap stream/data ABI changed")
		}
		stream := data(v[0])
		if !bytes.HasPrefix(stream, []byte("HEADER")) || !bytes.HasSuffix(stream, []byte("PAD")) {
			return 0x8009030f, 0, nil
		}
		plain := stream[6 : len(stream)-3]
		for n := range plain {
			plain[n] ^= 0x5a
		}
		v[1] = buffer(1, plain)
		if o.badQOP {
			*(*uint32)(oracleAddress(a[3])) = 0x80000001
		} else {
			*(*uint32)(oracleAddress(a[3])) = 0
		}
		return success()
	case "DeleteSecurityContext":
		o.deleted++
		return success()
	case "FreeCredentialsHandle":
		o.freed++
		return success()
	default:
		return fail("unexpected native API call")
	}
}

func TestSSPIWindowsNativeMessageABI(t *testing.T) {
	o := &nativeOracle{t: t}
	native := &windowsBackend{principal: "user@EXAMPLE.TEST", call: o.call, logon: func() (string, error) { return "user@example.test", nil }}
	i := &Initiator{network: context.Background(), native: native, principal: "user@EXAMPLE.TEST", spn: "nfs/server.test"}
	establishTest(t, i)
	plain := []byte("protected RPC body")
	saved := bytes.Clone(plain)
	mic, err := i.MakeSignature(plain)
	if err != nil || !bytes.Equal(mic, nativeMAC(plain)) {
		t.Fatal(mic, err)
	}
	if err = i.VerifySignature(plain, mic); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(mic)
	bad[0] ^= 1
	if err = i.VerifySignature(plain, bad); err == nil {
		t.Fatal("bad MIC accepted")
	}
	token, err := i.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("HEADER"), plain...)
	for n := 6; n < len(want); n++ {
		want[n] ^= 0x5a
	}
	want = append(want, []byte("PAD")...)
	if !bytes.Equal(token, want) || !bytes.Equal(plain, saved) {
		t.Fatal("wrap framing changed or caller data mutated")
	}
	got, err := i.Unseal(token)
	if err != nil || !bytes.Equal(got, plain) || !bytes.Equal(token, want) {
		t.Fatal("unwrap framing changed", err)
	}
	o.badQOP = true
	if got, err = i.Unseal(token); err == nil || got != nil {
		t.Fatal("signed-only data exposed as privacy")
	}
	if err = i.Close(); err != nil {
		t.Fatal(err)
	}
	i.Close()
	if o.deleted != 1 || o.freed != 1 || o.buffers != 3 {
		t.Fatal("native ownership mismatch", o.deleted, o.freed, o.buffers)
	}
}

func TestSSPIWindowsLocalLogonCheckPrecedesAcquisition(t *testing.T) {
	b := &windowsBackend{principal: "expected@EXAMPLE.TEST", logon: func() (string, error) { return "other@EXAMPLE.TEST", nil }, call: func(*windows.LazyProc, ...uintptr) (uintptr, uintptr, error) {
		t.Error("wrong logon reached credential API")
		return 0, 0, errors.New("unexpected")
	}}
	if _, err := b.step("nfs/server.test", nil, requestMutual|requestIntegrity); err == nil {
		t.Fatal("wrong local identity accepted")
	}
}

func TestSSPIWindowsNativeIdentityRefusal(t *testing.T) {
	// This exercises the real Windows provider without requesting a service
	// ticket: the deliberately impossible selected principal must fail locally.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	i, err := New(ctx, "nfs-viewer-invalid-current-logon@INVALID.TEST", "nfs/server.invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	if _, _, err = i.Initiate("nfs/server.invalid", testFlags, nil); err == nil {
		t.Fatal("another current-logon identity accepted")
	}
}

func TestSSPIWindowsLifetime(t *testing.T) {
	want := time.Date(2030, 1, 2, 3, 4, 5, 123456700, time.UTC)
	ticks := want.Unix()*10000000 + int64(want.Nanosecond()/100) + 116444736000000000
	got, err := sspiFileTime(ticks)
	if err != nil || !got.Equal(want) {
		t.Fatal(got, err)
	}
	for _, bad := range []int64{0, -1, int64(^uint64(0) >> 1)} {
		if _, err := sspiFileTime(bad); err == nil {
			t.Fatal("indefinite/invalid expiry accepted")
		}
	}
}
