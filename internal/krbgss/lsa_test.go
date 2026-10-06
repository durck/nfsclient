package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Independent Win32 wire fixtures use virtual pointer values; no native memory
// is dereferenced by these tests, including their 32-bit profiles.
type lsaWire struct {
	b     []byte
	width int
	base  uintptr
}

func (f *lsaWire) ptr(off int, p uintptr) {
	if f.width == 4 {
		binary.LittleEndian.PutUint32(f.b[off:], uint32(p))
	} else {
		binary.LittleEndian.PutUint64(f.b[off:], uint64(p))
	}
}
func (f *lsaWire) data(b []byte) uintptr {
	if len(f.b)%2 != 0 {
		f.b = append(f.b, 0)
	}
	p := f.base + uintptr(len(f.b))
	f.b = append(f.b, b...)
	return p
}
func (f *lsaWire) text(off int, s string) {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*(len(u)+1))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	p := f.data(b)
	binary.LittleEndian.PutUint16(f.b[off:], uint16(2*len(u)))
	binary.LittleEndian.PutUint16(f.b[off+2:], uint16(len(b)))
	f.ptr(off+f.width, p)
}
func (f *lsaWire) name(off int, parts ...string) {
	start := len(f.b)
	f.b = append(f.b, make([]byte, f.width+2*f.width*len(parts))...)
	binary.LittleEndian.PutUint16(f.b[start:], 1)
	binary.LittleEndian.PutUint16(f.b[start+2:], uint16(len(parts)))
	f.ptr(off, f.base+uintptr(start))
	for i, s := range parts {
		f.text(start+f.width+i*2*f.width, s)
	}
}
func lsaFixtureTimes() (uint64, uint64, uint64) {
	const epoch = 116444736000000000
	now := uint64(time.Now().Unix())
	return epoch + (now-2)*10000000, epoch + (now+3600)*10000000, epoch + (now+7200)*10000000
}
func lsaQueryFixture(width, count int) lsaBuffer {
	stride := 64
	if width == 8 {
		stride = 96
	}
	f := lsaWire{b: make([]byte, 8+count*stride), width: width, base: 0x10000000}
	binary.LittleEndian.PutUint32(f.b, 14)
	binary.LittleEndian.PutUint32(f.b[4:], uint32(count))
	start, end, renew := lsaFixtureTimes()
	for i := 0; i < count; i++ {
		off := 8 + i*stride
		for j, s := range []string{"root", "NFS.TEST", "krbtgt/NFS.TEST", "NFS.TEST"} {
			f.text(off+2*width*j, s)
		}
		x := off + 8*width
		binary.LittleEndian.PutUint64(f.b[x:], start)
		binary.LittleEndian.PutUint64(f.b[x+8:], end)
		binary.LittleEndian.PutUint64(f.b[x+16:], renew)
		binary.LittleEndian.PutUint32(f.b[x+24:], 18)
		binary.LittleEndian.PutUint32(f.b[x+28:], 0x40e00000)
	}
	return lsaBuffer{f.b, f.base, width}
}
func lsaExternalFixture(t *testing.T, width int, m lsaTicket) lsaBuffer {
	t.Helper()
	header, key, flags, times, size := 104, 36, 48, 56, 96
	if width == 8 {
		header, key, flags, times, size = 152, 72, 88, 96, 136
	}
	f := lsaWire{b: make([]byte, header), width: width, base: 0x20000000}
	f.name(0, "krbtgt", "NFS.TEST")
	f.name(width, "krbtgt", "NFS.TEST")
	f.name(2*width, "root")
	f.text(3*width, "NFS.TEST")
	f.text(5*width, "NFS.TEST")
	// Optional alternate/NetBIOS realm is intentionally absent.
	binary.LittleEndian.PutUint32(f.b[key:], 18)
	binary.LittleEndian.PutUint32(f.b[key+4:], 32)
	kp := f.data(bytes.Repeat([]byte{0x42}, 32))
	f.ptr(key+8, kp)
	binary.LittleEndian.PutUint32(f.b[flags:], m.flags)
	binary.LittleEndian.PutUint64(f.b[times+8:], m.start)
	binary.LittleEndian.PutUint64(f.b[times+16:], m.end)
	binary.LittleEndian.PutUint64(f.b[times+24:], m.renew)
	ticket := messages.Ticket{TktVNO: 5, Realm: "NFS.TEST", SName: types.NewPrincipalName(2, "krbtgt/NFS.TEST"), EncPart: types.EncryptedData{EType: 18, Cipher: []byte("opaque independent LSA fixture")}}
	b, err := ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := f.data(b)
	binary.LittleEndian.PutUint32(f.b[size:], uint32(len(b)))
	f.ptr(size+width, p)
	return lsaBuffer{f.b, f.base, width}
}
func TestLSABoundedQuery(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, mode := range []string{"valid", "wrong-header", "count", "duplicate", "missing", "client", "realm", "pointer", "length", "max-length", "surrogate", "keytype", "invalid-flag", "expired", "future", "base-overflow", "width"} {
			t.Run(string(rune('0'+width))+"/"+mode, func(t *testing.T) {
				count := 1
				if mode == "duplicate" {
					count = 2
				}
				if mode == "missing" {
					count = 0
				}
				b := lsaQueryFixture(width, count)
				x := 8 + 8*width
				principal := "root@NFS.TEST"
				switch mode {
				case "wrong-header":
					binary.LittleEndian.PutUint32(b.b, 1)
				case "count":
					binary.LittleEndian.PutUint32(b.b[4:], 65)
				case "client":
					principal = "other@NFS.TEST"
				case "realm":
					principal = "root@OTHER.TEST"
				case "pointer":
					for i := 0; i < width; i++ {
						b.b[8+width+i] = 0xff
					}
				case "length":
					binary.LittleEndian.PutUint16(b.b[8:], 1)
				case "max-length":
					binary.LittleEndian.PutUint16(b.b[10:], 2)
				case "surrogate":
					p, _ := b.pointer(8 + width)
					binary.LittleEndian.PutUint16(b.b[int(p-b.base):], 0xd800)
				case "keytype":
					binary.LittleEndian.PutUint32(b.b[x+24:], 23)
				case "invalid-flag":
					binary.LittleEndian.PutUint32(b.b[x+28:], 0x01000000)
				case "expired":
					binary.LittleEndian.PutUint64(b.b[x+8:], 116444736000000000)
				case "future":
					binary.LittleEndian.PutUint64(b.b[x:], 116444736000000000+uint64(time.Now().Add(time.Hour).Unix())*10000000)
				case "base-overflow":
					b.base = ^uintptr(0) - 1
				case "width":
					b.width = 3
				}
				_, err := selectLSATicket(b, principal)
				if (err == nil) != (mode == "valid") {
					t.Fatal("wrong bounded query decision", err)
				}
			})
		}
	}
}
func TestLSABoundedExternalTicket(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, mode := range []string{"valid", "key128-ticket256", "alt-netbios", "short", "external-name", "client", "realm", "key-pointer", "protected-key", "empty-key", "key-size", "ticket-pointer", "ticket-size", "ticket-framing", "ticket-identity", "flags", "reserved", "times", "skew"} {
			t.Run(string(rune('0'+width))+"/"+mode, func(t *testing.T) {
				q := lsaQueryFixture(width, 1)
				m, err := selectLSATicket(q, "root@NFS.TEST")
				if err != nil {
					t.Fatal(err)
				}
				b := lsaExternalFixture(t, width, m)
				key, flags, times, size := 36, 48, 56, 96
				if width == 8 {
					key, flags, times, size = 72, 88, 96, 136
				}
				switch mode {
				case "key128-ticket256":
					binary.LittleEndian.PutUint32(b.b[key:], 17)
					binary.LittleEndian.PutUint32(b.b[key+4:], 16)
				case "alt-netbios":
					f := lsaWire{b.b, width, b.base}
					f.text(7*width, "NFS")
					b.b = f.b
				case "short":
					b.b = b.b[:20]
				case "external-name":
					b.b[0] = 0
				case "client":
					p, _ := b.pointer(2 * width)
					s, _ := b.pointer(int(p-b.base) + 2*width)
					b.b[int(s-b.base)] = 'b'
				case "realm":
					s, _ := b.pointer(4 * width)
					b.b[int(s-b.base)] = 'O'
				case "key-pointer":
					for i := 0; i < width; i++ {
						b.b[key+8+i] = 0xff
					}
				case "protected-key":
					binary.LittleEndian.PutUint32(b.b[key:], 0)
				case "empty-key":
					p, _ := b.pointer(key + 8)
					clear(b.b[int(p-b.base) : int(p-b.base)+32])
				case "key-size":
					binary.LittleEndian.PutUint32(b.b[key+4:], 31)
				case "ticket-pointer":
					for i := 0; i < width; i++ {
						b.b[size+width+i] = 0xff
					}
				case "ticket-size":
					binary.LittleEndian.PutUint32(b.b[size:], maxCCacheSize+1)
				case "ticket-framing":
					b.b = append(b.b, 0)
					n := binary.LittleEndian.Uint32(b.b[size:])
					binary.LittleEndian.PutUint32(b.b[size:], n+1)
				case "ticket-identity":
					p, _ := b.pointer(size + width)
					wire := b.b[int(p-b.base):]
					idx := bytes.Index(wire, []byte("NFS.TEST"))
					if idx < 0 {
						t.Fatal("fixture realm")
					}
					wire[idx] = 'O'
				case "flags":
					binary.LittleEndian.PutUint32(b.b[flags:], 1)
				case "reserved":
					binary.LittleEndian.PutUint32(b.b[flags+4:], 1)
				case "times":
					binary.LittleEndian.PutUint64(b.b[times+16:], m.end+1)
				case "skew":
					binary.LittleEndian.PutUint64(b.b[times+32:], 1)
				}
				c, err := decodeLSATGT(b, m)
				valid := mode == "valid" || mode == "key128-ticket256" || mode == "alt-netbios"
				if c != nil {
					defer clearNativeCache(c)
				}
				if (err == nil) != valid {
					t.Fatal("wrong external ticket decision", err)
				}
			})
		}
	}
}

type fixtureLSAProvider struct {
	queryBuffers, retrieveBuffers []lsaBuffer
	queries, retrievals, closed   int
	targets                       []string
	errAt                         int
	cancel                        stdcontext.CancelFunc
}

func (p *fixtureLSAProvider) query(ctx stdcontext.Context) (lsaBuffer, error) {
	p.queries++
	if p.errAt == p.queries+p.retrievals {
		return lsaBuffer{}, errors.New("independent query refusal")
	}
	return p.queryBuffers[p.queries-1], nil
}
func (p *fixtureLSAProvider) retrieve(ctx stdcontext.Context, target string) (lsaBuffer, error) {
	p.retrievals++
	p.targets = append(p.targets, target)
	if p.errAt == p.queries+p.retrievals {
		return lsaBuffer{}, errors.New("independent retrieval refusal")
	}
	if p.cancel != nil {
		p.cancel()
	}
	return p.retrieveBuffers[p.retrievals-1], nil
}
func (p *fixtureLSAProvider) close() { p.closed++ }
func TestLSARepeatedSnapshot(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "key-change", "ticket-change", "metadata-change", "query-error", "retrieve-error", "final-error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			q := lsaQueryFixture(8, 1)
			m, err := selectLSATicket(q, "root@NFS.TEST")
			if err != nil {
				t.Fatal(err)
			}
			clone := func(b lsaBuffer) lsaBuffer { b.b = bytes.Clone(b.b); return b }
			first := lsaExternalFixture(t, 8, m)
			p := &fixtureLSAProvider{queryBuffers: []lsaBuffer{q, clone(q)}, retrieveBuffers: []lsaBuffer{first, clone(first)}}
			ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
			defer cancel()
			switch mode {
			case "missing":
				p.queryBuffers[0] = lsaQueryFixture(8, 0)
			case "key-change":
				ptr, _ := p.retrieveBuffers[1].pointer(80)
				p.retrieveBuffers[1].b[int(ptr-first.base)] ^= 1
			case "ticket-change":
				ptr, _ := p.retrieveBuffers[1].pointer(144)
				n := binary.LittleEndian.Uint32(first.b[136:])
				p.retrieveBuffers[1].b[int(ptr-first.base)+int(n)-1] ^= 1
			case "metadata-change":
				binary.LittleEndian.PutUint64(p.queryBuffers[1].b[80:], m.end+1)
			case "query-error":
				p.errAt = 1
			case "retrieve-error":
				p.errAt = 2
			case "final-error":
				p.errAt = 4
			case "canceled":
				p.cancel = cancel
			}
			c, err := readLSAWith(ctx, "root@NFS.TEST", p)
			if (err == nil) != (mode == "valid") {
				t.Fatal("wrong snapshot decision", err)
			}
			if c != nil {
				clearNativeCache(c)
			}
			if p.closed != 1 {
				t.Fatal("LSA handle retained")
			}
			for _, target := range p.targets {
				if target != "krbtgt/NFS.TEST" {
					t.Fatal("unpinned target")
				}
			}
			if mode == "missing" && p.retrievals != 0 {
				t.Fatal("missing selection retrieved credentials")
			}
			for _, b := range []lsaBuffer{q, first} {
				if mode == "valid" && !bytes.Equal(b.b, make([]byte, len(b.b))) {
					t.Fatal("raw native snapshot retained")
				}
			}
		})
	}
}
func TestLSASelectionBounds(t *testing.T) {
	for _, name := range []string{"MSLSA:", "MSLSA:DEFAULT", "MSLSA:123", "MSLSA:current"} {
		if ValidateCCacheSelection(name, "") == nil {
			t.Fatal("implicit/foreign logon selected")
		}
	}
	if ValidateCCacheSelection(lsaCurrentCache, "socket") == nil {
		t.Fatal("LSA accepted KCM socket")
	}
	if err := ValidateCCacheSelection(lsaCurrentCache, ""); (err == nil) != (lsaPlatform() == nil) {
		t.Fatal(err)
	}
	if _, err := readSelectedCCache(stdcontext.Background(), lsaCurrentCache, ""); err == nil {
		t.Fatal("LSA accepted unpinned identity")
	} else if !strings.Contains(err.Error(), "LSA") && !strings.Contains(err.Error(), "MSLSA") {
		t.Fatal(err)
	}
}
