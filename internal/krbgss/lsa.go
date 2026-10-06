package gssapi

import (
	"bytes"
	stdcontext "context"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const lsaCurrentCache = "MSLSA:CURRENT"

// Windows SDK NTSecAPI.h: KerbQueryTicketCacheExMessage (XP and later).
const lsaQueryCacheEx = 14

// Native response pointers are numeric offsets within a detached allocation.
// The parser never converts them into Go pointers or follows external memory.
type lsaBuffer struct {
	b     []byte
	base  uintptr
	width int
}
type lsaProvider interface {
	query(stdcontext.Context) (lsaBuffer, error)
	retrieve(stdcontext.Context, string) (lsaBuffer, error)
	close()
}
type lsaTicket struct {
	client, clientRealm, server, serverRealm string
	start, end, renew                        uint64
	etype                                    int32
	flags                                    uint32
}

func (b lsaBuffer) valid() bool {
	return (b.width == 4 || b.width == 8) && len(b.b) > 0 && len(b.b) <= maxCCacheSize && b.base != 0 && b.base+uintptr(len(b.b)) >= b.base
}
func (b lsaBuffer) pointer(off int) (uintptr, error) {
	if off < 0 || off > len(b.b)-b.width {
		return 0, errors.New("truncated LSA pointer")
	}
	if b.width == 4 {
		return uintptr(binary.LittleEndian.Uint32(b.b[off:])), nil
	}
	v := binary.LittleEndian.Uint64(b.b[off:])
	if uint64(uintptr(v)) != v {
		return 0, errors.New("LSA pointer exceeds platform width")
	}
	return uintptr(v), nil
}
func (b lsaBuffer) span(p uintptr, n int) ([]byte, error) {
	if !b.valid() || n < 0 || p < b.base || p-b.base > uintptr(len(b.b)) || uintptr(n) > uintptr(len(b.b))-(p-b.base) {
		return nil, errors.New("LSA data exceeds return allocation")
	}
	return b.b[int(p-b.base) : int(p-b.base)+n], nil
}
func (b lsaBuffer) text(off int) (string, error) {
	size := 2 * b.width
	if off < 0 || off > len(b.b)-size {
		return "", errors.New("truncated LSA Unicode descriptor")
	}
	n, max := int(binary.LittleEndian.Uint16(b.b[off:])), int(binary.LittleEndian.Uint16(b.b[off+2:]))
	if n == 0 || n > 4096 || n%2 != 0 || max < n || max%2 != 0 {
		return "", errors.New("invalid LSA Unicode length")
	}
	ptr, err := b.pointer(off + b.width)
	if err != nil {
		return "", err
	}
	if ptr%2 != 0 {
		return "", errors.New("unaligned LSA Unicode data")
	}
	data, err := b.span(ptr, max)
	if err != nil {
		return "", err
	}
	units := make([]uint16, n/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	for i := 0; i < len(units); i++ {
		v := units[i]
		if v < 32 || v == 127 {
			return "", errors.New("control character in LSA identity")
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", errors.New("invalid LSA UTF-16")
			}
			i++
		} else if v >= 0xdc00 && v <= 0xdfff {
			return "", errors.New("invalid LSA UTF-16")
		}
	}
	return string(utf16.Decode(units)), nil
}

func (b lsaBuffer) optionalText(off int) (string, error) {
	if off < 0 || off > len(b.b)-2*b.width {
		return "", errors.New("truncated LSA optional Unicode descriptor")
	}
	if binary.LittleEndian.Uint16(b.b[off:]) == 0 {
		max := int(binary.LittleEndian.Uint16(b.b[off+2:]))
		p, err := b.pointer(off + b.width)
		if err != nil {
			return "", err
		}
		if max == 0 {
			return "", nil
		}
		if max%2 != 0 {
			return "", errors.New("invalid optional LSA Unicode length")
		}
		_, err = b.span(p, max)
		return "", err
	}
	return b.text(off)
}
func selectLSATicket(b lsaBuffer, principal string) (lsaTicket, error) {
	var chosen lsaTicket
	user, realm, ok := strings.Cut(principal, "@")
	if !ok || user == "" || realm == "" || strings.Contains(realm, "@") || len(principal) > 512 {
		return chosen, errors.New("LSA requires a bounded explicit NAME@REALM")
	}
	if !b.valid() || len(b.b) < 8 || binary.LittleEndian.Uint32(b.b) != lsaQueryCacheEx {
		return chosen, errors.New("invalid LSA cache response")
	}
	count := int(binary.LittleEndian.Uint32(b.b[4:]))
	stride := 8*b.width + 32
	if count > 64 || count > (len(b.b)-8)/stride {
		return chosen, errors.New("invalid or excessive LSA ticket count")
	}
	matched := 0
	for i := 0; i < count; i++ {
		off := 8 + i*stride
		names := make([]string, 4)
		for j := range names {
			var err error
			names[j], err = b.text(off + j*2*b.width)
			if err != nil {
				return chosen, err
			}
		}
		if names[2] != "krbtgt/"+realm || names[3] != realm {
			continue
		}
		matched++
		if names[0] != user || names[1] != realm {
			return chosen, errors.New("LSA home TGT is ambiguous or differs from --principal")
		}
		x := off + 8*b.width
		chosen = lsaTicket{client: names[0], clientRealm: names[1], server: names[2], serverRealm: names[3], start: binary.LittleEndian.Uint64(b.b[x:]), end: binary.LittleEndian.Uint64(b.b[x+8:]), renew: binary.LittleEndian.Uint64(b.b[x+16:]), etype: int32(binary.LittleEndian.Uint32(b.b[x+24:])), flags: binary.LittleEndian.Uint32(b.b[x+28:])}
	}
	if matched != 1 {
		return chosen, errors.New("LSA requires exactly one cached selected home TGT; no acquisition or fallback")
	}
	if chosen.etype != 17 && chosen.etype != 18 || chosen.flags&0x2b000000 != 0 {
		return chosen, errors.New("LSA requires an ordinary valid AES home TGT")
	}
	start, err := lsaTime(chosen.start, false)
	if err != nil {
		return chosen, err
	}
	end, err := lsaTime(chosen.end, false)
	if err != nil {
		return chosen, err
	}
	now := time.Now()
	if start.After(now) || !end.After(now) || !end.After(start) {
		return chosen, errors.New("LSA TGT expired or not yet valid")
	}
	return chosen, nil
}
func lsaTime(ticks uint64, optional bool) (time.Time, error) {
	if optional && ticks == 0 {
		return time.Time{}, nil
	}
	const epoch = 116444736000000000
	if ticks < epoch || (ticks-epoch)/10000000 > 0xffffffff {
		return time.Time{}, errors.New("invalid LSA ticket timestamp")
	}
	ticks -= epoch
	return time.Unix(int64(ticks/10000000), int64(ticks%10000000)*100).UTC(), nil
}
func (b lsaBuffer) name(p uintptr) (types.PrincipalName, error) {
	var result types.PrincipalName
	head, err := b.span(p, b.width)
	if err != nil {
		return result, err
	}
	count := int(binary.LittleEndian.Uint16(head[2:]))
	kind := int16(binary.LittleEndian.Uint16(head))
	if count < 1 || count > 32 || kind < 0 || kind > 2 {
		return result, errors.New("invalid LSA principal descriptor")
	}
	if _, err = b.span(p, b.width+count*2*b.width); err != nil {
		return result, err
	}
	result.NameType = int32(kind)
	for i := 0; i < count; i++ {
		s, err := b.text(int(p-b.base) + b.width + i*2*b.width)
		if err != nil {
			return result, err
		}
		if strings.ContainsAny(s, "/@\\") {
			return result, errors.New("unsupported LSA principal component")
		}
		result.NameString = append(result.NameString, s)
	}
	return result, nil
}
func decodeLSATGT(b lsaBuffer, m lsaTicket) (*credentials.CCache, error) {
	// Native KERB_EXTERNAL_TICKET layouts: MSVC pointer alignment and 64-bit
	// LARGE_INTEGER alignment are reflected explicitly, independent of Go ABI.
	header := 104
	keyOff := 36
	flagsOff := 48
	timesOff := 56
	sizeOff := 96
	if b.width == 8 {
		header, keyOff, flagsOff, timesOff, sizeOff = 152, 72, 88, 96, 136
	}
	if !b.valid() || len(b.b) < header {
		return nil, errors.New("truncated LSA external ticket")
	}
	names := make([]types.PrincipalName, 3)
	for i := range names {
		p, err := b.pointer(i * b.width)
		if err != nil {
			return nil, err
		}
		names[i], err = b.name(p)
		if err != nil {
			return nil, err
		}
	}
	realms := make([]string, 3)
	for i := range realms {
		var err error
		if i == 2 {
			realms[i], err = b.optionalText(3*b.width + i*2*b.width)
		} else {
			realms[i], err = b.text(3*b.width + i*2*b.width)
		}
		if err != nil {
			return nil, err
		}
	}
	if names[0].PrincipalNameString() != m.server || names[1].PrincipalNameString() != m.server || names[2].PrincipalNameString() != m.client || realms[0] != m.serverRealm || realms[1] != m.serverRealm {
		return nil, errors.New("LSA returned ticket identity differs from the pinned cache entry")
	}
	kt := int32(binary.LittleEndian.Uint32(b.b[keyOff:]))
	kn := int(binary.LittleEndian.Uint32(b.b[keyOff+4:]))
	kp, err := b.pointer(keyOff + 8)
	if err != nil {
		return nil, err
	}
	if !(kt == 17 && kn == 16 || kt == 18 && kn == 32) {
		return nil, errors.New("LSA session key unavailable, protected or unsupported")
	}
	key, err := b.span(kp, kn)
	if err != nil {
		return nil, err
	}
	var nonzero byte
	for _, v := range key {
		nonzero |= v
	}
	if nonzero == 0 {
		return nil, errors.New("LSA session key unavailable or protected")
	}
	flags := binary.LittleEndian.Uint32(b.b[flagsOff:])
	reserved := binary.LittleEndian.Uint32(b.b[flagsOff+4:])
	start := binary.LittleEndian.Uint64(b.b[timesOff+8:])
	end := binary.LittleEndian.Uint64(b.b[timesOff+16:])
	renew := binary.LittleEndian.Uint64(b.b[timesOff+24:])
	skew := binary.LittleEndian.Uint64(b.b[timesOff+32:])
	if flags != m.flags || reserved != 0 || start != m.start || end != m.end || renew != m.renew || skew != 0 {
		return nil, errors.New("LSA ticket metadata changed or has unsupported clock correction")
	}
	n := int(binary.LittleEndian.Uint32(b.b[sizeOff:]))
	ticketPtr, err := b.pointer(sizeOff + b.width)
	if err != nil {
		return nil, err
	}
	if n < 1 || n > maxCCacheSize {
		return nil, errors.New("invalid LSA ticket size")
	}
	wire, err := b.span(ticketPtr, n)
	if err != nil {
		return nil, err
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(wire, &raw)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid LSA ticket framing")
	}
	var ticket messages.Ticket
	if ticket.Unmarshal(wire) != nil || ticket.TktVNO != 5 || ticket.Realm != m.serverRealm || ticket.SName.PrincipalNameString() != m.server || ticket.EncPart.EType != m.etype {
		return nil, errors.New("LSA encoded TGT identity differs from its metadata")
	}
	c := &credentials.CCache{Version: 4}
	c.DefaultPrincipal.Realm = m.clientRealm
	c.DefaultPrincipal.PrincipalName = names[2]
	e := &credentials.Credential{}
	e.Client = c.DefaultPrincipal
	e.Server.Realm = m.serverRealm
	e.Server.PrincipalName = names[0]
	e.Key = types.EncryptionKey{KeyType: kt, KeyValue: bytes.Clone(key)}
	e.Ticket = bytes.Clone(wire)
	e.StartTime, _ = lsaTime(start, false)
	e.AuthTime = e.StartTime
	e.EndTime, _ = lsaTime(end, false)
	e.RenewTill, err = lsaTime(renew, true)
	e.TicketFlags = types.NewKrbFlags()
	binary.BigEndian.PutUint32(e.TicketFlags.Bytes, flags)
	c.Credentials = []*credentials.Credential{e}
	if err != nil {
		clearNativeCache(c)
		return nil, err
	}
	if err := validateArmorTGT(c); err != nil {
		clearNativeCache(c)
		return nil, err
	}
	return c, nil
}

func readLSAWith(ctx stdcontext.Context, principal string, p lsaProvider) (_ *credentials.CCache, resultErr error) {
	defer p.close()
	if ctx == nil {
		ctx = stdcontext.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := p.query(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(before.b)
	m, err := selectLSATicket(before, principal)
	if err != nil {
		return nil, err
	}
	first, err := p.retrieve(ctx, m.server)
	if err != nil {
		return nil, err
	}
	defer clear(first.b)
	c, err := decodeLSATGT(first, m)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			clearNativeCache(c)
		}
	}()
	second, err := p.retrieve(ctx, m.server)
	if err != nil {
		return nil, err
	}
	defer clear(second.b)
	check, err := decodeLSATGT(second, m)
	if err != nil {
		return nil, err
	}
	defer clearNativeCache(check)
	if !bytes.Equal(c.Credentials[0].Key.KeyValue, check.Credentials[0].Key.KeyValue) || !bytes.Equal(c.Credentials[0].Ticket, check.Credentials[0].Ticket) {
		return nil, errors.New("LSA selected TGT changed during snapshot")
	}
	after, err := p.query(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(after.b)
	final, err := selectLSATicket(after, principal)
	if err != nil {
		return nil, err
	}
	if final != m {
		return nil, errors.New("LSA selected cache entry changed during snapshot")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}
