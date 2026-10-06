package gssapi

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/types"
)

const maxCCacheSize = 4 << 20

// Explicit FILE caches only. Do not pass malformed local files to the upstream
// unchecked-slice decoder. Keys/tickets never appear in parser errors.
func readCCache(path string) (*credentials.CCache, error) {
	path = strings.TrimPrefix(path, "FILE:")
	for _, prefix := range []string{"DIR:", "KCM:", "KEYRING:", "API:", "MSLSA:"} {
		if strings.HasPrefix(path, prefix) {
			return nil, errors.New("only explicit FILE credential caches are supported")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("ccache must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCCacheSize+1))
	if err != nil {
		return nil, err
	}
	defer clear(b)
	return parseCCache(b)
}

type cacheReader struct {
	b   []byte
	err error
}

func (r *cacheReader) take(n uint32) []byte {
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(r.b)) {
		r.err = errors.New("truncated credential cache")
		return nil
	}
	v := r.b[:int(n)]
	r.b = r.b[int(n):]
	return v
}
func (r *cacheReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *cacheReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *cacheReader) data() []byte { return r.take(r.u32()) }
func (r *cacheReader) principal() (string, types.PrincipalName) {
	p := types.PrincipalName{NameType: int32(r.u32())}
	count := r.u32()
	if count == 0 || count > 32 {
		r.err = errors.New("invalid ccache principal component count")
		return "", p
	}
	realm := string(r.data())
	if len(realm) == 0 || len(realm) > 4096 {
		r.err = errors.New("invalid ccache realm")
	}
	for i := uint32(0); i < count && r.err == nil; i++ {
		part := string(r.data())
		if len(part) == 0 || len(part) > 4096 {
			r.err = errors.New("invalid ccache principal component")
			break
		}
		p.NameString = append(p.NameString, part)
	}
	return realm, p
}
func (r *cacheReader) timestamp() time.Time { return time.Unix(int64(r.u32()), 0).UTC() }

// MIT FILE versions 3/4 use big endian fields. Old host-endian versions and
// clock-offset correction are rejected explicitly; unknown header tags are skipped.
func parseCCache(b []byte) (*credentials.CCache, error) {
	if len(b) < 2 || len(b) > maxCCacheSize || b[0] != 5 || (b[1] != 3 && b[1] != 4) {
		return nil, errors.New("expected FILE ccache format 3 or 4 (limit 4 MiB)")
	}
	c := &credentials.CCache{Version: b[1]}
	r := &cacheReader{b: b[2:]}
	if c.Version == 4 {
		header := &cacheReader{b: r.take(uint32(r.u16()))}
		for len(header.b) > 0 && header.err == nil {
			tag, size := header.u16(), header.u16()
			value := header.take(uint32(size))
			if tag == 1 {
				if size != 8 {
					return nil, errors.New("invalid ccache KDC offset field")
				}
				for _, v := range value {
					if v != 0 {
						return nil, errors.New("nonzero ccache KDC clock offset is unsupported; synchronize clocks and refresh cache")
					}
				}
			}
		}
		if header.err != nil {
			return nil, header.err
		}
	}
	c.DefaultPrincipal.Realm, c.DefaultPrincipal.PrincipalName = r.principal()
	for len(r.b) > 0 && r.err == nil {
		if len(c.Credentials) >= 4096 {
			return nil, errors.New("too many ccache entries")
		}
		e := &credentials.Credential{}
		e.Client.Realm, e.Client.PrincipalName = r.principal()
		e.Server.Realm, e.Server.PrincipalName = r.principal()
		e.Key.KeyType = int32(r.u16())
		if c.Version == 3 {
			second := int32(r.u16())
			if second != e.Key.KeyType {
				return nil, errors.New("inconsistent ccache key type")
			}
		}
		e.Key.KeyValue = append([]byte(nil), r.data()...)
		e.AuthTime, e.StartTime, e.EndTime, e.RenewTill = r.timestamp(), r.timestamp(), r.timestamp(), r.timestamp()
		iskey := r.take(1)
		if len(iskey) > 0 {
			if iskey[0] > 1 {
				return nil, errors.New("invalid ccache is_skey")
			}
			e.IsSKey = iskey[0] == 1
		}
		e.TicketFlags = types.NewKrbFlags()
		e.TicketFlags.Bytes = append([]byte(nil), r.take(4)...)
		for group := 0; group < 2; group++ {
			count := r.u32()
			if count > 256 {
				return nil, errors.New("too many ccache address/authdata entries")
			}
			for i := uint32(0); i < count && r.err == nil; i++ {
				kind := int32(r.u16())
				value := append([]byte(nil), r.data()...)
				if group == 0 {
					e.Addresses = append(e.Addresses, types.HostAddress{AddrType: kind, Address: value})
				} else {
					e.AuthData = append(e.AuthData, types.AuthorizationDataEntry{ADType: kind, ADData: value})
				}
			}
		}
		e.Ticket = append([]byte(nil), r.data()...)
		e.SecondTicket = append([]byte(nil), r.data()...)
		if r.err != nil {
			break
		}
		if e.Client.Realm != c.DefaultPrincipal.Realm || !e.Client.PrincipalName.Equal(c.DefaultPrincipal.PrincipalName) {
			return nil, errors.New("ccache contains a different client principal")
		}
		c.Credentials = append(c.Credentials, e)
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(c.Credentials) == 0 {
		return nil, errors.New("credential cache is empty")
	}
	return c, nil
}
