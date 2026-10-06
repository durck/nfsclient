// Package iscsi implements a bounded, single-connection iSCSI/TCP storage
// profile. Endpoints are explicit approvals; redirects, discovery, reconnects,
// task recovery and command replay are never implicit.
package iscsi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Target struct {
	Endpoint, Name string
	LUN            uint8
}

// ValidName accepts the normalized ASCII IQN subset used by this profile.
func ValidName(name string) bool {
	if len(name) < 13 || len(name) > 223 || !strings.HasPrefix(name, "iqn.") || name[8] != '-' || name[11] != '.' {
		return false
	}
	for _, c := range name[4:8] {
		if c < '0' || c > '9' {
			return false
		}
	}
	month, err := strconv.Atoi(name[9:11])
	if err != nil || month < 1 || month > 12 {
		return false
	}
	for _, c := range name[12:] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':') {
			return false
		}
	}
	domain, suffix, unique := strings.Cut(name[12:], ":")
	if unique && suffix == "" {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// ParseTarget requires iscsi://LITERAL_IP:PORT/IQN/DECIMAL_LUN. No userinfo,
// escaped paths, DNS, default port, query or fragment can alter the approval.
func ParseTarget(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "iscsi" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Opaque != "" || strings.ContainsAny(raw, "%#") {
		return Target{}, errors.New("invalid explicit iSCSI target URL")
	}
	a, err := netip.ParseAddrPort(u.Host)
	if err != nil || a.Port() == 0 || a.Addr().Zone() != "" || a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
		return Target{}, errors.New("iSCSI target requires a literal IP and explicit nonzero port")
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 3 || parts[0] != "" || !ValidName(parts[1]) {
		return Target{}, errors.New("iSCSI target requires a normalized IQN and LUN")
	}
	lun, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil || strconv.FormatUint(lun, 10) != parts[2] {
		return Target{}, errors.New("iSCSI LUN must be a canonical decimal in 0..255")
	}
	return Target{netip.AddrPortFrom(a.Addr().Unmap(), a.Port()).String(), parts[1], uint8(lun)}, nil
}

func decodeNAA(b []byte) ([]byte, error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0x83 || int(binary.BigEndian.Uint16(b[2:4])) != len(b)-4 {
		return nil, errors.New("invalid direct-access VPD device identification")
	}
	var id []byte
	for p := b[4:]; len(p) != 0; {
		if len(p) < 4 || int(p[3]) > len(p)-4 {
			return nil, errors.New("truncated VPD descriptor")
		}
		n := int(p[3])
		data := p[4 : 4+n]
		if p[0]&15 == 1 && p[1]&0x3f == 3 {
			if !(n == 8 && (data[0]>>4 == 2 || data[0]>>4 == 3 || data[0]>>4 == 5) || n == 16 && data[0]>>4 == 6) || id != nil && !bytes.Equal(id, data) {
				return nil, errors.New("invalid or ambiguous logical-unit NAA")
			}
			id = bytes.Clone(data)
		}
		p = p[4+n:]
	}
	if id == nil {
		return nil, errors.New("target must expose a logical-unit NAA in VPD page 83")
	}
	return id, nil
}
