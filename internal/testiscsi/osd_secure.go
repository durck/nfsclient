package testiscsi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// OSDCredential represents a security manager, independently issuing an OSD-1
// capability key from the device's working key and system identifier.
func OSDCredential(systemID, workingKey []byte, partition, object uint64, rights byte, expires time.Time) ([]byte, []byte) {
	cap := make([]byte, 80)
	cap[0] = 1
	cap[2] = 3
	cap[49] = rights
	stamp := expires.UnixMilli()
	for i := 9; i >= 4; i-- {
		cap[i] = byte(stamp)
		stamp >>= 8
	}
	cap[30] = 0x5a
	if partition == 0 {
		cap[48] = 1
		cap[55] = 0x20
	} else {
		cap[48] = 0x80
		cap[55] = 0x10
		binary.BigEndian.PutUint64(cap[60:], partition)
		binary.BigEndian.PutUint64(cap[68:], object)
	}
	return cap, peerOSDMAC(workingKey, append(bytes.Clone(cap), systemID...))
}
func peerOSDMAC(key, data []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(data)
	return m.Sum(nil)
}
func (s *Target) ObjectBytes(partition, object uint64) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.options.OSDObjects[[2]uint64{partition, object}])
}

func (s *Target) OSDActions() []uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint16(nil), s.osdActions...)
}

func (s *Target) serveSecureObject(c net.Conn, p, response frame, b []byte) error {
	invalid := func() error { return errors.New("independent OSD rejected authenticated command") }
	h := p.header[:]
	cap := b[80:160]
	part, obj := binary.BigEndian.Uint64(b[16:]), binary.BigEndian.Uint64(b[24:])
	action := binary.BigEndian.Uint16(b[8:])
	s.mu.Lock()
	s.osdActions = append(s.osdActions, action)
	s.mu.Unlock()
	rights := byte(0x20)
	switch action {
	case 0x8805:
		rights |= 0x80
	case 0x8806:
		rights |= 0x40
	case 0x8808:
		rights |= 2
	case 0x880e:
	default:
		return invalid()
	}
	if len(s.options.OSDKey) != 20 || cap[0] != 1 || cap[1]&15 != 0 || cap[2] != 3 || cap[49]&rights != rights || b[11] != 0x30 || h[1] != 0xe1 || len(p.ahs) != 196 || word(b, 68) != 0 || word(b, 72) != ^uint32(0) {
		return invalid()
	}
	if part == 0 {
		if obj != 0 || cap[48] != 1 || cap[55] != 0x20 || !bytes.Equal(cap[60:76], make([]byte, 16)) {
			return invalid()
		}
	} else if cap[48] != 0x80 || cap[55] != 0x10 || binary.BigEndian.Uint64(cap[60:]) != part || binary.BigEndian.Uint64(cap[68:]) != obj {
		return invalid()
	}
	var expiry, stamp int64
	for _, v := range cap[4:10] {
		expiry = expiry<<8 | int64(v)
	}
	for _, v := range b[180:186] {
		stamp = stamp<<8 | int64(v)
	}
	if expiry < time.Now().UnixMilli() || stamp == 0 || stamp < time.Now().Add(-time.Minute).UnixMilli() || stamp > time.Now().Add(time.Minute).UnixMilli() {
		return invalid()
	}
	s.mu.Lock()
	if s.osdNonces == nil {
		s.osdNonces = map[string]bool{}
	}
	duplicate := s.osdNonces[string(b[180:192])]
	s.osdNonces[string(b[180:192])] = true
	s.mu.Unlock()
	if duplicate {
		return invalid()
	}
	key := peerOSDMAC(s.options.OSDKey, append(bytes.Clone(cap), s.options.OSDSystemID...))
	defer clear(key)
	unsigned := bytes.Clone(b)
	clear(unsigned[160:180])
	if !hmac.Equal(b[160:180], peerOSDMAC(key, unsigned)) {
		if s.options.Fault == "wrong-key" || s.options.Fault == "wrong-system" {
			response.header[3] = 2
			return send(c, response)
		}
		return invalid()
	}
	decodeOffset := func(pos int) int {
		encoded := word(b, pos)
		if encoded>>28 != 0 {
			return -1
		}
		return int(encoded&0xfffffff) * 256
	}
	getAt, outAt, attrAt, inAt := decodeOffset(56), decodeOffset(196), decodeOffset(64), decodeOffset(192)
	getN, attrN := int(word(b, 52)), int(word(b, 60))
	outN, inN := int(word(h, 20)), int(word(p.ahs, 192))
	count, off := binary.BigEndian.Uint64(b[36:]), binary.BigEndian.Uint64(b[44:])
	outCount, inCount := 0, 0
	if action == 0x8806 {
		outCount = int(count)
	}
	if action == 0x8805 {
		inCount = int(count)
	}
	if count > 65024 || getAt < outCount || getAt < 0 || outAt < getAt+getN || outN != outAt+44 || attrAt < inCount || attrAt < 0 || inAt < attrAt+attrN || inN != inAt+36 || outN > 65536 || inN > 65536 || (getN != 12 && getN != 20) {
		return invalid()
	}
	// One R2T solicits the full authenticated Data-Out buffer; Data-Out PDUs
	// have their own burst numbering, whereas Data-In follows the R2T number.
	r := response
	r.header[0] = 0x31
	set(r.header[:], 20, 77)
	set(r.header[:], 36, 0)
	set(r.header[:], 40, 0)
	set(r.header[:], 44, uint32(outN))
	if err := send(c, r); err != nil {
		return err
	}
	out := make([]byte, 0, outN)
	var dataSN uint32
	for len(out) < outN {
		q, err := receive(c)
		if err != nil {
			return err
		}
		if q.header[0] != 5 || word(q.header[:], 16) != word(h, 16) || word(q.header[:], 20) != 77 || word(q.header[:], 36) != dataSN || word(q.header[:], 40) != uint32(len(out)) || len(q.payload) == 0 || len(q.payload) > outN-len(out) {
			return invalid()
		}
		out = append(out, q.payload...)
		dataSN++
	}
	integ := out[outAt:]
	get := out[getAt : getAt+getN]
	if !bytes.Equal(get[:4], []byte{1, 0, 0, 0}) || binary.BigEndian.Uint64(integ) != uint64(outCount) || binary.BigEndian.Uint64(integ[8:]) != 0 || binary.BigEndian.Uint64(integ[16:]) != uint64(getN) || !hmac.Equal(integ[24:], peerOSDMAC(key, append(bytes.Clone(out[:outCount]), get...))) {
		return invalid()
	}
	result := make([]byte, inN)
	attrs := result[attrAt : attrAt+attrN]
	attrs[0] = 9
	binary.BigEndian.PutUint16(attrs[2:], uint16(attrN-4))
	cursor := 4
	s.mu.Lock()
	objectData, exists := s.options.OSDObjects[[2]uint64{part, obj}]
	if action == 0x8805 || action == 0x8806 {
		if !exists || count == 0 || off > uint64(len(objectData)) || count > uint64(len(objectData))-off {
			s.mu.Unlock()
			return invalid()
		}
		if action == 0x8805 {
			copy(result, objectData[off:off+count])
		} else {
			copy(objectData[off:off+count], out[:outCount])
		}
	}
	s.mu.Unlock()
	for at := 4; at < getN; at += 8 {
		page, number := word(get, at), word(get, at+4)
		var value []byte
		switch {
		case page == 0xfffffffe && number == 1:
			value = peerOSDMAC(key, append(bytes.Clone(b[180:192]), 0))
		case part == 0 && obj == 0 && page == 0x90000005 && number == 0x80000000:
			value = []byte{1}
			if s.options.Fault == "osd-algorithm" {
				value[0] = 2
			}
		case part == 0 && obj == 0 && page == 0x90000001 && number == 3:
			value = s.options.OSDSystemID
		case part == 0 && obj == 0 && page == 0x90000001 && number == 9:
			value = s.options.OSDName
		case exists && page == 1 && number == 0x82:
			value = make([]byte, 8)
			binary.BigEndian.PutUint64(value, uint64(len(objectData)))
		default:
			return invalid()
		}
		if cursor+10+len(value) > len(attrs) {
			return invalid()
		}
		set(attrs, cursor, page)
		set(attrs, cursor+4, number)
		binary.BigEndian.PutUint16(attrs[cursor+8:], uint16(len(value)))
		copy(attrs[cursor+10:], value)
		cursor += 10 + len(value)
	}
	if cursor != len(attrs) {
		return invalid()
	}
	// Faults apply to user operations so device discovery succeeds first.
	user := part != 0
	if user && s.options.Fault == "osd-secure-status" {
		attrs[len(attrs)-1] ^= 1
	}
	binary.BigEndian.PutUint64(result[inAt:], uint64(inCount))
	binary.BigEndian.PutUint64(result[inAt+8:], uint64(attrN))
	copy(result[inAt+16:], peerOSDMAC(key, append(bytes.Clone(result[:inCount]), attrs...)))
	if user {
		switch s.options.Fault {
		case "osd-secure-data":
			result[0] ^= 1
		case "osd-secure-count":
			result[inAt+7] ^= 1
		case "osd-secure-icv":
			result[len(result)-1] ^= 1
		case "osd-secure-drop":
			return c.Close()
		}
	}
	if action == 0x8806 && s.options.Fault == "osd-write-drop" {
		return c.Close()
	}
	if action == 0x8808 && s.options.Fault == "osd-flush-drop" {
		return c.Close()
	}
	if action == 0x8806 && s.options.Fault == "osd-write-short" {
		result = result[:len(result)-1]
	}
	if action == 0x8806 && s.options.Fault == "osd-write-error" {
		response.header[3] = 2
		response.header[1] = 0x80
		return send(c, response)
	}
	sn := uint32(1)
	for at := 0; at < len(result); {
		n := min(512, len(result)-at)
		q := response
		q.header[0] = 0x25
		q.header[1] = 0
		if at+n == len(result) {
			q.header[1] = 0x80
		}
		set(q.header[:], 36, sn)
		set(q.header[:], 40, uint32(at))
		q.payload = result[at : at+n]
		if err := send(c, q); err != nil {
			return err
		}
		sn++
		at += n
	}
	set(response.header[:], 36, sn)
	return send(c, response)
}
