package testiscsi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

// Decode OSD-1 and iSCSI AHS bytes independently of the client implementation.
func (s *Target) serveObject(c net.Conn, p frame, stat, cmd uint32) error {
	h := p.header[:]
	s.event(h[32])
	var response frame
	response.header[0] = 0x21
	response.header[1] = 0x80
	set(response.header[:], 16, word(h, 16))
	set(response.header[:], 24, stat)
	set(response.header[:], 28, cmd)
	set(response.header[:], 32, cmd+63)
	// RFC 7143 section 4.2.2.4: bidirectional R2T and Data-In share
	// incoming numbering; solicited Data-Out starts from zero per burst.
	var sn uint32
	inputOffset := 0
	var data []byte
	bidi := false
	if h[32] == 0x12 {
		if h[1] != 0xc1 || h[33] != 0 || h[36] != 36 || word(h, 20) != 36 || len(p.ahs) != 0 {
			return errors.New("invalid OSD inquiry")
		}
		data = make([]byte, 36)
		data[0] = 0x11
		if s.options.Fault == "osd-type" {
			data[0] = 0
		}
	} else {
		if h[32] != 0x7f || h[39] != 192 || (len(p.ahs) != 188 && len(p.ahs) != 196) || binary.BigEndian.Uint16(p.ahs) != 185 || p.ahs[2] != 1 || p.ahs[3] != 0 {
			return errors.New("invalid OSD extended CDB")
		}
		b := append(bytes.Clone(h[32:]), p.ahs[4:188]...)
		if b[82] == 3 {
			return s.serveSecureObject(c, p, response, b)
		}
		if b[11] != 0x30 || b[80] > 1 || b[82] != 0 || word(b, 192) != ^uint32(0) || word(b, 196) != ^uint32(0) {
			return errors.New("invalid OSD options/security")
		}
		partition, object := binary.BigEndian.Uint64(b[16:]), binary.BigEndian.Uint64(b[24:])
		key := [2]uint64{partition, object}
		switch binary.BigEndian.Uint16(b[8:]) {
		case 0x880e:
			bidi = true
			if h[1] != 0xe1 || len(p.ahs) != 196 || binary.BigEndian.Uint16(p.ahs[188:]) != 5 || p.ahs[190] != 2 || p.ahs[191] != 0 || word(b, 52) != 12 || word(b, 56) != 0 || word(b, 64) != 0 || word(b, 68) != 0 || word(b, 72) != ^uint32(0) || word(h, 20) != 12 {
				return errors.New("invalid OSD list/bidirectional geometry")
			}
			if s.options.OSDDataFirst {
				// The fixed list header can precede receipt of the query descriptor.
				q := response
				q.header[0] = 0x25
				q.payload = []byte{9, 0, 0, 0}
				binary.BigEndian.PutUint16(q.payload[2:], uint16(word(b, 60)-4))
				set(q.header[:], 36, sn)
				if err := send(c, q); err != nil {
					return err
				}
				sn++
				inputOffset = len(q.payload)
			}
			var descriptor []byte
			for len(descriptor) < 12 {
				n := 12 - len(descriptor)
				if s.options.OSDSplitR2T {
					n = min(n, 8)
				}
				r := response
				r.header[0] = 0x31
				set(r.header[:], 20, 77)
				set(r.header[:], 36, sn)
				set(r.header[:], 40, uint32(len(descriptor)))
				set(r.header[:], 44, uint32(n))
				if s.options.Fault == "osd-r2t-sequence" {
					set(r.header[:], 36, 0)
				}
				if err := send(c, r); err != nil {
					return err
				}
				sn++
				q, err := receive(c)
				if err != nil {
					return err
				}
				if q.header[0] != 5 || q.header[1] != 0x80 || word(q.header[:], 16) != word(h, 16) || word(q.header[:], 20) != 77 || word(q.header[:], 28) != stat || word(q.header[:], 36) != 0 || word(q.header[:], 40) != uint32(len(descriptor)) || len(q.payload) != n {
					return errors.New("invalid OSD attribute descriptor transfer")
				}
				descriptor = append(descriptor, q.payload...)
			}
			if !bytes.Equal(descriptor[:4], []byte{1, 0, 0, 0}) {
				return errors.New("invalid OSD attribute descriptor")
			}
			page, number := word(descriptor, 4), word(descriptor, 8)
			var value []byte
			if partition == 0 && object == 0 && page == 0x90000001 && number == 3 {
				value = bytes.Clone(s.options.OSDSystemID)
				if s.options.Fault == "osd-id" {
					value[0] ^= 1
				}
			} else if partition == 0 && object == 0 && page == 0x90000001 && number == 9 {
				value = bytes.Clone(s.options.OSDName)
			} else if partition >= 0x10000 && object >= 0x10000 && page == 1 && number == 0x82 {
				value = make([]byte, 8)
				binary.BigEndian.PutUint64(value, uint64(len(s.options.OSDObjects[key])))
			} else {
				return errors.New("unexpected OSD attribute query")
			}
			data = make([]byte, 14+len(value))
			data[0] = 9
			binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
			set(data, 4, page)
			set(data, 8, number)
			binary.BigEndian.PutUint16(data[12:], uint16(len(value)))
			copy(data[14:], value)
			if word(b, 60) != uint32(len(data)) || word(p.ahs, 192) != uint32(len(data)) {
				return errors.New("incorrect OSD attribute allocation")
			}
			if s.options.Fault == "osd-attribute" {
				data[0] = 1
			}
		case 0x8805:
			if len(p.ahs) != 188 || h[1] != 0xc1 || partition < 0x10000 || object < 0x10000 || word(b, 52) != 0 || word(b, 56) != ^uint32(0) || word(b, 60) != 0 || word(b, 64) != ^uint32(0) || word(b, 68) != 0 || word(b, 72) != ^uint32(0) {
				return errors.New("invalid OSD read CDB")
			}
			n, off := binary.BigEndian.Uint64(b[36:]), binary.BigEndian.Uint64(b[44:])
			objectData := s.options.OSDObjects[key]
			if n == 0 || n > 65536 || off > uint64(len(objectData)) || n > uint64(len(objectData))-off || word(h, 20) != uint32(n) {
				return errors.New("invalid OSD read bounds")
			}
			if s.options.Fault == "osd-drop" {
				return c.Close()
			}
			data = bytes.Clone(objectData[off : off+n])
		default:
			return errors.New("unexpected OSD service action")
		}
	}
	dataPDUs := 0
	for off := inputOffset; off < len(data); {
		n := min(512, len(data)-off)
		q := response
		q.header[0] = 0x25
		q.header[1] = 0
		if off+n == len(data) || s.options.ReadSequencePDUs > 0 && (dataPDUs+1)%s.options.ReadSequencePDUs == 0 {
			q.header[1] = 0x80
		}
		set(q.header[:], 36, sn)
		set(q.header[:], 40, uint32(off))
		q.payload = data[off : off+n]
		if s.options.Fault == "osd-data-sequence" {
			set(q.header[:], 36, sn+1)
		}
		if bidi && s.options.Fault == "osd-data-counter-reset" {
			set(q.header[:], 36, uint32(dataPDUs))
		}
		if bidi && s.options.Fault == "osd-data-in-status" {
			q.header[1] |= 1
		}
		if err := send(c, q); err != nil {
			return err
		}
		sn++
		dataPDUs++
		off += n
	}
	set(response.header[:], 36, sn)
	if bidi && s.options.Fault == "osd-response-sequence" {
		set(response.header[:], 36, sn-1)
	}
	if bidi && s.options.Fault == "osd-residual" {
		set(response.header[:], 40, 1)
	}
	return send(c, response)
}
