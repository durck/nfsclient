package iscsi

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
)

const maxSegment = 65536

type pdu struct {
	h    [48]byte
	data []byte
	ahs  []byte
}

func (p *pdu) word(offset int) uint32   { return binary.BigEndian.Uint32(p.h[offset : offset+4]) }
func (p *pdu) set(offset int, n uint32) { binary.BigEndian.PutUint32(p.h[offset:offset+4], n) }

func readPDU(r io.Reader) (p pdu, err error) {
	return readDigestPDU(r, false, false)
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

func readDigestPDU(r io.Reader, headerDigest, dataDigest bool) (p pdu, err error) {
	if _, err = io.ReadFull(r, p.h[:]); err != nil {
		return p, err
	}
	if headerDigest {
		var digest [4]byte
		if _, err = io.ReadFull(r, digest[:]); err != nil {
			return p, err
		}
		if binary.LittleEndian.Uint32(digest[:]) != crc32.Checksum(p.h[:], crcTable) {
			return p, errors.New("iSCSI header digest mismatch")
		}
	}
	n := int(p.h[5])<<16 | int(p.h[6])<<8 | int(p.h[7])
	if p.h[4] != 0 || n > maxSegment {
		return p, errors.New("unsupported iSCSI AHS or oversized data segment")
	}
	b := make([]byte, (n+3)&^3)
	if _, err = io.ReadFull(r, b); err != nil {
		return p, err
	}
	if dataDigest && n != 0 {
		var digest [4]byte
		if _, err = io.ReadFull(r, digest[:]); err != nil {
			return p, err
		}
		if binary.LittleEndian.Uint32(digest[:]) != crc32.Checksum(b, crcTable) {
			return p, errors.New("iSCSI data digest mismatch")
		}
	}
	// Padding is excluded from the payload; receivers must ignore its contents.
	p.data = b[:n]
	return p, nil
}

func writePDU(w io.Writer, p pdu) error {
	return writeDigestPDU(w, p, false, false)
}

func writeDigestPDU(w io.Writer, p pdu, headerDigest, dataDigest bool) error {
	if len(p.data) > maxSegment || len(p.ahs) > 248 || len(p.ahs)%4 != 0 || len(p.ahs) != 0 && p.h[0] != 1 {
		return errors.New("oversized outgoing iSCSI segment")
	}
	n := len(p.data)
	p.h[4] = byte(len(p.ahs) / 4)
	p.h[5] = byte(n >> 16)
	p.h[6] = byte(n >> 8)
	p.h[7] = byte(n)
	headerLen := 48 + len(p.ahs)
	dataOffset := headerLen
	if headerDigest {
		dataOffset += 4
	}
	total := dataOffset + ((n + 3) &^ 3)
	if dataDigest && n != 0 {
		total += 4
	}
	b := make([]byte, total)
	defer clear(b)
	copy(b, p.h[:])
	copy(b[48:], p.ahs)
	if headerDigest {
		binary.LittleEndian.PutUint32(b[headerLen:], crc32.Checksum(b[:headerLen], crcTable))
	}
	copy(b[dataOffset:], p.data)
	if dataDigest && n != 0 {
		binary.LittleEndian.PutUint32(b[total-4:], crc32.Checksum(b[dataOffset:total-4], crcTable))
	}
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
