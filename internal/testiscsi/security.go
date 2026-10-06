package testiscsi

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Separate bit-at-a-time oracle, independent of the initiator CRC implementation.
func wireCRC(b []byte) uint32 {
	c := ^uint32(0)
	for _, v := range b {
		c ^= uint32(v)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ 0x82f63b78
			} else {
				c >>= 1
			}
		}
	}
	return ^c
}

type digestConnection struct {
	net.Conn
	header, data bool
	fault        string
	corrupted    bool
}

func testCHAP(id byte, secret, challenge []byte) []byte {
	b := append([]byte{id}, secret...)
	b = append(b, challenge...)
	sum := md5.Sum(b)
	return sum[:]
}
func textKeys(b []byte) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(string(b), "\x00") {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

func (s *Target) securityLogin(c net.Conn, stat *uint32) (bool, error) {
	challenge := bytes.Repeat([]byte{0x37}, 32)
	if s.options.Fault == "chap-hex-odd" {
		challenge = bytes.Repeat([]byte{0x37}, 16)
		challenge[0] = 7
	}
	var isid []byte
	for step := 0; step < 3; step++ {
		p, err := receive(c)
		if err != nil {
			return false, err
		}
		flags := byte(0)
		if step == 2 {
			flags = 0x81
		}
		if p.header[0] != 0x43 || p.header[1] != flags || word(p.header[:], 16) != 1 || word(p.header[:], 24) != 1 || step > 0 && (word(p.header[:], 28) != *stat || !bytes.Equal(isid, p.header[8:14])) {
			return false, errors.New("invalid CHAP login sequencing")
		}
		if step == 0 {
			isid = bytes.Clone(p.header[8:14])
		}
		k := textKeys(p.payload)
		var r frame
		r.header[0] = 0x23
		r.header[1] = flags
		copy(r.header[8:14], isid)
		set(r.header[:], 16, 1)
		set(r.header[:], 24, *stat)
		set(r.header[:], 28, 1)
		set(r.header[:], 32, 64)
		switch step {
		case 0:
			if k["AuthMethod"] != "CHAP" || k["InitiatorName"] != Initiator || k["TargetName"] != Name {
				return false, errors.New("missing approved CHAP identity")
			}
			r.payload = []byte("AuthMethod=CHAP\x00")
			if s.options.Fault == "auth-downgrade" {
				r.payload = []byte("AuthMethod=None\x00")
			}
		case 1:
			if k["CHAP_A"] != "5" {
				return false, errors.New("missing CHAP algorithm")
			}
			r.payload = []byte("CHAP_A=5\x00CHAP_I=71\x00CHAP_C=0x" + hex.EncodeToString(challenge) + "\x00")
			if s.options.Fault == "chap-hex-odd" {
				r.payload = []byte("CHAP_A=0x5\x00CHAP_I=0X47\x00CHAP_C=0x" + hex.EncodeToString(challenge)[1:] + "\x00")
			}
			if s.options.Fault == "chap-octal" {
				r.payload = bytes.ReplaceAll(r.payload, []byte("CHAP_I=71"), []byte("CHAP_I=0107"))
			}
			if s.options.Fault == "chap-binary-number" {
				r.payload = bytes.ReplaceAll(r.payload, []byte("CHAP_I=71"), []byte("CHAP_I=0b1000111"))
			}
			if s.options.Fault == "chap-algorithm" {
				r.payload = bytes.ReplaceAll(r.payload, []byte("CHAP_A=5"), []byte("CHAP_A=7"))
			}
			if s.options.Fault == "chap-malformed" {
				r.payload = []byte("CHAP_A=5\x00CHAP_I=71\x00CHAP_C=0xgg\x00")
			}
		case 2:
			if s.options.Fault == "chap-drop" {
				return false, nil
			}
			got, err := hex.DecodeString(strings.TrimPrefix(k["CHAP_R"], "0x"))
			if err != nil || k["CHAP_N"] != s.options.CHAPUsername || !bytes.Equal(got, testCHAP(71, s.options.CHAPSecret, challenge)) {
				r.header[36] = 2
				r.header[37] = 1
				return false, send(c, r)
			}
			if len(s.options.TargetSecret) != 0 {
				id, err := strconv.ParseUint(k["CHAP_I"], 10, 8)
				if err != nil {
					return false, errors.New("missing mutual identifier")
				}
				ch, err := hex.DecodeString(strings.TrimPrefix(k["CHAP_C"], "0x"))
				if err != nil || len(ch) < 16 || bytes.Equal(ch, challenge) {
					return false, errors.New("missing or reflected mutual challenge")
				}
				response := testCHAP(byte(id), s.options.TargetSecret, ch)
				if s.options.Fault == "mutual-reflect" {
					response = testCHAP(byte(id), s.options.CHAPSecret, ch)
				}
				if s.options.Fault == "mutual-wrong" {
					response[0] ^= 1
				}
				r.payload = []byte("CHAP_N=" + s.options.TargetUsername + "\x00CHAP_R=0x" + hex.EncodeToString(response) + "\x00")
			}
		}
		if err = send(c, r); err != nil {
			return false, err
		}
		*stat++
		if s.options.Fault == "auth-downgrade" || step == 1 && (s.options.Fault == "chap-algorithm" || s.options.Fault == "chap-malformed" || s.options.Fault == "chap-octal" || s.options.Fault == "chap-binary-number") || step == 2 && (s.options.Fault == "mutual-reflect" || s.options.Fault == "mutual-wrong") {
			return false, nil
		}
	}
	return true, nil
}

func appendDigest(b []byte, crc uint32) []byte {
	var d [4]byte
	binary.LittleEndian.PutUint32(d[:], crc)
	return append(b, d[:]...)
}
