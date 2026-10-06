package iscsi

import (
	"bytes"
	"crypto/md5" // CHAP algorithm 5, mandated by the iSCSI profile.
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type loginState struct {
	v      *Volume
	isid   [6]byte
	rounds int
}

func (l *loginState) exchange(flags byte, text string, allowWait bool) (map[string]string, bool, error) {
	l.rounds++
	if l.rounds > 6 || len(text) > 8192 {
		return nil, false, errors.New("iSCSI login negotiation bound exceeded")
	}
	var req pdu
	req.h[0], req.h[1] = 0x43, flags
	copy(req.h[8:14], l.isid[:])
	req.set(16, 1)
	req.set(24, l.v.cmd)
	req.set(28, l.v.stat)
	req.data = []byte(text)
	defer clear(req.data)
	if err := writePDU(l.v.conn, req); err != nil {
		return nil, false, err
	}
	resp, err := readPDU(l.v.conn)
	if err != nil {
		return nil, false, err
	}
	defer clear(resp.data)
	validFlags := resp.h[1] == flags || allowWait && flags == 0x81 && resp.h[1] == 0
	final := flags == 0x87
	if resp.h[0] != 0x23 || !validFlags || resp.h[2] != 0 || resp.h[3] != 0 || !bytes.Equal(resp.h[8:14], l.isid[:]) || resp.word(16) != 1 || resp.h[36] != 0 || resp.h[37] != 0 || !final && binary.BigEndian.Uint16(resp.h[14:16]) != 0 || final && binary.BigEndian.Uint16(resp.h[14:16]) == 0 {
		return nil, false, errors.New("iSCSI login rejected or mismatched; authentication changes and redirects refused")
	}
	if l.rounds > 1 && resp.word(24) != l.v.stat {
		return nil, false, errors.New("incorrect login StatSN")
	}
	l.v.stat = resp.word(24) + 1
	if err = l.v.window(resp); err != nil {
		return nil, false, err
	}
	keys := map[string]string{}
	if len(resp.data) != 0 {
		keys, err = loginText(resp.data)
		if err != nil {
			return nil, false, err
		}
	}
	if value, ok := keys["TargetPortalGroupTag"]; ok {
		if _, err := strconv.ParseUint(value, 10, 16); err != nil {
			return nil, false, errors.New("invalid portal group tag")
		}
		delete(keys, "TargetPortalGroupTag")
	}
	return keys, resp.h[1]&0x80 != 0, nil
}

func onlyKeys(keys map[string]string, allowed ...string) error {
	for k := range keys {
		found := false
		for _, a := range allowed {
			found = found || a == k
		}
		if !found {
			return errors.New("unexpected iSCSI security login key")
		}
	}
	return nil
}

func chapBinary(s string) ([]byte, error) {
	if len(s) > 2050 || len(s) < 3 {
		return nil, errors.New("invalid CHAP binary value")
	}
	var b []byte
	var err error
	switch s[:2] {
	case "0x", "0X":
		digits := s[2:]
		if len(digits)%2 != 0 {
			digits = "0" + digits
		}
		b, err = hex.DecodeString(digits)
	case "0b", "0B":
		b, err = base64.StdEncoding.Strict().DecodeString(s[2:])
	default:
		return nil, errors.New("CHAP binary value requires hex or base64")
	}
	if err != nil || len(b) > 1024 {
		return nil, errors.New("invalid CHAP binary encoding")
	}
	return b, nil
}

// RFC 7143 section 6.1 permits decimal and hexadecimal numerical values,
// excluding octal, signs, binary notation and digit separators.
func iscsiNumber(s string, bits int) (uint64, error) {
	digits, base := s, 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		digits = s[2:]
		base = 16
	} else if len(s) > 1 && s[0] == '0' {
		return 0, errors.New("invalid iSCSI numerical value")
	}
	if digits == "" {
		return 0, errors.New("empty iSCSI numerical value")
	}
	for _, c := range []byte(digits) {
		if c >= '0' && c <= '9' || base == 16 && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			continue
		}
		return 0, errors.New("invalid iSCSI numerical value")
	}
	return strconv.ParseUint(digits, base, bits)
}
func chapResponse(id byte, secret, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{id})
	h.Write(secret)
	h.Write(challenge)
	return h.Sum(nil)
}

func (v *Volume) loginSecurity(initiator string, policy Security, secret, targetSecret []byte) error {
	if err := v.deadline(); err != nil {
		return err
	}
	l := loginState{v: v}
	if _, err := rand.Read(l.isid[:]); err != nil {
		return err
	}
	l.isid[0] = 0x80
	base := "InitiatorName=" + initiator + "\x00TargetName=" + v.target.Name + "\x00SessionType=Normal\x00AuthMethod="
	if len(secret) == 0 {
		keys, _, err := l.exchange(0x81, base+"None\x00", false)
		if err != nil {
			return err
		}
		if keys["AuthMethod"] != "None" {
			return errors.New("iSCSI authentication policy mismatch")
		}
		if err = onlyKeys(keys, "AuthMethod"); err != nil {
			return err
		}
	} else {
		keys, _, err := l.exchange(0, base+"CHAP\x00", false)
		if err != nil {
			return err
		}
		if keys["AuthMethod"] != "CHAP" {
			return errors.New("required CHAP was not selected")
		}
		if err = onlyKeys(keys, "AuthMethod"); err != nil {
			return err
		}
		keys, _, err = l.exchange(0, "CHAP_A=5\x00", false)
		if err != nil {
			return err
		}
		if err = onlyKeys(keys, "CHAP_A", "CHAP_I", "CHAP_C"); err != nil {
			return err
		}
		algorithm, err := iscsiNumber(keys["CHAP_A"], 64)
		if err != nil || algorithm != 5 {
			return errors.New("required CHAP algorithm was not selected")
		}
		id, err := iscsiNumber(keys["CHAP_I"], 8)
		if err != nil {
			return errors.New("invalid CHAP identifier")
		}
		challenge, err := chapBinary(keys["CHAP_C"])
		if err != nil || len(challenge) < 16 {
			return errors.New("CHAP challenge must contain 16..1024 bytes")
		}
		response := chapResponse(byte(id), secret, challenge)
		defer clear(response)
		text := "CHAP_N=" + policy.Username + "\x00CHAP_R=0x" + hex.EncodeToString(response) + "\x00"
		var mutual [33]byte
		if len(targetSecret) != 0 {
			if _, err = rand.Read(mutual[:]); err != nil {
				return err
			}
			if bytes.Equal(mutual[1:], challenge) {
				return errors.New("CHAP reflection refused")
			}
			text += "CHAP_I=" + strconv.Itoa(int(mutual[0])) + "\x00CHAP_C=0x" + hex.EncodeToString(mutual[1:]) + "\x00"
		}
		keys, done, err := l.exchange(0x81, text, true)
		if err != nil {
			return err
		}
		if len(targetSecret) != 0 {
			if err = onlyKeys(keys, "CHAP_N", "CHAP_R"); err != nil {
				return err
			}
			got, err := chapBinary(keys["CHAP_R"])
			if err != nil || len(got) != md5.Size || keys["CHAP_N"] != policy.TargetUsername {
				return errors.New("mutual CHAP target authentication failed")
			}
			defer clear(got)
			want := chapResponse(mutual[0], targetSecret, mutual[1:])
			reflected := chapResponse(mutual[0], secret, mutual[1:])
			defer clear(want)
			defer clear(reflected)
			if subtle.ConstantTimeCompare(got, want) != 1 || subtle.ConstantTimeCompare(got, reflected) == 1 || subtle.ConstantTimeCompare(got, response) == 1 {
				return errors.New("mutual CHAP target authentication failed")
			}
		} else if err = onlyKeys(keys); err != nil {
			return err
		}
		if !done {
			keys, _, err = l.exchange(0x81, "", false)
			if err != nil {
				return err
			}
			if err = onlyKeys(keys); err != nil {
				return err
			}
		}
	}
	text := "HeaderDigest=" + digestName(policy.HeaderDigest) + "\x00DataDigest=" + digestName(policy.DataDigest) + "\x00MaxConnections=1\x00InitialR2T=Yes\x00ImmediateData=No\x00MaxRecvDataSegmentLength=65536\x00MaxBurstLength=65536\x00FirstBurstLength=65536\x00MaxOutstandingR2T=1\x00DataPDUInOrder=Yes\x00DataSequenceInOrder=Yes\x00ErrorRecoveryLevel=0\x00"
	keys, _, err := l.exchange(0x87, text, false)
	if err != nil {
		return err
	}
	defaults := map[string]string{"HeaderDigest": "None", "DataDigest": "None", "MaxConnections": "1", "InitialR2T": "Yes", "ImmediateData": "Yes", "MaxBurstLength": "262144", "FirstBurstLength": "65536", "MaxOutstandingR2T": "1", "DataPDUInOrder": "Yes", "DataSequenceInOrder": "Yes", "ErrorRecoveryLevel": "0"}
	for key, value := range keys {
		if key == "MaxRecvDataSegmentLength" {
			n, e := strconv.Atoi(value)
			if e != nil || n < 512 || n > 16777215 {
				return errors.New("invalid target receive limit")
			}
			v.recv = min(n, maxSegment)
			continue
		}
		if _, ok := defaults[key]; !ok {
			return errors.New("unsupported operational login key")
		}
		defaults[key] = value
	}
	for key, want := range map[string]string{"HeaderDigest": digestName(policy.HeaderDigest), "DataDigest": digestName(policy.DataDigest), "MaxConnections": "1", "InitialR2T": "Yes", "ImmediateData": "No", "MaxOutstandingR2T": "1", "DataPDUInOrder": "Yes", "DataSequenceInOrder": "Yes", "ErrorRecoveryLevel": "0"} {
		if defaults[key] != want {
			return fmt.Errorf("required iSCSI %s was not negotiated", key)
		}
	}
	for _, key := range []string{"MaxBurstLength", "FirstBurstLength"} {
		n, e := strconv.Atoi(defaults[key])
		if e != nil || n < 512 || n > maxSegment || key == "MaxBurstLength" && n != maxSegment {
			return errors.New("unsupported negotiated iSCSI burst bound")
		}
	}
	v.headerDigest = policy.HeaderDigest == "crc32c"
	v.dataDigest = policy.DataDigest == "crc32c"
	return nil
}
