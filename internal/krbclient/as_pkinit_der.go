package client

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"math/big"
	"sort"
)

// PKINIT uses DER, including CMS's IMPLICIT fields. Keep the parser bounded and
// reject extra values, indefinite lengths, and non-canonical integer encodings.
func pkDER(tag byte, content []byte) []byte {
	out := []byte{tag}
	if len(content) < 128 {
		out = append(out, byte(len(content)))
	} else {
		n, length := len(content), []byte{}
		for n != 0 {
			length = append([]byte{byte(n)}, length...)
			n >>= 8
		}
		out = append(out, byte(0x80|len(length)))
		out = append(out, length...)
	}
	return append(out, content...)
}
func pkJoin(tag byte, values ...[]byte) []byte { return pkDER(tag, bytes.Join(values, nil)) }
func pkSeq(values ...[]byte) []byte            { return pkJoin(0x30, values...) }
func pkSet(values ...[]byte) []byte {
	sort.Slice(values, func(i, j int) bool { return bytes.Compare(values[i], values[j]) < 0 })
	return pkJoin(0x31, values...)
}
func pkOID(s string) []byte {
	var oid asn1.ObjectIdentifier
	// Only constant OIDs constructed by this package reach this function.
	for _, component := range bytes.Split([]byte(s), []byte{'.'}) {
		value := 0
		for _, c := range component {
			value = value*10 + int(c-'0')
		}
		oid = append(oid, value)
	}
	b, _ := asn1.Marshal(oid)
	return b
}
func pkInt(n *big.Int) []byte { b, _ := asn1.Marshal(n); return b }
func pkNumber(n int64) []byte { return pkInt(big.NewInt(n)) }
func pkValue(data []byte, tag byte) (asn1.RawValue, error) {
	var v asn1.RawValue
	if len(data) == 0 || len(data) > 1<<20 || data[0] != tag {
		return v, errors.New("PKINIT DER tag/size mismatch")
	}
	rest, err := asn1.Unmarshal(data, &v)
	if err != nil || len(rest) != 0 {
		return v, errors.New("PKINIT DER framing mismatch")
	}
	return v, nil
}
func pkFields(data []byte, tag byte) ([][]byte, error) {
	v, err := pkValue(data, tag)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for len(v.Bytes) != 0 {
		if len(out) >= 64 {
			return nil, errors.New("too many PKINIT DER fields")
		}
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(v.Bytes, &field)
		if err != nil || len(rest) >= len(v.Bytes) {
			return nil, errors.New("invalid PKINIT DER field")
		}
		out = append(out, field.FullBytes)
		v.Bytes = rest
	}
	return out, nil
}
func pkUnsigned(data []byte) (*big.Int, error) {
	var n *big.Int
	rest, err := asn1.Unmarshal(data, &n)
	if err != nil || len(rest) != 0 || n == nil || n.Sign() < 0 {
		return nil, errors.New("invalid PKINIT unsigned integer")
	}
	return n, nil
}
func pkExplicitNumber(data []byte, tag byte) (*big.Int, error) {
	v, err := pkValue(data, tag)
	if err != nil {
		return nil, err
	}
	return pkUnsigned(v.Bytes)
}
