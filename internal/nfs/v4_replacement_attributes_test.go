package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
)

func runReplacementAttributes(t *testing.T, minor uint32, mode, security string, secure bool) {
	t.Helper()
	named := mode != "xattr"
	xattrs := minor == 2 && mode != "named"
	base := replacementTestAttrs()
	base[4] = replacementTestU64(0)
	base[12] = replacementTestACL(replacementTestACE{0, 0, 0x1f01ff, "OWNER@"})
	base[33] = replacementTestU32(0600)
	oldX, newX := map[string][]byte{}, map[string][]byte{}
	oldNames, newNames := map[string][]byte{}, map[string][]byte{}
	if xattrs {
		oldX["user.binary"] = []byte{0, 255, 1}
		oldX["user.empty"] = []byte{}
	}
	if named {
		oldNames["binary"] = bytes.Repeat([]byte{0, 255, 1}, 400)
		oldNames["empty"] = []byte{}
	}
	if mode == "budget" {
		oldX = map[string][]byte{}
		for i := 0; i < 17; i++ {
			oldX[fmt.Sprintf("user.%02d", i)] = make([]byte, 65536)
		}
	}
	if mode == "named-large" {
		oldNames["binary"] = make([]byte, 65537)
	}
	if mode == "stage-extra-xattr" {
		newX["user.extra"] = []byte("inherited")
	}
	if mode == "stage-extra-named" {
		newNames["extra"] = []byte("inherited")
	}
	changes := map[string]uint64{}
	current := ""
	setCalls, writeCalls, createCalls := 0, 0, 0
	var v *v4Client
	namesOf := func(m map[string][]byte) []string {
		n := make([]string, 0, len(m))
		for k := range m {
			n = append(n, k)
		}
		sort.Strings(n)
		return n
	}
	fields := func(fh string) map[uint32]encoder {
		a := map[uint32]encoder{}
		for k, b := range base {
			a[k] = bytes.Clone(b)
		}
		a[3] = replacementTestU64(7 + changes[fh])
		a[7] = replacementTestU32(0)
		bits := []uint32{0, 1, 3, 4, 7, 12, 13, 33, 36, 37}
		if minor == 2 {
			bits = append(bits, 82)
			a[82] = replacementTestU32(0)
		}
		if fh == "original" || fh == "stage" {
			m := oldNames
			if fh == "stage" {
				m = newNames
			}
			if len(m) > 0 {
				a[7] = replacementTestU32(1)
			}
			if xattrs {
				a[82] = replacementTestU32(1)
			}
		}
		if strings.HasSuffix(fh, "-dir") {
			a[1] = replacementTestU32(8)
		}
		if strings.HasPrefix(fh, "original-attr:") || strings.HasPrefix(fh, "stage-attr:") {
			a[1] = replacementTestU32(9)
			m := oldNames
			name := strings.TrimPrefix(fh, "original-attr:")
			if strings.HasPrefix(fh, "stage-attr:") {
				m = newNames
				name = strings.TrimPrefix(fh, "stage-attr:")
			}
			size := len(m[name])
			if mode == "named-size-mismatch" && strings.HasPrefix(fh, "original") {
				size++
			}
			a[4] = replacementTestU64(uint64(size))
			if mode == "named-policy-change" && strings.HasPrefix(fh, "stage") && changes[fh] > 0 {
				a[36] = replacementTestString("different@example.test")
			}
		}
		var b encoder
		bitmap4(&b, bits...)
		a[0] = b
		return a
	}
	v = peer4WithHandle(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 9:
			return replacementTestReply(readBitmap4(d), fields(current)), 0, nil
		case 19:
			create := d.boolean()
			if current != "original" && current != "stage" {
				return nil, 0, errors.New("recursive OPENATTR")
			}
			if create && current != "stage" {
				return nil, 0, errors.New("OPENATTR modified source")
			}
			current += "-dir"
		case 10:
			e.opaque([]byte(current))
		case 15:
			name := d.str()
			if current == "parent" {
				current = "original"
				break
			}
			if current == "original-dir" {
				current = "original-attr:" + name
			} else if current == "stage-dir" {
				current = "stage-attr:" + name
			} else {
				return nil, 0, errors.New("unexpected attribute lookup")
			}
		case 26:
			cookie := d.u64()
			d.take(8)
			d.u32()
			d.u32()
			if !slices.Equal(readBitmap4(d), []uint32{1, 19}) {
				return nil, 0, errors.New("attribute READDIR requested unrelated metadata")
			}
			m := oldNames
			prefix := "original-attr:"
			if current == "stage-dir" {
				m = newNames
				prefix = "stage-attr:"
			}
			e = append(e, []byte("verifier")...)
			names := namesOf(m)
			if mode == "named-duplicate" && current == "original-dir" {
				names = append(names, names[0])
			}
			for i, name := range names {
				e.u32(1)
				e.u64(uint64(i + 1))
				if mode == "named-cookie-loop" {
					e[len(e)-1] = byte(cookie)
				}
				e.str(name)
				var value encoder
				value.u32(9)
				value.opaque([]byte(prefix + name))
				if mode == "named-missing-handle" && current == "original-dir" {
					bitmap4(&e, 1)
					e.opaque(replacementTestU32(9))
				} else {
					bitmap4(&e, 1, 19)
					e.opaque(value)
				}
			}
			e.u32(0)
			if mode == "named-cookie-loop" && current == "original-dir" {
				e.u32(0)
			} else {
				e.u32(1)
			}
		case 18:
			d.u32()
			share, deny := d.u32(), d.u32()
			d.u64()
			d.opaque(128)
			create := d.u32()
			if create == 1 {
				createCalls++
				if current != "stage-dir" || d.u32() != 1 || !slices.Equal(readBitmap4(d), []uint32{33}) || !bytes.Equal(d.opaque(64), replacementTestU32(0600)) {
					return nil, 0, errors.New("nonprivate named create")
				}
			}
			if d.u32() != 0 || deny != 0 {
				return nil, 0, errors.New("bad attribute OPEN claim")
			}
			name := d.str()
			if current == "original-dir" {
				if create != 0 || share != 1 {
					return nil, 0, errors.New("source attr modification")
				}
				current = "original-attr:" + name
			} else if current == "stage-dir" {
				if (share != 1 && share != 2) || (create == 1 && share != 2) {
					return nil, 0, errors.New("invalid stage attribute access")
				}
				current = "stage-attr:" + name
				if create == 1 {
					if _, ok := newNames[name]; ok {
						return nil, 17, nil
					}
					newNames[name] = []byte{}
					changes["stage"]++
					changes["stage-dir"]++
				}
			} else {
				return nil, 0, errors.New("bad OPEN parent")
			}
			e = append(e, bytes.Repeat([]byte{7}, 16)...)
			e.u32(1)
			e.u64(1)
			e.u64(1)
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 25:
			d.take(16)
			off, count := d.u64(), d.u32()
			if !strings.HasPrefix(current, "original-attr:") && !strings.HasPrefix(current, "stage-attr:") {
				return nil, 0, errors.New("unexpected attribute READ")
			}
			data := oldNames[strings.TrimPrefix(current, "original-attr:")]
			if strings.HasPrefix(current, "stage-attr:") {
				data = newNames[strings.TrimPrefix(current, "stage-attr:")]
			}
			if off > uint64(len(data)) {
				return nil, 0, errors.New("READ beyond attribute")
			}
			n := min(uint64(count), uint64(len(data))-off)
			e.u32(1)
			e.opaque(data[off : off+n])
		case 38:
			writeCalls++
			d.take(16)
			off := d.u64()
			if d.u32() != 2 || !strings.HasPrefix(current, "stage-attr:") {
				return nil, 0, errors.New("unstable/outside-stage attr WRITE")
			}
			name := strings.TrimPrefix(current, "stage-attr:")
			data := d.opaque(65536)
			if off != uint64(len(newNames[name])) {
				return nil, 0, errors.New("attr WRITE offset")
			}
			newNames[name] = append(newNames[name], data...)
			changes[current]++
			if mode == "named-data-change" && len(newNames[name]) > 0 {
				newNames[name][0] ^= 1
			}
			e.u32(uint32(len(data)))
			e.u32(2)
			e = append(e, []byte("verifier")...)
		case 4:
			d.u32()
			e = append(e, d.take(16)...)
		case 74:
			d.u64()
			d.u32()
			m := oldX
			if current == "stage" {
				m = newX
			}
			names := namesOf(m)
			if mode == "xattr-duplicate" && current == "original" {
				names = append(names, names[0])
			}
			e.u64(0)
			e.u32(uint32(len(names)))
			for _, name := range names {
				e.str(name)
			}
			e.u32(1)
		case 72:
			name := d.str()
			m := oldX
			if current == "stage" {
				m = newX
			}
			value, ok := m[name]
			if !ok || mode == "xattr-missing" {
				return nil, 10095, nil
			}
			if mode == "xattr-changed" && current == "original" {
				changes[current]++
			}
			if mode == "xattr-readback" && current == "stage" {
				value = []byte("wrong")
			}
			e.opaque(value)
		case 73:
			setCalls++
			if current != "stage" || d.u32() != 1 {
				return nil, 0, errors.New("xattr mutation outside private stage or without CREATE")
			}
			name := d.str()
			value := d.opaque(65536)
			if mode == "xattr-denied" {
				return nil, 13, nil
			}
			if _, ok := newX[name]; ok {
				return nil, 10096, nil
			}
			if !bytes.Equal(value, oldX[name]) {
				return nil, 0, errors.New("xattr value changed")
			}
			newX[name] = bytes.Clone(value)
			changes[current]++
			e.u32(1)
			e.u64(1)
			e.u64(2)
		case 34:
			if current != "stage" && !strings.HasPrefix(current, "stage-attr:") {
				return nil, 0, errors.New("metadata mutation outside stage")
			}
			d.take(16)
			bits := readBitmap4(d)
			value := d.opaque(65536)
			var expected encoder
			for _, bit := range bits {
				expected = append(expected, base[bit]...)
			}
			if !bytes.Equal(value, expected) {
				return nil, 0, errors.New("named policy was not preserved")
			}
			bitmap4(&e, bits...)
		case 3:
			d.u32()
			e.u32(63)
			e.u32(13)
		default:
			return nil, 0, fmt.Errorf("unexpected attribute operation %d", code)
		}
		return e, 0, nil
	}, func(fh []byte) error { current = string(fh); return nil })
	if security != "" {
		opts := mitTLSOptions{expectedService: map[string]uint32{"krb5i": 2, "krb5p": 3}[security]}
		if secure {
			policy, server := pnfsTLSFixture(t, "data")
			opts.client, opts.server = policy, server(0)
		}
		pnfsMITWrapClient(t, v.c, security, nil, opts)
	}
	ctx := context.Background()
	m, err := v.c.CaptureV4Replacement(ctx, []byte("original"))
	if err == nil {
		err = v.c.CheckV4ReplacementStage(ctx, []byte("stage"), m)
	}
	if err == nil {
		err = v.c.ApplyV4Replacement(ctx, []byte("stage"), m)
	}
	if err == nil {
		err = v.c.VerifyV4ReplacementSource(ctx, []byte("parent"), "target", m)
	}
	ok := mode == "named" || mode == "xattr" || mode == "both"
	if (err == nil) != ok {
		t.Fatal(mode, err, setCalls, createCalls, writeCalls)
	}
	if ok {
		if !reflectAttributeMaps(oldX, newX) || !reflectAttributeMaps(oldNames, newNames) {
			t.Fatal("attributes changed")
		}
		if xattrs && setCalls != len(oldX) {
			t.Fatal("xattr replay")
		}
		if named && createCalls != len(oldNames) {
			t.Fatal("named create replay")
		}
	}
}

func reflectAttributeMaps(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for n, v := range a {
		other, ok := b[n]
		if !ok || !bytes.Equal(v, other) {
			return false
		}
	}
	return true
}
func TestReplacementAttributes(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"named", "xattr", "both", "budget", "named-large", "named-size-mismatch", "named-duplicate", "named-missing-handle", "named-cookie-loop", "named-policy-change", "named-data-change", "xattr-duplicate", "xattr-changed", "xattr-missing", "xattr-denied", "xattr-readback", "stage-extra-xattr", "stage-extra-named"} {
			if minor == 1 && mode != "named" && !strings.HasPrefix(mode, "named-") && mode != "stage-extra-named" {
				continue
			}
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runReplacementAttributes(t, minor, mode, "", false) })
		}
	}
}
func TestMITReplacementAttributes(t *testing.T) {
	for _, security := range []string{"krb5i", "krb5p"} {
		for _, secure := range []bool{false, true} {
			for _, mode := range []string{"both", "xattr-changed", "xattr-denied", "named-data-change", "named-policy-change", "stage-extra-named"} {
				t.Run(fmt.Sprintf("%s/tls=%t/%s", security, secure, mode), func(t *testing.T) { runReplacementAttributes(t, 2, mode, security, secure) })
			}
		}
	}
}
