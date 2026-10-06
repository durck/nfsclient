package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func replacementExtendedAttrs(mode string) map[uint32]encoder {
	a := replacementTestAttrs()
	bits := []uint32{0, 1, 3, 7, 12, 13, 33, 36, 37}
	if mode == "dacl" || mode == "all" {
		bits = append(bits, 58)
		a[58] = append(replacementTestU32(3), replacementTestACL(replacementTestACE{0, 0x80, 7, "OWNER@"}, replacementTestACE{1, 0, 2, "EVERYONE@"})...)
		a[12] = replacementTestACL(replacementTestACE{0, 0, 7, "OWNER@"}, replacementTestACE{1, 0, 2, "EVERYONE@"})
	}
	if mode == "sacl" || mode == "all" {
		bits = append(bits, 59)
		a[59] = append(replacementTestU32(5), replacementTestACL(replacementTestACE{2, 0x90, 1, "EVERYONE@"}, replacementTestACE{3, 0x20, 2, "OWNER@"})...)
		audit := replacementTestACL(replacementTestACE{2, 0x10, 1, "EVERYONE@"}, replacementTestACE{3, 0x20, 2, "OWNER@"})
		a[12] = append(bytes.Clone(a[12]), audit[4:]...)
		count := uint32(6)
		if mode == "all" {
			count = 4
		}
		copy(a[12][:4], replacementTestU32(count))
		a[13] = replacementTestU32(15)
	}
	if mode == "label" || mode == "all" {
		bits = append(bits, 80)
		var e encoder
		e.u32(7)
		e.u32(42)
		e.opaque([]byte{0, 255, 'a'})
		a[80] = e
	}
	if mode == "setuid" {
		a[33] = replacementTestU32(04640)
	}
	if mode == "setgid" {
		a[33] = replacementTestU32(02640)
	}
	if mode == "sticky" {
		a[33] = replacementTestU32(01640)
	}
	if mode == "all" {
		a[33] = replacementTestU32(07640)
	}
	slices.Sort(bits)
	var supported encoder
	bitmap4(&supported, bits...)
	a[0] = supported
	return a
}

func runReplacementExtended(t *testing.T, minor uint32, mode, security string, secure bool) {
	t.Helper()
	kind := mode
	switch mode {
	case "foreign", "access-denied", "owner-denied", "bad-owner-ack", "bad-label-readback", "bad-dacl-readback", "bad-sacl-readback", "mode-cleared", "apply-denied", "missing-ack", "source-changed", "stage-changed":
		kind = "all"
	}
	if minor < 2 && (kind == "label" || kind == "all") {
		return
	}
	ctx := context.Background()
	original := replacementExtendedAttrs(kind)
	stage := replacementExtendedAttrs(kind)
	stage[33] = replacementTestU32(0600)
	stage[12] = replacementTestACL(replacementTestACE{0, 0, 7, "OWNER@"})
	if stage[58] != nil {
		stage[58] = append(replacementTestU32(1), replacementTestACL(replacementTestACE{0, 0x80, 7, "OWNER@"})...)
	}
	stage[36] = replacementTestString("uploader@example.test")
	stage[37] = replacementTestString("uploaders@example.test")
	current := ""
	var setters [][]uint32
	v := peer4WithHandle(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 22:
			current = string(d.opaque(128))
		case 15:
			name := d.str()
			current = "original"
			if name == "stage" {
				current = "stage"
			}
		case 10:
			e.opaque([]byte(current))
		case 9:
			fields := original
			if current == "stage" {
				fields = stage
			}
			e = replacementTestReply(readBitmap4(d), fields)
		case 3:
			d.u32()
			e.u32(63)
			access := uint32(13)
			if mode == "access-denied" {
				access = 1
			}
			e.u32(access)
		case 34:
			if current != "stage" || !bytes.Equal(d.take(16), make([]byte, 16)) {
				return nil, 0, errors.New("mutation outside private stage")
			}
			bits := readBitmap4(d)
			setters = append(setters, slices.Clone(bits))
			rawValues := d.opaque(65536)
			var expected encoder
			for _, bit := range bits {
				expected = append(expected, original[bit]...)
			}
			if !bytes.Equal(rawValues, expected) {
				return nil, 0, errors.New("replacement wire values differ from original")
			}
			values := &decoder{b: rawValues}
			if reflect.DeepEqual(bits, []uint32{36, 37}) {
				if mode == "owner-denied" {
					bitmap4(&e)
					return e, 1, nil
				}
				owner, group := values.str(), values.str()
				if owner != "alice@example.test" || group != "staff@example.test" {
					return nil, 0, errors.New("ownership not copied")
				}
				stage[36] = replacementTestString(owner)
				stage[37] = replacementTestString(group)
				stage[33] = replacementTestU32(0600)
				if mode == "bad-owner-ack" {
					bitmap4(&e, 36)
					return e, 0, nil
				}
			} else {
				if mode == "apply-denied" {
					bitmap4(&e)
					return e, 13, nil
				}
				for _, bit := range bits {
					stage[bit] = bytes.Clone(original[bit])
				}
				values.b = nil
				// DACL/SACL readback must also retain the legacy ACL union.
				stage[12] = bytes.Clone(original[12])
				switch mode {
				case "bad-label-readback":
					stage[80] = append(replacementTestU32(7), replacementTestU32(42)...)
					var x encoder
					x.opaque([]byte("changed"))
					stage[80] = append(stage[80], x...)
				case "bad-dacl-readback":
					stage[58] = replacementTestU32(0)
					stage[58] = append(stage[58], replacementTestU32(0)...)
				case "bad-sacl-readback":
					stage[59] = append(replacementTestU32(0), replacementTestU32(0)...)
				case "mode-cleared":
					stage[33] = replacementTestU32(0640)
				case "source-changed":
					original[3] = replacementTestU64(72)
				}
				if mode == "missing-ack" {
					bitmap4(&e, 33)
					return e, 0, nil
				}
			}
			if values.err != nil || len(values.b) != 0 {
				return nil, 0, errors.New("malformed replacement values")
			}
			bitmap4(&e, bits...)
		default:
			return nil, 0, fmt.Errorf("unexpected metadata operation %d", code)
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
	m, err := v.c.CaptureV4Replacement(ctx, []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	err = v.c.CheckV4ReplacementStage(ctx, []byte("stage"), m)
	if err == nil {
		err = v.c.ApplyV4Replacement(ctx, []byte("stage"), m)
	}
	if err == nil {
		err = v.c.VerifyV4ReplacementSource(ctx, []byte("parent"), "target", m)
	}
	if mode == "stage-changed" {
		stage[36] = replacementTestString("unexpected@example.test")
	}
	if err == nil {
		err = v.c.VerifyV4ReplacementStage(ctx, []byte("parent"), "stage", []byte("stage"), m)
	}
	ok := mode == "dacl" || mode == "sacl" || mode == "label" || mode == "setuid" || mode == "setgid" || mode == "sticky" || mode == "all" || mode == "foreign"
	if (err == nil) != ok {
		t.Fatal(mode, err, setters)
	}
	if ok && (len(setters) != 2 || !reflect.DeepEqual(setters[0], []uint32{36, 37})) {
		t.Fatal("ownership must precede final policy", setters)
	}
	if mode == "access-denied" && len(setters) != 0 {
		t.Fatal("private access refusal mutated")
	}
	if mode == "owner-denied" || mode == "bad-owner-ack" {
		if len(setters) != 1 {
			t.Fatal("uncertain ownership followed by policy")
		}
	}
}

func TestExtendedReplacement(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"dacl", "sacl", "label", "setuid", "setgid", "sticky", "all", "foreign", "access-denied", "owner-denied", "bad-owner-ack", "bad-label-readback", "bad-dacl-readback", "bad-sacl-readback", "mode-cleared", "apply-denied", "missing-ack", "source-changed"} {
			if minor == 1 && mode != "dacl" && mode != "sacl" && mode != "setuid" && mode != "setgid" && mode != "sticky" {
				continue
			}
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runReplacementExtended(t, minor, mode, "", false) })
		}
	}
}
func TestMITExtendedReplacement(t *testing.T) {
	for _, security := range []string{"krb5i", "krb5p"} {
		for _, secure := range []bool{false, true} {
			for _, mode := range []string{"all", "foreign", "owner-denied", "bad-label-readback", "bad-dacl-readback", "source-changed"} {
				t.Run(fmt.Sprintf("%s/tls=%t/%s", security, secure, mode), func(t *testing.T) { runReplacementExtended(t, 2, mode, security, secure) })
			}
		}
	}
}
