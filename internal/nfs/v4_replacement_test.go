package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Encode the server's ACL independently of the production ACL codec. Order,
// principal bytes, and flags are policy, not a set that may be sorted.
type replacementTestACE struct {
	kind, flags, mask uint32
	who               string
}

func replacementTestACL(entries ...replacementTestACE) encoder {
	var e encoder
	e.u32(uint32(len(entries)))
	for _, entry := range entries {
		e.u32(entry.kind)
		e.u32(entry.flags)
		e.u32(entry.mask)
		e.str(entry.who)
	}
	return e
}

func replacementTestU32(n uint32) encoder    { var e encoder; e.u32(n); return e }
func replacementTestU64(n uint64) encoder    { var e encoder; e.u64(n); return e }
func replacementTestString(s string) encoder { var e encoder; e.str(s); return e }

func replacementTestAttrs() map[uint32]encoder {
	var supported encoder
	bitmap4(&supported, 0, 1, 3, 7, 12, 13, 33, 36, 37)
	return map[uint32]encoder{
		0: supported, 1: replacementTestU32(1), 3: replacementTestU64(71), 7: replacementTestU32(0),
		12: replacementTestACL(
			replacementTestACE{1, 0, 2, "bob@example.test"},
			replacementTestACE{0, 0, 0x1f01ff, "OWNER@"},
			replacementTestACE{0, 0, 1, "bob@example.test"},
			replacementTestACE{0, 0x40, 1, "readers@example.test"}),
		13: replacementTestU32(3), 33: replacementTestU32(0640),
		36: replacementTestString("alice@example.test"),
		37: replacementTestString("staff@example.test"),
	}
}

func replacementTestReply(wanted []uint32, fields map[uint32]encoder) encoder {
	var bits []uint32
	var values, e encoder
	for _, bit := range wanted {
		if value, ok := fields[bit]; ok {
			bits = append(bits, bit)
			values = append(values, value...)
		}
	}
	bitmap4(&e, bits...)
	e.opaque(values)
	return e
}

func TestV4ReplacementCaptureRejectsUnknownPolicy(t *testing.T) {
	tests := []struct {
		name   string
		change func(map[uint32]encoder)
		status Status
	}{
		{"dacl", func(a map[uint32]encoder) {
			bitmap := encoder(nil)
			bitmap4(&bitmap, 0, 1, 3, 12, 13, 33, 36, 37, 58)
			a[0] = bitmap
		}, 0},
		{"sacl", func(a map[uint32]encoder) {
			bitmap := encoder(nil)
			bitmap4(&bitmap, 0, 1, 3, 12, 13, 33, 36, 37, 59)
			a[0] = bitmap
		}, 0},
		{"security-label", func(a map[uint32]encoder) {
			bitmap := encoder(nil)
			bitmap4(&bitmap, 0, 1, 3, 12, 13, 33, 36, 37, 80)
			a[0] = bitmap
		}, 0},
		{"unknown-aclsupport", func(a map[uint32]encoder) { a[13] = replacementTestU32(0x13) }, 0},
		{"unadvertised-deny", func(a map[uint32]encoder) { a[13] = replacementTestU32(1) }, 0},
		{"directory", func(a map[uint32]encoder) { a[1] = replacementTestU32(2) }, 0},
		{"unknown-mode", func(a map[uint32]encoder) { a[33] = replacementTestU32(010640) }, 0},
		{"empty-owner", func(a map[uint32]encoder) { a[36] = replacementTestString("") }, 0},
		{"invalid-group", func(a map[uint32]encoder) { a[37] = replacementTestString("staff\nforged") }, 0},
		{"access-denied", nil, 13},
		{"attribute-unsupported", nil, 10032},
	}
	for _, bit := range []uint32{0, 1, 3, 12, 13, 33, 36, 37} {
		tests = append(tests, struct {
			name   string
			change func(map[uint32]encoder)
			status Status
		}{
			fmt.Sprintf("omitted-%d", bit), func(a map[uint32]encoder) { delete(a, bit) }, 0})
		tests = append(tests, struct {
			name   string
			change func(map[uint32]encoder)
			status Status
		}{
			fmt.Sprintf("unsupported-%d", bit), func(a map[uint32]encoder) {
				var bits []uint32
				for _, b := range []uint32{0, 1, 3, 12, 13, 33, 36, 37} {
					if b != bit {
						bits = append(bits, b)
					}
				}
				var e encoder
				bitmap4(&e, bits...)
				a[0] = e
			}, 0})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := replacementTestAttrs()
			if test.change != nil {
				test.change(fields)
			}
			calls := 0
			v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
				calls++
				if code != 9 {
					return nil, 0, fmt.Errorf("policy capture mutated the server: operation %d", code)
				}
				bits := readBitmap4(d)
				if test.status != 0 {
					return nil, test.status, nil
				}
				return replacementTestReply(bits, fields), 0, nil
			})
			got, err := v.c.CaptureV4Replacement(context.Background(), []byte("original"))
			if err == nil || got != nil || calls != 1 {
				t.Fatalf("capture=%v err=%v calls=%d", got, err, calls)
			}
			if test.status != 0 && !errors.Is(err, test.status) {
				t.Fatalf("status lost: %v", err)
			}
			if test.name == "unadvertised-deny" && !strings.Contains(err.Error(), "ACL entry type 1 is not advertised by ACL support flags 0x1") {
				t.Fatalf("missing concrete capability diagnosis: %v", err)
			}
		})
	}
}

func TestV4ReplacementCaptureRejectsMalformedACL(t *testing.T) {
	tests := []struct {
		name string
		acl  encoder
	}{
		{"too-many-entries", replacementTestU32(1025)},
		{"truncated-entry", append(replacementTestU32(1), 0, 0, 0)},
	}
	for _, item := range []struct {
		name  string
		entry replacementTestACE
	}{
		{"audit", replacementTestACE{2, 0x10, 1, "OWNER@"}},
		{"unknown-type", replacementTestACE{4, 0, 1, "OWNER@"}},
		{"unknown-flags", replacementTestACE{0, 0x100, 1, "OWNER@"}},
		// RFC 8881 6.4.3.2: this flag is valid in dacl/sacl, never acl.
		{"inherited-flag-in-acl", replacementTestACE{0, 0x80, 1, "OWNER@"}},
		{"unknown-mask", replacementTestACE{0, 0, 0x200000, "OWNER@"}},
		{"empty-principal", replacementTestACE{0, 0, 1, ""}},
		{"control-principal", replacementTestACE{0, 0, 1, "bob\x00@example.test"}},
		{"invalid-utf8", replacementTestACE{0, 0, 1, "bob\xff"}},
		{"long-principal", replacementTestACE{0, 0, 1, strings.Repeat("a", 4097)}},
	} {
		tests = append(tests, struct {
			name string
			acl  encoder
		}{item.name, replacementTestACL(item.entry)})
	}
	var large []replacementTestACE
	for i := 0; i < 17; i++ {
		large = append(large, replacementTestACE{0, 0, 1, strings.Repeat("a", 4096)})
	}
	tests = append(tests, struct {
		name string
		acl  encoder
	}{"attribute-blob-over-64KiB", replacementTestACL(large...)})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := replacementTestAttrs()
			fields[12] = test.acl
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 9 {
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				return replacementTestReply(readBitmap4(d), fields), 0, nil
			})
			if got, err := v.c.CaptureV4Replacement(context.Background(), []byte("original")); err == nil || got != nil {
				t.Fatalf("malformed ACL accepted: snapshot=%v err=%v", got, err)
			}
		})
	}
}

func TestV4ReplacementCaptureAcceptsPresentZeroValues(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			fields := replacementTestAttrs()
			fields[3], fields[12], fields[13], fields[33] = replacementTestU64(0), replacementTestACL(), replacementTestU32(0), replacementTestU32(0)
			v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 9 {
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				return replacementTestReply(readBitmap4(d), fields), 0, nil
			})
			if got, err := v.c.CaptureV4Replacement(context.Background(), []byte("original")); err != nil || got == nil {
				t.Fatalf("present zero-valued policy refused: %v", err)
			}
		})
	}
}

func TestV4ReplacementCaptureFitsNegotiatedReplyPayload(t *testing.T) {
	for _, delta := range []int{-1, 0} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			fields := replacementTestAttrs()
			fields[12] = replacementTestACL(replacementTestACE{0, 0, 1, strings.Repeat("a", 3000) + "@example.test"})
			payloadBytes := 0
			for _, value := range fields {
				payloadBytes += len(value)
			}
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 9 {
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				return replacementTestReply(readBitmap4(d), fields), 0, nil
			})
			v.maxReplyPayload = uint32(payloadBytes + delta)
			v.c.ReadSize = 1 // File READ tuning must not limit GETATTR.
			got, err := v.c.CaptureV4Replacement(context.Background(), []byte("original"))
			if delta < 0 {
				if err == nil || got != nil {
					t.Fatalf("oversized attribute payload accepted: %v %v", got, err)
				}
			} else if err != nil || got == nil {
				t.Fatalf("fitting attribute payload refused: %v", err)
			}
		})
	}
}

func TestV4ReplacementStageRequiresMatchingPrivatePolicy(t *testing.T) {
	tests := []struct {
		name    string
		change  func(map[uint32]encoder)
		allowed bool
	}{
		{"owner-data-only", nil, true},
		{"metadata-read-for-everyone", func(a map[uint32]encoder) {
			a[12] = replacementTestACL(replacementTestACE{0, 0, 7, "OWNER@"}, replacementTestACE{0, 0, 0x80, "EVERYONE@"})
		}, true},
		{"different-owner", func(a map[uint32]encoder) { a[36] = replacementTestString("other@example.test") }, true},
		{"setgid-parent-group", func(a map[uint32]encoder) { a[37] = replacementTestString("project@example.test") }, true},
		{"mode-widened", func(a map[uint32]encoder) { a[33] = replacementTestU32(0640) }, false},
		// RFC 8881 6.2.1.5 requires ignoring the group flag for OWNER@.
		{"owner-marked-as-group", func(a map[uint32]encoder) { a[12] = replacementTestACL(replacementTestACE{0, 0x40, 1, "OWNER@"}) }, true},
		{"deny-before-named-allow", func(a map[uint32]encoder) {
			a[12] = replacementTestACL(replacementTestACE{1, 0, 7, "bob@example.test"}, replacementTestACE{0, 0, 1, "bob@example.test"})
		}, false},
	}
	for _, mask := range []uint32{1, 2, 4} {
		for _, who := range []string{"bob@example.test", "GROUP@", "EVERYONE@"} {
			tests = append(tests, struct {
				name    string
				change  func(map[uint32]encoder)
				allowed bool
			}{
				fmt.Sprintf("nonowner-%s-mask-%d", who, mask), func(a map[uint32]encoder) { a[12] = replacementTestACL(replacementTestACE{0, 0, mask, who}) }, false})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := replacementTestAttrs()
			calls := 0
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				calls++
				if code == 3 {
					d.u32()
					var e encoder
					e.u32(63)
					e.u32(13)
					return e, 0, nil
				}
				if code != 9 {
					return nil, 0, fmt.Errorf("stage validation mutated server: %d", code)
				}
				return replacementTestReply(readBitmap4(d), fields), 0, nil
			})
			original, err := v.c.CaptureV4Replacement(context.Background(), []byte("original"))
			if err != nil {
				t.Fatal(err)
			}
			fields = replacementTestAttrs()
			fields[33] = replacementTestU32(0600)
			fields[12] = replacementTestACL(replacementTestACE{0, 0, 7, "OWNER@"}, replacementTestACE{1, 0, 7, "EVERYONE@"})
			if test.change != nil {
				test.change(fields)
			}
			err = v.c.CheckV4ReplacementStage(context.Background(), []byte("stage"), original)
			wantCalls := 2
			if test.name == "different-owner" || test.name == "setgid-parent-group" {
				wantCalls = 3
			}
			if (err == nil) != test.allowed || calls != wantCalls {
				t.Fatalf("stage allowed=%t error=%v calls=%d", test.allowed, err, calls)
			}
		})
	}
}

func TestV4ReplacementApplyRequiresAcknowledgementAndExactReadback(t *testing.T) {
	tests := []struct {
		name    string
		ack     []uint32
		status  Status
		change  func(map[uint32]encoder)
		allowed bool
	}{
		{"preserved", []uint32{12, 33}, 0, nil, true},
		{"missing-acl-ack", []uint32{33}, 0, nil, false},
		{"missing-mode-ack", []uint32{12}, 0, nil, false},
		{"extra-ack", []uint32{12, 33, 36}, 0, nil, false},
		{"denied", []uint32{33}, 13, nil, false},
		{"mode-changed", []uint32{12, 33}, 0, func(a map[uint32]encoder) { a[33] = replacementTestU32(0600) }, false},
		{"owner-changed", []uint32{12, 33}, 0, func(a map[uint32]encoder) { a[36] = replacementTestString("other@example.test") }, false},
		{"group-changed", []uint32{12, 33}, 0, func(a map[uint32]encoder) { a[37] = replacementTestString("other@example.test") }, false},
		{"acl-dropped", []uint32{12, 33}, 0, func(a map[uint32]encoder) { delete(a, 12) }, false},
		{"acl-reordered", []uint32{12, 33}, 0, func(a map[uint32]encoder) {
			a[12] = replacementTestACL(replacementTestACE{0, 0, 1, "bob@example.test"}, replacementTestACE{1, 0, 2, "bob@example.test"}, replacementTestACE{0, 0, 0x1f01ff, "OWNER@"}, replacementTestACE{0, 0x40, 1, "readers@example.test"})
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := replacementTestAttrs()
			var calls []uint32
			wantValues := append(append(encoder(nil), fields[12]...), fields[33]...)
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				calls = append(calls, code)
				switch code {
				case 9:
					return replacementTestReply(readBitmap4(d), fields), 0, nil
				case 34:
					if !bytes.Equal(d.take(16), make([]byte, 16)) || !reflect.DeepEqual(readBitmap4(d), []uint32{12, 33}) || !bytes.Equal(d.opaque(65536), wantValues) {
						return nil, 0, errors.New("SETATTR did not copy ordered ACL and mode in one operation")
					}
					fields[3] = replacementTestU64(900) // The new inode's change is independent.
					if test.change != nil {
						test.change(fields)
					}
					var e encoder
					bitmap4(&e, test.ack...)
					return e, test.status, nil
				default:
					return nil, 0, fmt.Errorf("unexpected mutation %d", code)
				}
			})
			original, err := v.c.CaptureV4Replacement(context.Background(), []byte("original"))
			if err != nil {
				t.Fatal(err)
			}
			err = v.c.ApplyV4Replacement(context.Background(), []byte("stage"), original)
			if (err == nil) != test.allowed {
				t.Fatalf("apply allowed=%t error=%v calls=%v", test.allowed, err, calls)
			}
			wantCalls := []uint32{9, 34}
			if test.status == 0 && reflect.DeepEqual(test.ack, []uint32{12, 33}) {
				wantCalls = append(wantCalls, 9)
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("apply replayed or skipped validation: %v want %v", calls, wantCalls)
			}
			if test.status != 0 && !errors.Is(err, test.status) {
				t.Fatalf("lost setter status: %v", err)
			}
		})
	}
}

func TestV4ReplacementApplyRequestBudget(t *testing.T) {
	for _, limitDelta := range []int{-1, 0} {
		t.Run(fmt.Sprint(limitDelta), func(t *testing.T) {
			fields := replacementTestAttrs()
			setters := 0
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				switch code {
				case 9:
					return replacementTestReply(readBitmap4(d), fields), 0, nil
				case 34:
					setters++
					d.take(16)
					readBitmap4(d)
					d.opaque(65536)
					var e encoder
					bitmap4(&e, 12, 33)
					return e, 0, nil
				default:
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
			})
			original, err := v.c.CaptureV4Replacement(context.Background(), []byte("original"))
			if err != nil {
				t.Fatal(err)
			}
			var request encoder
			bitmap4(&request, 12, 33)
			request.opaque(append(append(encoder(nil), fields[12]...), fields[33]...))
			v.maxRequestPayload = uint32(len(request) + limitDelta)
			v.c.WriteSize = 1 // File WRITE tuning is unrelated to SETATTR capacity.
			err = v.c.ApplyV4Replacement(context.Background(), []byte("stage"), original)
			if limitDelta < 0 {
				if err == nil || setters != 0 {
					t.Fatalf("over-budget request reached server: %v setters=%d", err, setters)
				}
			} else if err != nil || setters != 1 {
				t.Fatalf("fitting request refused: %v setters=%d", err, setters)
			}
		})
	}
}

func TestV4ReplacementSeparatesCachedSetterFromLargeACLReadback(t *testing.T) {
	fields := replacementTestAttrs()
	fields[12] = replacementTestACL(replacementTestACE{0, 0, 7, "OWNER@"}, replacementTestACE{0, 0, 1, strings.Repeat("a", 2200) + "@example.test"})
	var caches []bool
	var operations []uint32
	var cache bool
	v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 53:
			id := d.take(16)
			seq, slot := d.u32(), d.u32()
			d.u32()
			cache = d.boolean()
			caches = append(caches, cache)
			e = append(e, id...)
			e.u32(seq)
			e.u32(slot)
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 9:
			operations = append(operations, code)
			if cache {
				return nil, 10067, nil
			} // REP_TOO_BIG_TO_CACHE on a small slot.
			e = replacementTestReply(readBitmap4(d), fields)
		case 34:
			operations = append(operations, code)
			if !cache {
				return nil, 0, errors.New("SETATTR did not request mutation caching")
			}
			d.take(16)
			readBitmap4(d)
			d.opaque(65536)
			bitmap4(&e, 12, 33)
		default:
			return nil, 0, fmt.Errorf("unexpected operation %d", code)
		}
		return e, 0, nil
	})
	v.session = bytes.Repeat([]byte{2}, 16)
	v.sequence = 1
	original, err := v.c.CaptureV4Replacement(context.Background(), []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if err = v.c.ApplyV4Replacement(context.Background(), []byte("stage"), original); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(caches, []bool{false, true, false}) || !reflect.DeepEqual(operations, []uint32{9, 34, 9}) {
		t.Fatalf("compounds do not separate mutation from variable readback: caches=%v operations=%v", caches, operations)
	}
}

func TestV4ReplacementSourceChecksNameAndPolicy(t *testing.T) {
	tests := []struct {
		name    string
		handle  string
		status  Status
		change  func(map[uint32]encoder)
		allowed bool
	}{
		{"unchanged", "original", 0, nil, true},
		{"name-replaced", "other-inode", 0, nil, false},
		{"name-removed", "", 2, nil, false},
		{"content-change", "original", 0, func(a map[uint32]encoder) { a[3] = replacementTestU64(72) }, false},
		{"change-not-monotonic", "original", 0, func(a map[uint32]encoder) { a[3] = replacementTestU64(70) }, false},
		{"acl-changed-with-same-change", "original", 0, func(a map[uint32]encoder) { a[12] = replacementTestACL(replacementTestACE{0, 0, 7, "OWNER@"}) }, false},
		{"owner-changed-with-same-change", "original", 0, func(a map[uint32]encoder) { a[36] = replacementTestString("other@example.test") }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := replacementTestAttrs()
			lookups := 0
			getters := 0
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 9:
					getters++
					e = replacementTestReply(readBitmap4(d), fields)
				case 15:
					lookups++
					if d.str() != "destination" {
						return nil, 0, errors.New("wrong destination lookup")
					}
					return nil, test.status, nil
				case 10:
					e.opaque([]byte(test.handle))
				default:
					return nil, 0, fmt.Errorf("verification mutated server: %d", code)
				}
				return e, 0, nil
			})
			original, err := v.c.CaptureV4Replacement(context.Background(), []byte("original"))
			if err != nil {
				t.Fatal(err)
			}
			if test.change != nil {
				test.change(fields)
			}
			err = v.c.VerifyV4ReplacementSource(context.Background(), []byte("parent"), "destination", original)
			if (err == nil) != test.allowed || lookups != 1 {
				t.Fatalf("source allowed=%t error=%v lookups=%d", test.allowed, err, lookups)
			}
			wantGetters := 3
			if test.status != 0 {
				wantGetters = 1
			} else if test.handle != "original" {
				wantGetters = 2
			}
			if getters != wantGetters {
				t.Fatalf("source validation reads=%d want=%d", getters, wantGetters)
			}
		})
	}
}
