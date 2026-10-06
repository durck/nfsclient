package nfs

import (
	"bytes"
	"context"
	"math"
	"testing"
)

type layoutSegmentSpec struct {
	offset, length, pattern uint64
	mode, kind              uint32
}

func segmentReply(specs []layoutSegmentSpec) encoder {
	var e encoder
	e.u32(1)
	e = append(e, bytes.Repeat([]byte{8}, 16)...)
	e.u32(uint32(len(specs)))
	for i, s := range specs {
		e.u64(s.offset)
		e.u64(s.length)
		e.u32(s.mode)
		e.u32(s.kind)
		body := encoder(bytes.Repeat([]byte{byte(i)}, 16))
		body.u32(64)
		body.u32(0)
		body.u64(s.pattern)
		body.u32(1)
		body.opaque([]byte{byte(i)})
		e.opaque(body)
	}
	return e
}

func TestPNFSSegmentValidation(t *testing.T) {
	valid := []layoutSegmentSpec{{0, 95, 0, 1, 1}, {95, math.MaxUint64, 64, 1, 1}}
	for _, tc := range []struct {
		name  string
		specs []layoutSegmentSpec
		size  uint64
		bad   bool
	}{
		{"two", valid, 173, false},
		{"empty-file", valid, 0, false},
		{"finite", []layoutSegmentSpec{{0, 95, 0, 2, 1}, {95, 78, 64, 2, 1}}, 173, false},
		{"empty", nil, 1, true},
		{"gap", []layoutSegmentSpec{{0, 94, 0, 1, 1}, {95, 78, 64, 1, 1}}, 173, true},
		{"overlap", []layoutSegmentSpec{{0, 96, 0, 1, 1}, {95, 78, 64, 1, 1}}, 173, true},
		{"unordered", []layoutSegmentSpec{valid[1], valid[0]}, 173, true},
		{"short", []layoutSegmentSpec{{0, 95, 0, 1, 1}}, 173, true},
		{"zero", []layoutSegmentSpec{{0, 0, 0, 1, 1}}, 0, true},
		{"mixed-mode", []layoutSegmentSpec{{0, 95, 0, 1, 1}, {95, 78, 64, 2, 1}}, 173, true},
		{"bad-type", []layoutSegmentSpec{{0, 173, 0, 1, 2}}, 173, true},
		{"bad-mode", []layoutSegmentSpec{{0, 173, 0, 3, 1}}, 173, true},
		{"future-pattern", []layoutSegmentSpec{{0, 95, 0, 1, 1}, {95, 78, 96, 1, 1}}, 173, true},
		{"infinity-not-last", []layoutSegmentSpec{{0, math.MaxUint64, 0, 1, 1}, {95, 78, 64, 1, 1}}, 173, true},
		{"overflow", []layoutSegmentSpec{{0, 95, 0, 1, 1}, {95, math.MaxUint64 - 1, 64, 1, 1}}, 173, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &decoder{b: segmentReply(tc.specs)}
			_, segments := decodeFileLayouts(d, tc.size)
			if (d.err != nil) != tc.bad {
				t.Fatalf("err=%v", d.err)
			}
			if !tc.bad && len(segments) != len(tc.specs) {
				t.Fatal("lost segment")
			}
		})
	}
	for _, b := range []encoder{segmentReply(valid)[:25], append(segmentReply(valid), 1), segmentReply(make([]layoutSegmentSpec, 65)), make(encoder, 32769)} {
		d := &decoder{b: b}
		decodeFileLayouts(d, 173)
		if d.err == nil {
			t.Fatal("accepted malformed array")
		}
	}
}

func TestPNFSSegmentMalformedGrantQuarantined(t *testing.T) {
	for _, mode := range []string{"gap", "trailing", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			specs := []layoutSegmentSpec{{0, 95, 0, 1, 1}, {95, 78, 64, 1, 1}}
			if mode == "gap" {
				specs[1].offset++
			}
			reply := segmentReply(specs)
			if mode == "trailing" {
				reply = append(reply, 1)
			}
			if mode == "truncated" {
				reply = reply[:len(reply)-2]
			}
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) { d.take(len(d.b)); return reply, 0, nil })
			v.recall = &layoutRecall{}
			if _, err := v.getLayout(context.Background(), []byte("file"), make([]byte, 16), 173); err == nil {
				t.Fatal("accepted malformed grant")
			}
			if !v.stateLost.Load() || v.recall.active {
				t.Fatal("unvalidated grant became usable")
			}
		})
	}
}

func TestPNFSSegmentSelectionAndLimit(t *testing.T) {
	var specs []layoutSegmentSpec
	for i := range 64 {
		specs = append(specs, layoutSegmentSpec{uint64(i), 1, 0, 1, 1})
	}
	d := &decoder{b: segmentReply(specs)}
	_, layouts := decodeFileLayouts(d, 64)
	if d.err != nil || len(layouts) != 64 {
		t.Fatal("valid segment limit", d.err)
	}
	for i := range 64 {
		l, err := fileLayoutAt(layouts, uint64(i))
		if err != nil || l.offset != uint64(i) {
			t.Fatal("boundary selected wrong segment", i, err)
		}
	}
	if _, err := fileLayoutAt(layouts, 64); err == nil {
		t.Fatal("read beyond finite coverage")
	}
	d = &decoder{b: segmentReply([]layoutSegmentSpec{{0, math.MaxUint64 - 2, 0, 1, 1}, {math.MaxUint64 - 2, math.MaxUint64, 0, 1, 1}})}
	_, layouts = decodeFileLayouts(d, math.MaxInt64)
	if d.err != nil {
		t.Fatal(d.err)
	}
	if l, err := fileLayoutAt(layouts, math.MaxUint64-1); err != nil || l != layouts[1] {
		t.Fatal("overflow selecting EOF range", err)
	}
}
