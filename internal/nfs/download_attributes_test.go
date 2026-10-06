package nfs

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestDownloadTimestampDecoding(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		for _, invalid := range []string{"", "mtime", "ctime"} {
			t.Run(fmt.Sprintf("v2=%t/%s", v2, invalid), func(t *testing.T) {
				var e encoder
				limit := uint32(1000000000)
				scale := int64(1)
				if v2 {
					for _, v := range []uint32{1, 0600, 1, 10, 20, 9, 4096, 0, 1, 6, 7} {
						e.u32(v)
					}
					limit, scale = 1000000, 1000
				} else {
					compatibilityAttr(&e)
					e = e[:len(e)-24]
				}
				for i, name := range []string{"atime", "mtime", "ctime"} {
					e.u32(uint32(100 + i))
					fraction := uint32(900 + i)
					if name == invalid {
						fraction = limit
					}
					e.u32(fraction)
				}
				d := &decoder{b: e}
				var a Attr
				if v2 {
					a = attr2(d)
				} else {
					a = readAttr(d)
				}
				if invalid != "" {
					if d.err == nil {
						t.Fatal("invalid timestamp accepted")
					}
					return
				}
				if d.err != nil || len(d.b) != 0 || !a.HasSize || !a.HasMTime || !a.HasCTime || !a.MTime.Equal(time.Unix(101, 901*scale)) || !a.CTime.Equal(time.Unix(102, 902*scale)) {
					t.Fatalf("timestamp/size evidence: %+v, remaining=%d error=%v", a, len(d.b), d.err)
				}
			})
		}
	}
}

func TestV4DownloadAttributePresence(t *testing.T) {
	for _, optional := range []bool{false, true} {
		t.Run(fmt.Sprint(optional), func(t *testing.T) {
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				bits := readBitmap4(d)
				if code != 9 || !slices.Contains(bits, uint32(3)) || !slices.Contains(bits, uint32(52)) {
					return nil, 0, fmt.Errorf("missing download evidence request: %d %v", code, bits)
				}
				var e, a encoder
				if optional {
					bitmap4(&e, 1, 3, 4, 52, 53)
				} else {
					bitmap4(&e, 1, 3, 4)
				}
				a.u32(1)
				a.u64(0) // Zero is a valid opaque change value, distinct from absent.
				a.u64(0)
				if optional {
					a.u64(101)
					a.u32(22)
					a.u64(102)
					a.u32(33)
				}
				e.opaque(a)
				return e, 0, nil
			})
			a, err := v.getAttr(context.Background(), []byte("file"))
			if err != nil || !a.HasSize || !a.HasChange || a.Change != 0 || a.HasCTime != optional || a.HasMTime != optional {
				t.Fatalf("attribute presence: %+v %v", a, err)
			}
			if optional && (!a.CTime.Equal(time.Unix(101, 22)) || !a.MTime.Equal(time.Unix(102, 33))) {
				t.Fatalf("swapped timestamps: %+v", a)
			}
		})
	}
}
