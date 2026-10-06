package nfs

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

// Linux 6.8 negotiates 2048 bytes of slot data plus 80 bytes of reply headers.
// This is a cache limit, not the maximum size of an uncached READ reply.
func TestV4KernelSessionCacheLimits(t *testing.T) {
	for _, profile := range [][4]uint32{{1 << 20, 1 << 20, 2128, 16}, {1 << 20, 1 << 20, 1024, 16}, {1 << 20, 1 << 20, 1023, 16}, {1 << 20, 1 << 20, 88, 16}, {1 << 20, 1 << 20, 87, 16}, {1 << 20, 1 << 20, 0, 16}, {512, 512, 128, 4}, {128, 104, 88, 3}, {1 << 20, 1 << 20, 2128, 32}} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			cached := profile[2]
			sid := bytes.Repeat([]byte{3}, 16)
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 42:
					d.take(8)
					d.str()
					d.u32()
					d.u32()
					d.u32()
					e.u64(123)
					e.u32(1)
					e.u32(0x10000)
					e.u32(0)
					e.u64(1)
					e.opaque([]byte("server"))
					e.opaque([]byte("scope"))
					e.u32(0)
				case 43:
					d.u64()
					d.u32()
					d.u32()
					for i := 0; i < 2; i++ {
						d.take(7 * 4)
					}
					d.u32()
					d.u32()
					e = append(e, sid...)
					e.u32(1)
					e.u32(0)
					for i := 0; i < 2; i++ {
						e.u32(0)
						e.u32(profile[0])
						e.u32(profile[1])
						e.u32(cached)
						e.u32(profile[3])
						e.u32(1)
						e.u32(0)
					}
				case 53:
					id := d.take(16)
					seq := d.u32()
					slot := d.u32()
					d.u32()
					d.boolean()
					e = append(e, id...)
					e.u32(seq)
					e.u32(slot)
					e.u32(0)
					e.u32(0)
					e.u32(0)
				case 58:
					d.boolean()
				case 24:
				case 10:
					e.opaque([]byte("root"))
				default:
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				return e, 0, nil
			})
			v.c.ReadSize, v.c.WriteSize = 65536, 65536
			err := v.initialize(context.Background())
			if cached < 88 {
				if err == nil || !strings.Contains(err.Error(), "session limits too small") {
					t.Fatalf("unsupported tiny cache: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			readSize, writeSize := uint32(65536), uint32(65536)
			if profile[1] > 104 {
				readSize = min(readSize, (profile[1]-104)&^3)
			}
			if profile[0] > 292 {
				writeSize = min(writeSize, (profile[0]-292)&^3)
			}
			if !bytes.Equal(v.session, sid) || v.c.ReadSize != readSize || v.c.WriteSize != writeSize {
				t.Fatalf("cache incorrectly limits transfer: read=%d write=%d", v.c.ReadSize, v.c.WriteSize)
			}
		})
	}
}

func TestV4VariableRepliesDoNotRequireSlotCache(t *testing.T) {
	for _, test := range []struct {
		name  string
		codes []uint32
		cache bool
	}{
		{"read", []uint32{25}, false}, {"readdir", []uint32{26}, false},
		{"attributes", []uint32{9}, false}, {"readlink", []uint32{27}, false},
		{"secinfo", []uint32{33}, false}, {"write", []uint32{38}, true},
		{"open", []uint32{18, 10}, true}, {"remove", []uint32{28}, true},
		{"mixed-mutation-read", []uint32{38, 25}, true}, {"unknown", []uint32{999}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cache bool
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				if code == 53 {
					id := d.take(16)
					seq := d.u32()
					slot := d.u32()
					d.u32()
					cache = d.boolean()
					e = append(e, id...)
					e.u32(seq)
					e.u32(slot)
					e.u32(0)
					e.u32(0)
					e.u32(0)
				}
				return e, 0, nil
			})
			v.session = bytes.Repeat([]byte{1}, 16)
			v.sequence = 1
			ops := []v4Op{fh4([]byte("file"))}
			for _, code := range test.codes {
				ops = append(ops, op4(code, nil, nil))
			}
			if err := v.compound(context.Background(), ops...); err != nil {
				t.Fatal(err)
			}
			if cache != test.cache {
				t.Fatalf("SEQUENCE cachethis=%t, want %t", cache, test.cache)
			}
		})
	}
}

func TestV4ReadDirFitsNegotiatedReplyBudget(t *testing.T) {
	for _, budget := range []uint32{3072, 65536} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 26 {
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				d.u64()
				d.take(8)
				dirCount, maxCount := d.u32(), d.u32()
				readBitmap4(d)
				if dirCount != min(uint32(4096), budget) || maxCount != dirCount {
					return nil, 0, fmt.Errorf("READDIR count %d/%d exceeds negotiated budget %d", dirCount, maxCount, budget)
				}
				e := make(encoder, 8)
				e.u32(0)
				e.u32(1)
				return e, 0, nil
			})
			v.c.ReadSize = budget
			v.maxReplyPayload = budget
			v.c.ReadSize = 128 // File READ tuning must not shrink directory replies.
			if entries, err := v.readdir(context.Background(), []byte("directory")); err != nil || len(entries) != 0 {
				t.Fatalf("empty directory: %v %v", entries, err)
			}
		})
	}
}

func TestV4TunesReadAndWriteLimitsIndependently(t *testing.T) {
	for _, limits := range [][2]uint64{{512, 8192}, {16384, 256}, {1 << 40, 1 << 40}, {0, 4096}, {4096, 0}} {
		t.Run(fmt.Sprint(limits), func(t *testing.T) {
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 9 {
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				if bits := readBitmap4(d); fmt.Sprint(bits) != "[30 31]" {
					return nil, 0, fmt.Errorf("wrong transfer attributes: %v", bits)
				}
				var e, a encoder
				bitmap4(&e, 30, 31)
				a.u64(limits[0])
				a.u64(limits[1])
				e.opaque(a)
				return e, 0, nil
			})
			v.c.ReadSize, v.c.WriteSize = 65536, 65536
			err := v.tune(context.Background(), []byte("file"))
			if limits[0] == 0 || limits[1] == 0 {
				if err == nil || !strings.Contains(err.Error(), "zero transfer maximum") {
					t.Fatalf("zero limit: %v", err)
				}
				return
			}
			if err != nil || uint64(v.c.ReadSize) != min(uint64(65536), limits[0]) || uint64(v.c.WriteSize) != min(uint64(65536), limits[1]) {
				t.Fatalf("read=%d write=%d: %v", v.c.ReadSize, v.c.WriteSize, err)
			}
		})
	}
}
