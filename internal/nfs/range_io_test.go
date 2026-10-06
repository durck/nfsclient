package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestRangeLockCoverage(t *testing.T) {
	c := &Client{}
	v := &v4Client{c: c}
	c.v4 = v
	v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Offset: 16, Length: 16}, file: &v4Open{fh: []byte("file")}}}
	for _, tc := range []struct {
		offset, length uint64
		write, ok      bool
	}{
		{16, 16, false, true}, {20, 4, false, true}, {15, 1, false, false},
		{32, 1, false, false}, {16, 17, false, false}, {16, 1, true, false},
		{16, 0, false, false}, {16, LockToEOF, false, false}, {LockToEOF, 1, false, false},
	} {
		err := c.RequireRangeLock([]byte("file"), tc.offset, tc.length, tc.write)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	v.locks[1].info.Length = LockToEOF
	if err := c.RequireRangeLock([]byte("file"), 1<<40, 4096, false); err != nil {
		t.Fatal(err)
	}
	c.Auth.UID = 123
	if err := c.RequireRangeLock([]byte("file"), 16, 16, false); err == nil {
		t.Fatal("identity changed")
	}
	c.Auth.UID = 0
	v.locks[1].info.Uncertain = true
	if err := c.RequireRangeLock([]byte("file"), 16, 16, false); !errors.Is(err, ErrLockUncertain) {
		t.Fatal(err)
	}
}

func TestRangeWireBoundaries(t *testing.T) {
	for _, variant := range []string{"read", "early-eof", "oversized", "write", "short-write", "commit-change", "short-source"} {
		t.Run(variant, func(t *testing.T) {
			var transferred uint64
			sid := bytes.Repeat([]byte{8}, 16)
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 25:
					if !bytes.Equal(d.take(16), sid) || d.u64() != 64+transferred {
						return nil, 0, errors.New("wrong range READ state or offset")
					}
					limit := d.u32()
					if limit == 0 || limit > 4 || uint64(limit) > 8-transferred {
						return nil, 0, errors.New("out-of-range READ")
					}
					size := limit
					if variant == "oversized" {
						size++
					}
					if variant == "early-eof" {
						size = 1
						e.u32(1)
					} else {
						e.u32(0)
					}
					e.opaque(bytes.Repeat([]byte{'r'}, int(size)))
					transferred += uint64(size)
				case 38:
					if !bytes.Equal(d.take(16), sid) || d.u64() != 64+transferred || d.u32() != 2 {
						return nil, 0, errors.New("wrong range WRITE state or offset")
					}
					data := d.opaque(4)
					if uint64(len(data)) > 8-transferred {
						return nil, 0, errors.New("out-of-range WRITE")
					}
					accepted := len(data)
					if variant == "short-write" {
						accepted = 1
					}
					transferred += uint64(accepted)
					e.u32(uint32(accepted))
					e.u32(0)
					e = append(e, make([]byte, 8)...)
				case 5:
					if d.u64() < 64 || d.u32() > 4 {
						return nil, 0, errors.New("out-of-range COMMIT")
					}
					e = make(encoder, 8)
					if variant == "commit-change" {
						e[0] = 1
					}
				default:
					return nil, 0, fmt.Errorf("unexpected range operation %d", code)
				}
				return e, 0, nil
			})
			v.c.ReadSize, v.c.WriteSize = 4, 4
			v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Offset: 64, Length: 8, Write: true}, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}, sid: sid}}
			var n int64
			var err error
			if variant == "read" || variant == "early-eof" || variant == "oversized" {
				var b bytes.Buffer
				n, err = v.c.ReadRangeToProgress(context.Background(), []byte("file"), 64, 8, &b, nil)
			} else {
				source := bytes.Repeat([]byte{'w'}, 12) // excess bytes must never be read/written
				if variant == "short-source" {
					source = source[:3]
				}
				n, err = v.c.WriteRangeFromProgress(context.Background(), []byte("file"), 64, 8, bytes.NewReader(source), nil)
			}
			if variant == "read" || variant == "write" || variant == "short-write" {
				if err != nil || n != 8 || transferred != 8 {
					t.Fatal(n, transferred, err)
				}
			} else if err == nil {
				t.Fatal("invalid range reply accepted")
			}
			if variant == "early-eof" || variant == "short-source" {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
			}
		})
	}
}
