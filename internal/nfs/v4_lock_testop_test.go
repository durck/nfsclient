package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestV4LockTestWire(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, status := range []Status{0, 10010, 10013} {
			t.Run(fmt.Sprintf("%d/%d", minor, status), func(t *testing.T) {
				var owners [][]byte
				v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
					var e encoder
					if code == 53 {
						e = append(e, d.take(16)...)
						e.u32(d.u32())
						e.u32(d.u32())
						d.u32()
						d.boolean()
						e.u32(0)
						e.u32(0)
						e.u32(0)
						return e, 0, nil
					}
					if code != 13 || d.u32() != 2 || d.u64() != 5 || d.u64() != LockToEOF {
						return nil, 0, errors.New("unexpected LOCKT operation/range")
					}
					clientID := d.u64()
					if minor == 0 && clientID != 123 || minor != 0 && clientID != 0 {
						return nil, 0, errors.New("wrong LOCKT client ID")
					}
					owner := bytes.Clone(d.opaque(1024))
					if len(owner) != 16 || len(owners) > 0 && bytes.Equal(owner, owners[0]) {
						return nil, 0, errors.New("LOCKT owner reused")
					}
					owners = append(owners, owner)
					if status == 10010 {
						e.u64(8)
						e.u64(3)
						e.u32(2)
						e.u64(987)
						e.opaque([]byte{0, 255, 7})
					}
					return e, status, nil
				})
				if minor > 0 {
					v.session = bytes.Repeat([]byte{1}, 16)
				}
				for i := 0; i < 2; i++ {
					got, err := v.c.TestLock(context.Background(), []byte("file"), true, 5, LockToEOF)
					if status == 10013 {
						if !errors.Is(err, status) {
							t.Fatalf("status: %v", err)
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if status == 0 && got != nil {
						t.Fatal("false conflict")
					}
					if status == 10010 && (got == nil || got.Protocol != "NFSv4" || got.ClientID != 987 || !got.Write || got.Offset != 8 || got.Length != 3 || !bytes.Equal(got.Owner, []byte{0, 255, 7})) {
						t.Fatalf("conflict: %+v", got)
					}
					if len(v.c.Locks()) != 0 {
						t.Fatal("LOCKT retained lock")
					}
				}
			})
		}
	}
}

func TestV4LockTestRejectsMalformedDenial(t *testing.T) {
	for _, mode := range []string{"type", "zero-length", "nonoverlap", "read-read", "truncated", "trailing", "oversized-owner"} {
		t.Run(mode, func(t *testing.T) {
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				if code != 13 {
					return nil, 0, fmt.Errorf("unexpected op %d", code)
				}
				d.u32()
				d.u64()
				d.u64()
				d.u64()
				d.opaque(1024)
				off, length, kind := uint64(0), uint64(10), uint32(2)
				if mode == "type" {
					kind = 9
				}
				if mode == "zero-length" {
					length = 0
				}
				if mode == "nonoverlap" {
					off = 10
				}
				if mode == "read-read" {
					kind = 1
				}
				var e encoder
				e.u64(off)
				e.u64(length)
				e.u32(kind)
				e.u64(2)
				owner := []byte("owner")
				if mode == "oversized-owner" {
					owner = make([]byte, 1025)
				}
				e.opaque(owner)
				if mode == "truncated" {
					e = e[:len(e)-1]
				}
				if mode == "trailing" {
					e.u32(0)
				}
				return e, 10010, nil
			})
			if got, err := v.c.TestLock(context.Background(), []byte("file"), false, 0, 10); err == nil || got != nil {
				t.Fatalf("accepted %s: %+v %v", mode, got, err)
			}
		})
	}
}
