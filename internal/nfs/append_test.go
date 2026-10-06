package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestAppendAtWire(t *testing.T) {
	for _, kind := range []string{"stable", "unstable", "verifier", "malformed", "wrong-eof", "wrong-change", "missing-size", "directory", "overflow", "no-lock", "read-lock", "partial-lock", "uncertain"} {
		t.Run(kind, func(t *testing.T) {
			const base = uint64(1 << 40)
			writes, commits := 0, 0
			sequences := 0
			v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 53:
					e = append(e, d.take(16)...)
					e.u32(d.u32())
					//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
					if d.u32() != 0 || d.u32() != 0 || d.boolean() != (sequences > 0) {
						return nil, 0, errors.New("wrong append read/mutation cache policy")
					}
					sequences++
					for range 4 {
						e.u32(0)
					}
				case 9:
					readBitmap4(d)
					if kind == "missing-size" {
						bitmap4(&e, 1)
					} else {
						bitmap4(&e, 1, 3, 4)
					}
					var a encoder
					if kind == "directory" {
						a.u32(2)
					} else {
						a.u32(1)
					}
					if kind != "missing-size" {
						change := uint64(42)
						if kind == "wrong-change" {
							change++
						}
						a.u64(change)
						size := base
						if kind == "wrong-eof" {
							size++
						}
						a.u64(size)
					}
					e.opaque(a)
				case 38:
					if !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) || d.u64() != base+uint64(writes*2) || d.u32() != 2 {
						return nil, 0, errors.New("wrong resumed WRITE offset/state")
					}
					data := d.opaque(4)
					want := []string{"abcd", "cd", "XY"}
					if writes >= len(want) || string(data) != want[writes] {
						return nil, 0, fmt.Errorf("wrong append bytes %q", data)
					}
					writes++
					e.u32(2)
					if kind == "malformed" {
						return e, 0, nil
					}
					stable := uint32(2)
					if kind != "stable" {
						stable = 0
					}
					e.u32(stable)
					e = append(e, []byte("verifier")...)
				case 5:
					if d.u64() != base+uint64(commits*2) || d.u32() != 2 {
						return nil, 0, errors.New("wrong resumed COMMIT offset")
					}
					commits++
					if kind == "verifier" {
						return encoder("changed!"), 0, nil
					}
					return encoder("verifier"), 0, nil
				default:
					return nil, 0, fmt.Errorf("unexpected append operation %d", code)
				}
				return e, 0, nil
			})
			v.session = bytes.Repeat([]byte{9}, 16)
			v.sequence = 1
			v.locks = map[uint64]*v4Lock{2: {info: LockInfo{ID: 2, Length: LockToEOF, Write: true}, file: &v4Open{fh: []byte("destination"), auth: v.c.Auth}, sid: bytes.Repeat([]byte{8}, 16)}}
			c := v.c
			c.WriteSize = 4
			offset := base
			switch kind {
			case "overflow":
				offset = 1 << 63
			case "no-lock":
				delete(c.v4.locks, 2)
			case "read-lock":
				c.v4.locks[2].info.Write = false
			case "partial-lock":
				c.v4.locks[2].info.Length = 1
			case "uncertain":
				c.v4.locks[2].info.Uncertain = true
			}
			var progress []uint64
			n, err := c.AppendFromProgress(context.Background(), []byte("destination"), offset, 42, bytes.NewReader([]byte("abcdXY")), func(n uint64) { progress = append(progress, n) })
			if kind == "stable" || kind == "unstable" {
				if err != nil || n != 6 || writes != 3 || !reflect.DeepEqual(progress, []uint64{2, 4, 6}) {
					t.Fatal(n, err, writes, progress)
				}
				if (kind == "unstable" && commits != 3) || (kind == "stable" && commits != 0) {
					t.Fatal(commits)
				}
			} else {
				if err == nil || n != 0 || len(progress) != 0 {
					t.Fatal(n, err, progress)
				}
				want := 0
				if kind == "verifier" || kind == "malformed" {
					want = 1
				}
				if writes != want {
					t.Fatal("unsafe WRITE count", writes)
				}
			}
		})
	}
}

func TestV4WriteAtBoundary(t *testing.T) {
	c := copyPeer(t, func(uint32, *decoder) (encoder, Status, error) {
		t.Error("overflowing write sent RPC")
		return nil, 0, nil
	})
	c.WriteSize = 4
	if n, err := c.v4.writeAt(context.Background(), []byte("destination"), bytes.NewReader([]byte("xy")), nil, uint64(1<<63-1)); err == nil || n != 0 {
		t.Fatal(n, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := c.v4.writeAt(ctx, []byte("destination"), bytes.NewReader([]byte("xy")), nil, 1<<40); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatal(n, err)
	}
}
