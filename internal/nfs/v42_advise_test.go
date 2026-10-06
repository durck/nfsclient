package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func advicePeer(t *testing.T, reply func(*decoder) (encoder, Status, error)) *Client {
	t.Helper()
	sid := bytes.Repeat([]byte{7}, 16)
	v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 53:
			e = append(e, d.take(16)...)
			e.u32(d.u32())
			//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
			if d.u32() != 0 || d.u32() != 0 || !d.boolean() {
				return nil, 0, errors.New("advice should cache small stateful reply")
			}
			for range 4 {
				e.u32(0)
			}
		case 63:
			if !bytes.Equal(d.take(16), sid) {
				return nil, 0, errors.New("invalid advice stateid")
			}
			return reply(d)
		default:
			return nil, 0, fmt.Errorf("unexpected advice operation %d", code)
		}
		return e, 0, nil
	})
	v.session = bytes.Repeat([]byte{9}, 16)
	v.sequence = 1
	v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Length: LockToEOF}, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}, sid: sid}}
	return v.c
}

func TestV42AdviceWire(t *testing.T) {
	for _, kind := range []string{"accepted", "different", "empty", "padding", "unknown", "too-long", "truncated", "unsupported", "denied", "lost"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			var c *Client
			c = advicePeer(t, func(d *decoder) (encoder, Status, error) {
				calls++
				if d.u64() != 1<<40 || d.u64() != 0 || d.u32() != 1 || d.u32() != 258 {
					return nil, 0, errors.New("wrong advice arguments")
				}
				var e encoder
				switch kind {
				case "accepted":
					e.u32(1)
					e.u32(258)
				case "different":
					e.u32(1)
					e.u32(1)
				case "empty":
					e.u32(0)
				case "padding":
					e.u32(2)
					e.u32(1)
					e.u32(0)
				case "unknown":
					e.u32(2)
					e.u32(0)
					e.u32(1)
				case "too-long":
					e.u32(9)
				case "truncated":
					e.u32(1)
				case "unsupported":
					return nil, 10004, nil
				case "denied":
					return nil, 13, nil
				case "lost":
					c.v4.stateLost.Store(true)
					e.u32(0)
				}
				return e, 0, nil
			})
			r, err := c.Advise(context.Background(), []byte("file"), 1<<40, 0, 258)
			if calls != 1 {
				t.Fatal("advice replayed", calls)
			}
			var want []string
			switch kind {
			case "accepted":
				want = []string{"sequential", "read"}
			case "different", "padding":
				want = []string{"normal"}
			case "empty":
				want = []string{}
			default:
				if err == nil || r.Hints != nil {
					t.Fatal(r, err)
				}
				if kind == "unsupported" && !errors.Is(err, Status(10004)) {
					t.Fatal(err)
				}
				if kind == "lost" && !errors.Is(err, ErrLockUncertain) {
					t.Fatal(err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(r.Hints, want) {
				t.Fatal(r, err, want)
			}
		})
	}
}

func TestV42AdviceValidation(t *testing.T) {
	for bit, name := range adviseNames {
		if got, err := ParseAdvice(name + "," + name); err != nil || got != 1<<bit {
			t.Fatal(name, got, err)
		}
	}
	for _, bad := range []string{"", "read,", "READ", "read,randomly", " read"} {
		if _, err := ParseAdvice(bad); err == nil {
			t.Fatal(bad)
		}
	}
	if mask, err := ParseAdvice("sequential,random"); err != nil || mask != 10 {
		t.Fatal(mask, err)
	}
	for _, kind := range []string{"v3", "v41", "no-lock", "partial", "uncertain", "identity", "empty-hint", "unknown-hint", "overflow"} {
		t.Run(kind, func(t *testing.T) {
			c := advicePeer(t, func(*decoder) (encoder, Status, error) { t.Error("invalid advice sent RPC"); return nil, 0, nil })
			offset, length, hints := uint64(0), uint64(0), uint32(1)
			switch kind {
			case "v3":
				c.v4 = nil
			case "v41":
				c.v4.minor = 1
			case "no-lock":
				c.v4.locks = nil
			case "partial":
				c.v4.locks[1].info.Length = 1
			case "uncertain":
				c.v4.locks[1].info.Uncertain = true
			case "identity":
				c.Auth.UID++
			case "empty-hint":
				hints = 0
			case "unknown-hint":
				hints = 1 << 11
			case "overflow":
				offset = ^uint64(0)
				length = 1
			}
			if _, err := c.Advise(context.Background(), []byte("file"), offset, length, hints); err == nil {
				t.Fatal("accepted invalid advice")
			}
		})
	}
}
