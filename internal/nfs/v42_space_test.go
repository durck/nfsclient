package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func spacePeer42(t *testing.T, share uint32, operation operationReply4, closed *int) *Client {
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
				return nil, 0, errors.New("unexpected slot/cache policy")
			}
			for range 4 {
				e.u32(0)
			}
		case 18:
			if d.u32() != 0 || d.u32() != share || d.u32() != 0 || d.u64() != 123 || len(d.opaque(128)) != 16 || d.u32() != 0 || d.u32() != 0 || d.str() != "file" {
				return nil, 0, errors.New("invalid space OPEN")
			}
			e = append(e, sid...)
			e.u32(1)
			e.u64(1)
			e.u64(2)
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 10:
			e.opaque([]byte("file"))
		case 4:
			if d.u32() != 1 || !bytes.Equal(d.take(16), sid) {
				return nil, 0, errors.New("invalid space CLOSE")
			}
			*closed++
			e = append(e, sid...)
		default:
			if !bytes.Equal(d.take(16), sid) {
				return nil, 0, errors.New("operation did not use open state")
			}
			return operation(code, d)
		}
		return e, 0, nil
	})
	v.session = bytes.Repeat([]byte{9}, 16)
	v.sequence = 1
	return v.c
}

func TestV42SeekWire(t *testing.T) {
	for _, kind := range []string{"data", "hole", "eof", "backward", "bad-bool", "truncated", "unsupported", "past-eof"} {
		t.Run(kind, func(t *testing.T) {
			closed, calls := 0, 0
			c := spacePeer42(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				calls++
				what := uint32(0)
				if kind == "hole" {
					what = 1
				}
				if code != 69 || d.u64() != 1<<40 || d.u32() != what {
					return nil, 0, errors.New("invalid SEEK range")
				}
				if kind == "unsupported" {
					return nil, 10004, nil
				}
				if kind == "past-eof" {
					return nil, 6, nil
				}
				var e encoder
				b := uint32(0)
				if kind == "eof" {
					b = 1
				}
				if kind == "bad-bool" {
					b = 2
				}
				e.u32(b)
				if kind == "truncated" {
					return e, 0, nil
				}
				offset := uint64(1<<40) + 4096
				if kind == "backward" {
					offset = 0
				}
				e.u64(offset)
				return e, 0, nil
			}, &closed)
			result, err := c.Seek(context.Background(), []byte("file"), 1<<40, kind == "hole")
			good := kind == "data" || kind == "hole" || kind == "eof"
			if calls != 1 {
				t.Fatal("operation replayed or omitted", calls)
			}
			if good {
				if err != nil || result.Offset != 1<<40+4096 || result.EOF != (kind == "eof") || closed != 1 {
					t.Fatal(result, err, closed)
				}
			} else {
				if err == nil || result != (SeekResult{}) {
					t.Fatal("bad reply accepted", result, err)
				}
				if kind == "unsupported" && (!errors.Is(err, Status(10004)) || closed != 1) {
					t.Fatal(err, closed)
				}
				if kind == "past-eof" && !errors.Is(err, Status(6)) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestV42SpaceMutations(t *testing.T) {
	for _, code := range []uint32{59, 62} {
		for _, failure := range []string{"", "denied", "unsupported", "malformed"} {
			t.Run(fmt.Sprintf("%d/%s", code, failure), func(t *testing.T) {
				closed, calls := 0, 0
				c := spacePeer42(t, 2, func(op uint32, d *decoder) (encoder, Status, error) {
					calls++
					if op != code || d.u64() != 1<<40 || d.u64() != 8192 {
						return nil, 0, errors.New("invalid space mutation")
					}
					if failure == "denied" {
						return nil, 13, nil
					}
					if failure == "unsupported" {
						return nil, 10004, nil
					}
					if failure == "malformed" {
						return []byte{0, 0, 0, 0}, 0, nil
					}
					return nil, 0, nil
				}, &closed)
				mutate := c.Allocate
				if code == 62 {
					mutate = c.Deallocate
				}
				err := mutate(context.Background(), []byte("file"), 1<<40, 8192)
				if calls != 1 {
					t.Fatal("mutation replayed", calls)
				}
				if failure == "" && (err != nil || closed != 1) {
					t.Fatal(err, closed)
				}
				if failure != "" && err == nil {
					t.Fatal("failure accepted")
				}
				if failure == "malformed" && !strings.Contains(err.Error(), "outcome unverified") {
					t.Fatal(err)
				}
				if failure == "denied" && !errors.Is(err, Status(13)) {
					t.Fatal(err)
				}
				if failure == "unsupported" && !errors.Is(err, Status(10004)) {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestV42SpaceRefusals(t *testing.T) {
	ctx := context.Background()
	for _, c := range []*Client{{}, {v4: &v4Client{minor: 0}}, {v4: &v4Client{minor: 1}}} {
		if _, err := c.Seek(ctx, nil, 0, false); !errors.Is(err, ErrRequiresV42) {
			t.Fatal(err)
		}
		if err := c.Allocate(ctx, nil, 0, 1); !errors.Is(err, ErrRequiresV42) {
			t.Fatal(err)
		}
		if err := c.Deallocate(ctx, nil, 0, 1); !errors.Is(err, ErrRequiresV42) {
			t.Fatal(err)
		}
	}
	for _, r := range [][2]uint64{{0, 0}, {^uint64(0), 1}, {^uint64(0) - 1, 2}} {
		c := &Client{v4: &v4Client{minor: 2}}
		if c.Allocate(ctx, nil, r[0], r[1]) == nil || c.Deallocate(ctx, nil, r[0], r[1]) == nil {
			t.Fatal("invalid range sent")
		}
	}
	if ValidateSpaceRange(0, ^uint64(0)) != nil || ValidateSpaceRange(^uint64(0)-1, 1) != nil {
		t.Fatal("valid finite range rejected")
	}
	for _, mode := range []string{"read", "partial", "uncertain", "identity"} {
		t.Run(mode, func(t *testing.T) {
			p := &lockPeerState{}
			if mode == "partial" {
				p.offset = 4096
				p.length = 4096
			}
			v := lockPeer4(t, 2, p)
			if _, err := v.c.LockRange(ctx, []byte("file"), mode != "read", p.offset, func() uint64 {
				if p.length == 0 {
					return LockToEOF
				}
				return p.length
			}()); err != nil {
				t.Fatal(err)
			}
			if mode == "uncertain" {
				v.stateLost.Store(true)
			}
			if mode == "identity" {
				v.c.Auth.UID++
			}
			if v.c.Allocate(ctx, []byte("file"), 0, 1) == nil || v.c.Deallocate(ctx, []byte("file"), 0, 1) == nil {
				t.Fatal("invalid held lock allowed mutation")
			}
			if mode != "read" {
				if _, err := v.c.Seek(ctx, []byte("file"), 0, false); err == nil {
					t.Fatal("invalid held lock allowed seek")
				}
			}
		})
	}
}
