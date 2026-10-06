package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
)

func plusReply(eof bool, parts ...readPlusPart) encoder {
	var e encoder
	if eof {
		e.u32(1)
	} else {
		e.u32(0)
	}
	e.u32(uint32(len(parts)))
	for _, p := range parts {
		if p.data == nil {
			e.u32(1)
			e.u64(p.offset)
			e.u64(p.end - p.offset)
		} else {
			e.u32(0)
			e.u64(p.offset)
			e.opaque(p.data)
		}
	}
	return e
}

func plusPeer(t *testing.T, reply func(uint64, uint32) (encoder, Status)) *Client {
	t.Helper()
	sid := bytes.Repeat([]byte{7}, 16)
	v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 53:
			e = append(e, d.take(16)...)
			e.u32(d.u32())
			//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
			if d.u32() != 0 || d.u32() != 0 || d.boolean() {
				return nil, 0, errors.New("READ_PLUS must use uncached reply slot")
			}
			for range 4 {
				e.u32(0)
			}
		case 68:
			if !bytes.Equal(d.take(16), sid) {
				return nil, 0, errors.New("READ_PLUS did not use held state")
			}
			e, status := reply(d.u64(), d.u32())
			return e, status, nil
		default:
			return nil, 0, fmt.Errorf("unexpected READ_PLUS operation %d", code)
		}
		return e, 0, nil
	})
	v.session = bytes.Repeat([]byte{9}, 16)
	v.sequence = 1
	v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Length: LockToEOF}, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}, sid: sid}}
	v.c.ReadSize = 4
	return v.c
}

func TestV42ReadPlusStreams(t *testing.T) {
	for _, kind := range []string{"whole-hole", "mixed", "hole-before-offset", "empty", "empty-data"} {
		t.Run(kind, func(t *testing.T) {
			var expected []byte
			calls := 0
			c := plusPeer(t, func(offset uint64, count uint32) (encoder, Status) {
				calls++
				switch kind {
				case "whole-hole":
					return plusReply(true, readPlusPart{end: 12}), 0
				case "mixed":
					return plusReply(true, readPlusPart{data: []byte("ab")}, readPlusPart{offset: 2, end: 4}, readPlusPart{offset: 4, data: []byte("cdef")}), 0
				case "hole-before-offset":
					if offset == 0 {
						return plusReply(false, readPlusPart{data: []byte("abcd")}), 0
					}
					return plusReply(true, readPlusPart{offset: 0, end: 7}, readPlusPart{offset: 7, data: []byte("x")}), 0
				case "empty-data":
					return plusReply(true, readPlusPart{data: []byte{}}), 0
				default:
					return plusReply(true), 0
				}
			})
			switch kind {
			case "whole-hole":
				expected = make([]byte, 12)
			case "mixed":
				expected = []byte("ab\x00\x00cdef")
				c.ReadSize = 8
			case "hole-before-offset":
				expected = []byte("abcd\x00\x00\x00x")
			}
			var out bytes.Buffer
			n, err := c.ReadPlusToProgress(context.Background(), []byte("file"), uint64(len(expected)), &out, nil)
			if err != nil || n != int64(len(expected)) || !bytes.Equal(out.Bytes(), expected) {
				t.Fatal(n, err, out.Bytes())
			}
			if kind == "whole-hole" && calls != 3 {
				t.Fatal("unbounded hole output", calls)
			}
		})
	}
}

func TestV42ReadPlusInvalidReplies(t *testing.T) {
	unknown := encoder{}
	unknown.u32(1)
	unknown.u32(1)
	unknown.u32(7)
	unknown.u64(0)
	badBool := plusReply(true)
	badBool[3] = 2
	excess := encoder{}
	excess.u32(0)
	excess.u32(1025)
	overflow := encoder{}
	overflow.u32(1)
	overflow.u32(1)
	overflow.u32(1)
	overflow.u64(math.MaxUint64 - 2)
	overflow.u64(8)
	for name, wire := range map[string]encoder{
		"unknown": unknown, "bad-bool": badBool, "excess": excess, "overflow": overflow,
		"gap":            plusReply(true, readPlusPart{offset: 1, end: 4}),
		"overlap":        plusReply(true, readPlusPart{end: 2}, readPlusPart{offset: 1, end: 4}),
		"oversized-data": plusReply(true, readPlusPart{data: []byte("12345")}),
		"after-interval": plusReply(true, readPlusPart{end: 5}, readPlusPart{offset: 5, end: 6}),
		"empty-not-eof":  plusReply(false),
		"zero-hole":      plusReply(false, readPlusPart{}),
		"short-eof":      plusReply(true, readPlusPart{data: []byte("ab")}),
		"truncated":      {0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c := plusPeer(t, func(uint64, uint32) (encoder, Status) { calls++; return wire, 0 })
			var out bytes.Buffer
			n, err := c.ReadPlusToProgress(context.Background(), []byte("file"), 4, &out, nil)
			if err == nil || n != 0 || out.Len() != 0 || calls != 1 {
				t.Fatal("invalid reply exposed data", n, err, out.Len(), calls)
			}
		})
	}
	t.Run("unsupported", func(t *testing.T) {
		c := plusPeer(t, func(uint64, uint32) (encoder, Status) { return nil, 10004 })
		if _, err := c.ReadPlusToProgress(context.Background(), []byte("file"), 4, io.Discard, nil); !errors.Is(err, Status(10004)) {
			t.Fatal(err)
		}
	})
	t.Run("no-eof", func(t *testing.T) {
		c := plusPeer(t, func(uint64, uint32) (encoder, Status) { return plusReply(false, readPlusPart{data: []byte("abcd")}), 0 })
		if n, err := c.ReadPlusToProgress(context.Background(), []byte("file"), 4, io.Discard, nil); err == nil || n != 4 {
			t.Fatal(n, err)
		}
	})
}

type plusWriter func([]byte) (int, error)

func (w plusWriter) Write(b []byte) (int, error) { return w(b) }

func TestV42ReadPlusLocalFailures(t *testing.T) {
	for _, kind := range []string{"short", "write-error", "cancel", "lost-lock"} {
		t.Run(kind, func(t *testing.T) {
			c := plusPeer(t, func(uint64, uint32) (encoder, Status) { return plusReply(true, readPlusPart{end: 65536}), 0 })
			c.ReadSize = 65536
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writes := 0
			writer := plusWriter(func(b []byte) (int, error) {
				writes++
				if len(b) > 32768 {
					t.Fatal("hole-sized allocation")
				}
				if kind == "short" {
					return 1, nil
				}
				if kind == "write-error" {
					return 1, io.ErrClosedPipe
				}
				return len(b), nil
			})
			n, err := c.ReadPlusToProgress(ctx, []byte("file"), 65536, writer, func(uint64) {
				if kind == "cancel" {
					cancel()
				}
				if kind == "lost-lock" {
					c.v4.stateLost.Store(true)
				}
			})
			if err == nil || writes != 1 {
				t.Fatal(n, err, writes)
			}
		})
	}
	for _, c := range []*Client{{}, {v4: &v4Client{minor: 1}}, {ReadSize: 0, v4: &v4Client{minor: 2}}} {
		if _, err := c.ReadPlusToProgress(context.Background(), nil, 0, io.Discard, nil); err == nil {
			t.Fatal("invalid client accepted")
		}
	}
	if _, err := (&Client{ReadSize: 1, v4: &v4Client{minor: 2}}).ReadPlusToProgress(context.Background(), nil, math.MaxUint64, io.Discard, nil); err == nil {
		t.Fatal("oversized source accepted")
	}
}

func FuzzReadPlusDecoder(f *testing.F) {
	f.Add([]byte(plusReply(true, readPlusPart{end: 4096})), uint64(0), uint32(4096))
	f.Add([]byte(plusReply(true)), uint64(math.MaxUint64), uint32(1))
	f.Fuzz(func(t *testing.T, wire []byte, offset uint64, count uint32) {
		d := &decoder{b: wire}
		_, _, _ = decodeReadPlus(d, offset, count)
	})
}
