package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestApplicationDataBlockValidation(t *testing.T) {
	first := uint32(7)
	valid := ApplicationDataBlock{Offset: 1 << 40, BlockSize: 4096, BlockCount: 100, FirstNumber: &first, NumberOffset: 0, PatternOffset: 8, Pattern: []byte{0xfe, 0xed, 0xfa, 0xce}}
	if n, err := ValidateApplicationDataBlock(valid); err != nil || n != 409600 {
		t.Fatal(n, err)
	}
	for _, kind := range []string{"zero-size", "large-size", "zero-count", "multiply-overflow", "offset-overflow", "number-outside", "number-wrap", "overlap", "pattern-outside", "large-pattern", "unused-number", "unused-pattern"} {
		t.Run(kind, func(t *testing.T) {
			b := valid
			switch kind {
			case "zero-size":
				b.BlockSize = 0
			case "large-size":
				b.BlockSize = 1<<20 + 1
			case "zero-count":
				b.BlockCount = 0
			case "multiply-overflow":
				b.BlockCount = ^uint64(0)
			case "offset-overflow":
				b.Offset = ^uint64(0) - 5
			case "number-outside":
				b.NumberOffset = 4092
			case "number-wrap":
				b.BlockCount = 1 << 32
			case "overlap":
				b.PatternOffset = 7
			case "pattern-outside":
				b.PatternOffset = 4093
			case "large-pattern":
				b.BlockSize = 8192
				b.Pattern = make([]byte, 4097)
			case "unused-number":
				b.FirstNumber = nil
				b.NumberOffset = 8
			case "unused-pattern":
				b.Pattern = nil
			}
			if _, err := ValidateApplicationDataBlock(b); err == nil {
				t.Fatal("invalid ADB accepted", b)
			}
		})
	}
	for _, b := range []ApplicationDataBlock{
		{BlockSize: 1, BlockCount: 1},
		{BlockSize: 1 << 20, BlockCount: 2, PatternOffset: 1<<20 - 1, Pattern: []byte{7}},
		{BlockSize: 8, BlockCount: 1, FirstNumber: &first},
	} {
		if _, err := ValidateApplicationDataBlock(b); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWriteADBLifecycle(t *testing.T) {
	for _, form := range []string{"zero", "pattern", "number", "both"} {
		for _, mode := range []string{"sync", "unstable", "async", "cancel", "short", "denied", "truncated", "wrong-id"} {
			t.Run(form+"/"+mode, func(t *testing.T) {
				first := uint32(17)
				b := ApplicationDataBlock{Offset: 1 << 40, BlockSize: 4096, BlockCount: 3}
				if form == "number" || form == "both" {
					b.FirstNumber = &first
					b.NumberOffset = 8
				}
				if form == "pattern" || form == "both" {
					b.PatternOffset = 24
					b.Pattern = []byte{0xca, 0xfe, 0xde, 0xad}
				}
				calls, commits, cancels := 0, 0, 0
				var c *Client
				c = copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
					var e encoder
					switch code {
					case 70:
						calls++
						if !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) || d.u32() != 2 || d.u64() != 1<<40 || d.u64() != 4096 || d.u64() != 3 {
							return nil, 0, errors.New("wrong ADB header")
						}
						numberOffset, number := d.u64(), d.u32()
						if b.FirstNumber == nil && (numberOffset != ^uint64(0) || number != 0) || b.FirstNumber != nil && (numberOffset != 8 || number != 17) {
							return nil, 0, errors.New("wrong ADB number")
						}
						patternOffset, pattern := d.u64(), d.opaque(4096)
						if len(b.Pattern) == 0 && (patternOffset != ^uint64(0) || len(pattern) != 0) || len(b.Pattern) > 0 && (patternOffset != 24 || !bytes.Equal(pattern, []byte{0xca, 0xfe, 0xde, 0xad})) {
							return nil, 0, errors.New("wrong ADB pattern")
						}
						if mode == "denied" {
							return nil, 13, nil
						}
						if mode == "async" || mode == "cancel" || mode == "wrong-id" {
							e.u32(1)
							sid := byte(8)
							if mode == "wrong-id" {
								sid = 9
							}
							e = append(e, bytes.Repeat([]byte{sid}, 16)...)
						} else {
							e.u32(0)
						}
						count := uint64(12288)
						if mode == "short" {
							count = 4096
						}
						e.u64(count)
						if mode == "unstable" {
							e.u32(0)
						} else {
							e.u32(2)
						}
						e = append(e, []byte("verifier")...)
						if mode == "truncated" {
							e = e[:len(e)-1]
						}
						return e, 0, nil
					case 67:
						if !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) {
							return nil, 0, errors.New("wrong status ID")
						}
						_, err := c.v4.recall.callback(offloadCallback(c.v4.recall, 1, []byte("destination"), bytes.Repeat([]byte{8}, 16), offloadReply{count: 12288, stable: 2, verifier: []byte("verifier")}))
						if err != nil {
							return nil, 0, err
						}
						e.u64(12288)
						e.u32(1)
						e.u32(0)
						return e, 0, nil
					case 66:
						cancels++
						if !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) {
							return nil, 0, errors.New("wrong cancel ID")
						}
						return nil, 0, nil
					case 5:
						commits++
						if d.u64() != 1<<40 || d.u32() != 0 {
							return nil, 0, errors.New("wrong COMMIT")
						}
						return encoder("verifier"), 0, nil
					}
					return nil, 0, fmt.Errorf("unexpected ADB operation %d", code)
				})
				c.v4.recall = &layoutRecall{offloadEnabled: true, minor: 2, session: bytes.Repeat([]byte{9}, 16)}
				wait := 2 * time.Second
				if mode == "cancel" {
					wait = 25 * time.Millisecond
				}
				n, err := c.WriteApplicationDataBlocks(context.Background(), []byte("destination"), b, wait)
				ok := mode == "sync" || mode == "unstable" || mode == "async"
				if (err == nil) != ok || ok && n != 12288 || mode == "short" && n != 4096 || calls != 1 || (commits == 1) != (mode == "unstable") || (cancels == 1) != (mode == "cancel") {
					t.Fatal(n, err, calls, commits, cancels)
				}
			})
		}
	}
}
