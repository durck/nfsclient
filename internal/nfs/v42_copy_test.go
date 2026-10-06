package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

func copyPeer(t *testing.T, reply operationReply4) *Client {
	t.Helper()
	v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		if code != 53 {
			return reply(code, d)
		}
		e = append(e, d.take(16)...)
		e.u32(d.u32())
		//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
		if d.u32() != 0 || d.u32() != 0 || !d.boolean() {
			return nil, 0, errors.New("copy slot should cache mutation reply")
		}
		for range 4 {
			e.u32(0)
		}
		return e, 0, nil
	})
	v.session = bytes.Repeat([]byte{9}, 16)
	v.sequence = 1
	v.locks = map[uint64]*v4Lock{
		1: {info: LockInfo{ID: 1, Length: LockToEOF}, file: &v4Open{fh: []byte("source"), auth: v.c.Auth}, sid: bytes.Repeat([]byte{7}, 16)},
		2: {info: LockInfo{ID: 2, Length: LockToEOF, Write: true}, file: &v4Open{fh: []byte("destination"), auth: v.c.Auth}, sid: bytes.Repeat([]byte{8}, 16)},
	}
	return v.c
}

func TestV42CopyWire(t *testing.T) {
	for _, kind := range []string{"stable", "unstable", "data-sync", "short", "zero", "clone", "unsupported", "denied", "no-reqs", "no-reqs-truncated", "async", "excess", "bad-stable", "not-consecutive", "not-synchronous", "bad-bool", "truncated", "commit-verifier", "commit-denied", "commit-truncated", "clone-trailing"} {
		t.Run(kind, func(t *testing.T) {
			copies, commits, saves := 0, 0, 0
			clone := kind == "clone" || kind == "clone-trailing"
			c := copyPeer(t, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 32:
					saves++
					return nil, 0, nil
				case 60, 71:
					copies++
					if (code == 71) != clone || !bytes.Equal(d.take(16), bytes.Repeat([]byte{7}, 16)) || !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) || d.u64() != 1<<40 || d.u64() != 1<<41 || d.u64() != 8192 {
						return nil, 0, errors.New("invalid copy arguments")
					}
					//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
					if !clone && (!d.boolean() || !d.boolean() || d.u32() != 0) {
						return nil, 0, errors.New("COPY must require synchronous consecutive local-server copy")
					}
					if kind == "unsupported" {
						return nil, 10004, nil
					}
					if kind == "denied" {
						return nil, 13, nil
					}
					if strings.HasPrefix(kind, "no-reqs") {
						e.u32(1)
						if kind == "no-reqs" {
							e.u32(0)
						}
						return e, 10094, nil
					}
					if clone {
						if kind == "clone-trailing" {
							e.u32(0)
						}
						return e, 0, nil
					}
					if kind == "async" {
						e.u32(1)
						return e, 0, nil
					}
					e.u32(0)
					count := uint64(8192)
					if kind == "short" {
						count = 17
					}
					if kind == "zero" {
						count = 0
					}
					if kind == "excess" {
						count = 8193
					}
					e.u64(count)
					stable := uint32(2)
					if kind == "unstable" || strings.HasPrefix(kind, "commit-") {
						stable = 0
					}
					if kind == "data-sync" {
						stable = 1
					}
					if kind == "bad-stable" {
						stable = 3
					}
					e.u32(stable)
					e = append(e, []byte("verifier")...)
					if kind == "truncated" {
						return e, 0, nil
					}
					consecutive, synchronous := uint32(1), uint32(1)
					if kind == "not-consecutive" {
						consecutive = 0
					}
					if kind == "not-synchronous" {
						synchronous = 0
					}
					if kind == "bad-bool" {
						synchronous = 2
					}
					e.u32(consecutive)
					e.u32(synchronous)
				case 5:
					commits++
					if d.u64() != 1<<41 || d.u32() != 0 {
						return nil, 0, errors.New("invalid copy COMMIT")
					}
					if kind == "commit-denied" {
						return nil, 5, nil
					}
					if kind == "commit-truncated" {
						return []byte{1}, 0, nil
					}
					if kind == "commit-verifier" {
						return encoder("changed!"), 0, nil
					}
					return encoder("verifier"), 0, nil
				default:
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				return e, 0, nil
			})
			copy := c.CopyRange
			if clone {
				copy = c.CloneRange
			}
			n, err := copy(context.Background(), []byte("source"), []byte("destination"), 1<<40, 1<<41, 8192)
			if copies != 1 || saves != 1 {
				t.Fatal("copy omitted or replayed", copies, saves)
			}
			good := kind == "stable" || kind == "unstable" || kind == "data-sync" || kind == "clone"
			if good {
				if err != nil || n != 8192 {
					t.Fatal(n, err)
				}
			} else if err == nil {
				t.Fatal("bad reply accepted", n)
			}
			if (kind == "short" && (n != 17 || !errors.Is(err, io.ErrShortWrite))) || (kind == "zero" && (n != 0 || !errors.Is(err, io.ErrShortWrite))) {
				t.Fatal(n, err)
			}
			if (kind == "unsupported" && !errors.Is(err, Status(10004))) || (kind == "denied" && !errors.Is(err, Status(13))) {
				t.Fatal(err)
			}
			needsCommit := kind == "unstable" || kind == "data-sync" || strings.HasPrefix(kind, "commit-")
			if (commits == 1) != needsCommit {
				t.Fatal("wrong COMMIT count", commits)
			}
			if strings.HasPrefix(kind, "commit-") && n != 8192 {
				t.Fatal("acknowledged bytes lost", n, err)
			}
		})
	}
}

func TestV42CopyValidation(t *testing.T) {
	for _, clone := range []bool{false, true} {
		for _, kind := range []string{"v3", "v41", "same", "empty", "zero", "source-overflow", "destination-overflow", "source-partial", "destination-partial", "destination-read", "identity", "lost", "canceled"} {
			t.Run(fmt.Sprintf("%t/%s", clone, kind), func(t *testing.T) {
				c := copyPeer(t, func(uint32, *decoder) (encoder, Status, error) { t.Error("invalid copy sent RPC"); return nil, 0, nil })
				src, dst := []byte("source"), []byte("destination")
				a, b, n := uint64(0), uint64(0), uint64(1)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch kind {
				case "v3":
					c.v4 = nil
				case "v41":
					c.v4.minor = 1
				case "same":
					dst = src
				case "empty":
					src = nil
				case "zero":
					n = 0
				case "source-overflow":
					a = ^uint64(0)
				case "destination-overflow":
					b = ^uint64(0)
				case "source-partial":
					c.v4.locks[1].info.Length = 1
				case "destination-partial":
					c.v4.locks[2].info.Offset = 1
				case "destination-read":
					c.v4.locks[2].info.Write = false
				case "identity":
					c.Auth.UID++
				case "lost":
					c.v4.stateLost.Store(true)
				case "canceled":
					cancel()
				}
				copy := c.CopyRange
				if clone {
					copy = c.CloneRange
				}
				if _, err := copy(ctx, src, dst, a, b, n); err == nil {
					t.Fatal("invalid copy accepted")
				}
			})
		}
	}
}
