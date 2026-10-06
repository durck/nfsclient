package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Independent record/XDR oracle: do not use production encoders, decoders,
// readRecord, or peer4 to decide the actual RPC message length or cache flag.
func channelWirePeer(t *testing.T, limits sessionChannelLimits, reply func([]byte) []byte) (*v4Client, *atomic.Int32) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	rpc := &rpcClient{conn: client, timeout: time.Second}
	v := &v4Client{c: &Client{nfs: rpc, ReadSize: 65536, WriteSize: 65536}, minor: 1, session: bytes.Repeat([]byte{7}, 16), sequence: 1, channel: limits}
	var calls atomic.Int32
	go func() {
		for {
			var header [4]byte
			if _, err := io.ReadFull(server, header[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(header[:])
			if n&0x80000000 == 0 || n&0x7fffffff > 1<<20 {
				t.Error("invalid independent RPC record")
				return
			}
			request := make([]byte, n&0x7fffffff)
			if _, err := io.ReadFull(server, request); err != nil {
				return
			}
			calls.Add(1)
			response := reply(request)
			if response == nil {
				server.Close()
				return
			}
			packet := binary.BigEndian.AppendUint32(nil, 0x80000000|uint32(len(response)))
			packet = append(packet, response...)
			if _, err := server.Write(packet); err != nil {
				return
			}
		}
	}()
	return v, &calls
}

func channelWords(values ...uint32) []byte {
	var b []byte
	for _, n := range values {
		b = binary.BigEndian.AppendUint32(b, n)
	}
	return b
}

func channelReply(request []byte, last []byte) []byte {
	// AUTH_SYS request header is 72 bytes (no supplementary groups).
	// Compound header is 12 and SEQUENCE request is 36.
	b := append([]byte(nil), request[:4]...)
	b = append(b, channelWords(1, 0, 0, 0, 0, 0, 0, 3, 53, 0)...)
	b = append(b, request[88:104]...)
	b = append(b, channelWords(binary.BigEndian.Uint32(request[104:]), 0, 0, 0, 0, 22, 0)...)
	return append(b, last...)
}

func TestSessionChannelWireWriteBoundary(t *testing.T) {
	for _, requestLimit := range []uint32{512, 1023, 2048, 4096, 8192} {
		t.Run(fmt.Sprint(requestLimit), func(t *testing.T) {
			var accepted uint32
			v, calls := channelWirePeer(t, sessionChannelLimits{requestLimit, 128, 112, 3}, func(request []byte) []byte {
				// WRITE fixed prefix ends at byte 168 for a four-byte handle.
				if len(request) != int(requestLimit&^3) {
					t.Errorf("wire request=%d limit=%d", len(request), requestLimit)
				}
				if got := binary.BigEndian.Uint32(request[116:]); got != 1 {
					t.Errorf("mutation cachethis=%d", got)
				}
				n := binary.BigEndian.Uint32(request[164:])
				if int(n)+168 != len(request) {
					t.Errorf("WRITE length=%d record=%d", n, len(request))
				}
				return channelReply(request, channelWords(38, 0, n, 2, 0, 0))
			})
			args := make(encoder, 28)
			args.u32(16384)
			args = append(args, bytes.Repeat([]byte{3}, 16384)...)
			if err := v.compound(context.Background(), fh4([]byte("file")), op4(38, args, func(d *decoder) { accepted = d.u32(); d.take(12) })); err != nil {
				t.Fatal(err)
			}
			if accepted != (requestLimit-168)&^3 || calls.Load() != 1 || v.sequence != 2 {
				t.Fatalf("accepted=%d calls=%d sequence=%d", accepted, calls.Load(), v.sequence)
			}
		})
	}
}

func TestSessionChannelCacheAndOperationRefusalIsLocal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits sessionChannelLimits
		ops    []v4Op
	}{
		{"cache-one-byte-short", sessionChannelLimits{512, 512, 111, 3}, []v4Op{fh4([]byte("file")), op4(38, make(encoder, 32), nil)}},
		{"operation-count", sessionChannelLimits{512, 512, 512, 2}, []v4Op{fh4([]byte("file")), op4(28, nil, nil)}},
		{"request-one-byte-short", sessionChannelLimits{131, 512, 512, 3}, []v4Op{fh4([]byte("file")), op4(28, encoder{0, 0, 0, 0}, nil)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, calls := channelWirePeer(t, tc.limits, func([]byte) []byte { t.Error("refused request transmitted"); return nil })
			err := v.compound(context.Background(), tc.ops...)
			if !channelNotSent(err) || calls.Load() != 0 || v.sequence != 1 || v.stateLost.Load() || v.c.nfs.closed {
				t.Fatalf("err=%v calls=%d seq=%d lost=%t closed=%t", err, calls.Load(), v.sequence, v.stateLost.Load(), v.c.nfs.closed)
			}
		})
	}
}

func TestSessionChannelReadResponseBoundary(t *testing.T) {
	for _, limit := range []uint32{108, 512, 1023, 4096} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			v, _ := channelWirePeer(t, sessionChannelLimits{512, limit, 88, 3}, func(request []byte) []byte {
				if binary.BigEndian.Uint32(request[116:]) != 0 {
					t.Error("READ unnecessarily cached")
				}
				n := binary.BigEndian.Uint32(request[160:])
				if n != (limit-104)&^3 {
					t.Errorf("READ count=%d reply limit=%d", n, limit)
				}
				last := channelWords(25, 0, 1, n)
				last = append(last, make([]byte, n)...)
				reply := channelReply(request, last)
				if len(reply) != int(limit&^3) {
					t.Errorf("reply=%d limit=%d", len(reply), limit)
				}
				return reply
			})
			args := make(encoder, 24)
			args.u32(65536)
			if err := v.compound(context.Background(), fh4([]byte("file")), op4(25, args, func(d *decoder) { d.boolean(); d.opaque(65536) })); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionChannelOversizedReplyInvalidatesSlot(t *testing.T) {
	v, _ := channelWirePeer(t, sessionChannelLimits{512, 112, 112, 3}, func(request []byte) []byte {
		return append(channelReply(request, channelWords(38, 0, 0, 2, 0, 0)), 0, 0, 0, 0)
	})
	err := v.compound(context.Background(), fh4([]byte("file")), op4(38, make(encoder, 32), nil))
	if err == nil || !strings.Contains(err.Error(), "reply exceeds") || !v.stateLost.Load() || v.sequence != 1 || !v.c.nfs.closed {
		t.Fatalf("err=%v lost=%t seq=%d closed=%t", err, v.stateLost.Load(), v.sequence, v.c.nfs.closed)
	}
}

func TestSessionChannelInitializationLowerBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits sessionChannelLimits
		valid  bool
	}{
		{"minimal", sessionChannelLimits{128, 104, 88, 3}, true},
		{"request", sessionChannelLimits{127, 104, 88, 3}, false},
		{"response", sessionChannelLimits{128, 103, 88, 3}, false},
		{"cache", sessionChannelLimits{128, 104, 87, 3}, false},
		{"operations", sessionChannelLimits{128, 104, 88, 2}, false},
		{"small-usable", sessionChannelLimits{512, 512, 128, 4}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := channelWirePeer(t, sessionChannelLimits{}, func([]byte) []byte { return nil })
			err := v.setChannel(tc.limits)
			if (err == nil) != tc.valid {
				t.Fatalf("%v", err)
			}
			if v.maxReplyPayload > tc.limits.Response || v.maxRequestPayload > tc.limits.Request {
				t.Fatal("payload budget underflow")
			}
		})
	}
}

type channelTestGSS struct{ testMIC }

func (channelTestGSS) TokenSizes() (int, int, error) { return 32, 13, nil }
func (channelTestGSS) Seal(b []byte) ([]byte, error) { return append(make([]byte, 13), b...), nil }

func TestSessionChannelGSSWireSizesAndFinalGuard(t *testing.T) {
	for _, service := range []uint32{1, 2, 3} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			v, calls := channelWirePeer(t, sessionChannelLimits{}, func([]byte) []byte { t.Error("oversize protected RPC transmitted"); return nil })
			g := &rpcGSS{context: channelTestGSS{}, handle: []byte("context"), service: service, established: true}
			v.c.nfs.gss = g
			request, response, protection, err := rpcSizes(Auth{}, g)
			if err != nil {
				t.Fatal(err)
			}
			wantProtection := map[uint32]uint64{1: 0, 2: 44, 3: 24}[service]
			if request != 100 || response != 56 || protection != wantProtection || g.seq != 0 {
				t.Fatalf("sizes %d/%d/%d seq=%d", request, response, protection, g.seq)
			}
			// Eight payload bytes; count excludes the TCP record marker. The
			// authenticated message exceeds this budget by exactly one byte.
			budget := sessionWireBudget{uint32(100 + 8 + wantProtection - 1), 512}
			ctx := context.WithValue(context.Background(), sessionWireBudgetKey{}, budget)
			_, err = v.c.nfs.call(ctx, nfsProgram, 4, 1, &Auth{}, make(encoder, 8))
			if !channelNotSent(err) || calls.Load() != 0 || v.c.nfs.closed {
				t.Fatalf("err=%v calls=%d closed=%t", err, calls.Load(), v.c.nfs.closed)
			}
		})
	}
}

func TestSessionChannelCachedMutationErrorAdvancesWithoutReplay(t *testing.T) {
	v, calls := channelWirePeer(t, sessionChannelLimits{512, 512, 112, 3}, func(request []byte) []byte {
		if binary.BigEndian.Uint32(request[116:]) != 1 {
			t.Error("mutation caching disabled after cache error")
		}
		seq := binary.BigEndian.Uint32(request[104:])
		if seq == 1 {
			b := channelReply(request, channelWords(38, 10067))
			binary.BigEndian.PutUint32(b[24:], 10067)
			return b
		}
		if seq != 2 {
			t.Errorf("unexpected slot sequence %d", seq)
		}
		return channelReply(request, channelWords(38, 0, 0, 2, 0, 0))
	})
	args := make(encoder, 32)
	err := v.compound(context.Background(), fh4([]byte("file")), op4(38, args, nil))
	if err != Status(10067) || calls.Load() != 1 || v.sequence != 2 || v.stateLost.Load() {
		t.Fatalf("err=%v calls=%d seq=%d", err, calls.Load(), v.sequence)
	}
	if err = v.compound(context.Background(), fh4([]byte("file")), op4(38, args, func(d *decoder) { d.take(16) })); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || v.sequence != 3 {
		t.Fatalf("calls=%d seq=%d", calls.Load(), v.sequence)
	}
}

func TestSessionCreateReturnsHandleInMutationCompound(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprint(directory), func(t *testing.T) {
			var calls []uint32
			v := peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
				calls = append(calls, code)
				var e encoder
				switch code {
				case 6:
					kind := d.u32()
					if kind == 5 {
						d.str()
					}
					d.str()
					readBitmap4(d)
					d.opaque(32)
					e.u32(1)
					e.u64(1)
					e.u64(2)
					bitmap4(&e, 33)
				case 10:
					e.opaque([]byte("made"))
				case 15:
					// Directory creation performs a later ordinary lookup.
					if fmt.Sprint(calls) != "[6 10 15]" {
						t.Errorf("CREATE lacks immediate GETFH: %v", calls)
					}
					d.str()
					return nil, Status(2), nil
				default:
					return nil, 0, fmt.Errorf("unexpected operation %d", code)
				}
				return e, 0, nil
			})
			if directory {
				_, err := v.create(context.Background(), []byte("dir"), "made", 0755, true)
				if err != Status(2) {
					t.Fatal(err)
				}
			} else {
				if err := v.c.Symlink(context.Background(), []byte("dir"), "made", "target"); err != nil {
					t.Fatal(err)
				}
				if fmt.Sprint(calls) != "[6 10]" {
					t.Fatalf("CREATE lacks immediate GETFH: %v", calls)
				}
			}
		})
	}
}
