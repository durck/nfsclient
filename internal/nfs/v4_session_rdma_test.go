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

// FreeBSD 14.4 a456f852d145 returns ca_rdma_ird = <0> for both
// CREATE_SESSION channels on TCP, with CONN_RDMA clear. RFC 8881 section
// 18.36.1 defines this as a bounded array of at most one uint32, not an
// empty-array-only representation of a connection without RDMA.
func TestV4SessionOptionalRDMAArray(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, tc := range []struct {
			name                 string
			foreCount, backCount uint32
			fore, back           []uint32
			wantError            string
			truncated            bool
		}{
			{name: "empty"},
			{name: "freebsd-singleton-zero", foreCount: 1, backCount: 1, fore: []uint32{0}, back: []uint32{0}},
			{name: "fore-singleton-zero", foreCount: 1, fore: []uint32{0}},
			{name: "back-singleton-zero", backCount: 1, back: []uint32{0}},
			{name: "oversized-fore", foreCount: 2, fore: []uint32{0, 0}, wantError: "invalid NFSv4 RDMA array"},
			{name: "oversized-back", backCount: 2, back: []uint32{0, 0}, wantError: "invalid NFSv4 RDMA array"},
			{name: "truncated-back-singleton", backCount: 1, truncated: true},
		} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, tc.name), func(t *testing.T) {
				sid := bytes.Repeat([]byte{3}, 16)
				v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
					var e encoder
					switch code {
					case 42:
						d.take(8)
						d.str()
						d.take(12)
						e.u64(123)
						e.u32(1)
						e.u32(0x20000)
						e.u32(0)
						e.u64(1)
						e.opaque([]byte("server"))
						e.opaque([]byte("scope"))
						e.u32(0)
					case 43:
						d.u64()
						d.u32()
						if d.u32() != 2 {
							return nil, 0, errors.New("unexpected RDMA request flag")
						}
						d.take(2 * 28)
						if d.u32() != pnfsCallbackProgram || d.u32() != 1 || d.u32() != 0 {
							return nil, 0, errors.New("callback setup differs")
						}
						e = append(e, sid...)
						e.u32(1)
						e.u32(2) // Backchannel association; no RDMA mode.
						for _, n := range []uint32{0, 1 << 20, 1 << 20, 65536, 16, 1, tc.foreCount} {
							e.u32(n)
						}
						for _, n := range tc.fore {
							e.u32(n)
						}
						for _, n := range []uint32{0, 65536, 65536, 65536, 8, 1, tc.backCount} {
							e.u32(n)
						}
						for _, n := range tc.back {
							e.u32(n)
						}
					case 53:
						e = append(e, d.take(16)...)
						e.u32(d.u32())
						d.take(12)
						for range 4 {
							e.u32(0)
						}
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
				v.recall = &layoutRecall{}
				err := v.initialize(context.Background())
				if tc.truncated {
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatalf("truncated RDMA value: %v", err)
					}
					return
				}
				if tc.wantError != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantError) {
						t.Fatalf("wanted %q, got %v", tc.wantError, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(v.session, sid) || !bytes.Equal(v.recall.session, sid) || v.recall.requestLimit != 65536 || v.recall.responseLimit != 65536 || v.recall.cacheLimit != 65536 || string(v.root) != "root" {
					t.Fatal("session fields or following operations misaligned")
				}
			})
		}
	}
}
