package nfs

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
)

type zeroSource struct{}

func (zeroSource) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// Opt-in because this streams >8 GiB through real RPC framing. The peer is
// synthetic: it checks offset/count/stability boundaries without disk allocation.
func TestNFS3LargeOffsets(t *testing.T) {
	if os.Getenv("NFS_VIEWER_LARGE_TRANSFER") != "1" {
		t.Skip("set NFS_VIEWER_LARGE_TRANSFER=1 for >4 GiB read/write boundary validation")
	}
	const size uint64 = (uint64(1) << 32) + 17
	for _, write := range []bool{false, true} {
		t.Run(fmt.Sprintf("write=%t", write), func(t *testing.T) {
			var offset uint64
			chunk := make([]byte, 1<<20)
			c := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
				d.opaque(64)
				got := d.u64()
				if prog != nfsProgram || got != offset {
					return nil, fmt.Errorf("wrong 64-bit offset got=%d want=%d", got, offset)
				}
				requested := d.u32()
				var e encoder
				e.u32(0)
				if write {
					if proc != 7 || d.u32() != 2 {
						return nil, fmt.Errorf("wrong WRITE/stability")
					}
					data := d.opaque(1 << 20)
					if len(data) != int(requested) || uint64(len(data)) > size-offset {
						return nil, fmt.Errorf("bad large WRITE")
					}
					for _, b := range data {
						if b != 0 {
							return nil, fmt.Errorf("corrupt payload")
						}
					}
					offset += uint64(len(data))
					e.u32(0)
					e.u32(0)
					e.u32(uint32(len(data)))
					e.u32(2)
					e = append(e, make([]byte, 8)...)
				} else {
					if proc != 6 {
						return nil, fmt.Errorf("wrong READ")
					}
					n := min(uint64(requested), size-offset)
					offset += n
					e.u32(0)
					e.u32(uint32(n))
					if offset == size {
						e.u32(1)
					} else {
						e.u32(0)
					}
					e.opaque(chunk[:n])
				}
				return e, nil
			})
			c.ReadSize, c.WriteSize = 1<<20, 1<<20
			var last uint64
			progress := func(n uint64) {
				if n < last || n > size {
					t.Errorf("nonmonotonic progress %d", n)
				}
				last = n
			}
			var n int64
			var err error
			if write {
				n, err = c.WriteFromProgress(context.Background(), []byte{1}, io.LimitReader(zeroSource{}, int64(size)), progress)
			} else {
				n, err = c.ReadToProgress(context.Background(), []byte{1}, io.Discard, progress)
			}
			if err != nil || uint64(n) != size || offset != size || last != size {
				t.Fatalf("large transfer n=%d offset=%d last=%d: %v", n, offset, last, err)
			}
		})
	}
}
