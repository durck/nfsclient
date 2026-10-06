package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"testing"
)

func TestPNFSIncrementalReadWire(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, packing := range []string{"dense", "sparse-many", "sparse-one", "sparse-mds"} {
			for _, parallel := range []int{1, 8} {
				for _, mode := range []string{"data", "holes", "denied", "cancel-hole", "recall-hole", "writer-hole"} {
					t.Run(fmt.Sprintf("4.%d/%s/%d/%s", minor, packing, parallel, mode), func(t *testing.T) {
						runPNFSStripedRead(t, minor, "acquire-paths-segments-"+packing, 128, mode, parallel)
					})
				}
			}
		}
	}
}

func TestPNFSIncrementalAcquisition(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"adjacent", "expanded", "wrap", "denied", "identity", "old-sequence", "zero-sequence", "recall"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				ctx := context.Background()
				open := bytes.Repeat([]byte{7}, 16)
				state := bytes.Repeat([]byte{8}, 16)
				binary.BigEndian.PutUint32(state, 17)
				calls, returns := 0, 0
				var v *v4Client
				v = peer4(t, minor, func(op uint32, d *decoder) (encoder, Status, error) {
					var e encoder
					if op == 51 {
						returns++
						d.take(32)
						if !bytes.Equal(d.take(16), state) {
							return nil, 0, errors.New("return did not use latest layout state")
						}
						d.opaque(64)
						e.u32(0)
						return e, 0, nil
					}
					if op != 50 {
						return nil, 0, fmt.Errorf("unexpected operation %d", op)
					}
					if calls >= 3 {
						return nil, 0, errors.New("layout request replayed")
					}
					wantOffset := []uint64{0, 95, 256}[calls]
					wantState := state
					if calls == 0 {
						wantState = open
					}
					if d.u32() != 0 || d.u32() != 1 || d.u32() != 1 || d.u64() != wantOffset || d.u64() != math.MaxUint64 || d.u64() != 1 || !bytes.Equal(d.take(16), wantState) || d.u32() != 32768 {
						return nil, 0, errors.New("bad incremental LAYOUTGET")
					}
					calls++
					if calls == 2 && mode == "denied" {
						return nil, Status(13), nil
					}
					spec := layoutSegmentSpec{wantOffset, math.MaxUint64, 0, 1, 1}
					if calls == 1 {
						spec.length = 95
					} else if calls == 2 {
						spec.length = 161
						if mode == "expanded" {
							spec.offset, spec.length = 64, 192
						}
					} else {
						spec.pattern = 256
					}
					e = segmentReply([]layoutSegmentSpec{spec})
					binary.BigEndian.PutUint32(state, uint32(16+calls))
					if mode == "wrap" {
						binary.BigEndian.PutUint32(state, []uint32{math.MaxUint32, 1, 2}[calls-1])
					}
					copy(e[4:20], state)
					if calls == 2 {
						switch mode {
						case "identity":
							e[8]++
						case "old-sequence":
							binary.BigEndian.PutUint32(e[4:8], 17)
						case "zero-sequence":
							binary.BigEndian.PutUint32(e[4:8], 0)
						case "recall":
							// A callback processed before this reply has the newer
							// seqid. The response must not erase the recall or state.
							binary.BigEndian.PutUint32(state, 19)
							v.recall.mu.Lock()
							v.recall.recalled = true
							v.recall.state = append([]byte(nil), state...)
							v.recall.mu.Unlock()
						}
					}
					return e, 0, nil
				})
				v.recall = &layoutRecall{}
				layouts, err := v.getLayout(ctx, []byte("file"), open, 529)
				if mode == "adjacent" || mode == "expanded" || mode == "wrap" {
					boundary := uint64(95)
					if mode == "expanded" {
						boundary = 64
					}
					if err != nil || calls != 3 || len(layouts) != 3 || layouts[0].length != boundary || layouts[1].offset != boundary || layouts[2].offset != 256 {
						t.Fatal("incomplete or overlapping coverage", calls, layouts, err)
					}
					if err := v.returnLayout([]byte("file")); err != nil {
						t.Fatal(err)
					}
				} else if err == nil || calls != 2 || v.recall.active {
					t.Fatal("failed acquisition remained usable", calls, err)
				}
				if mode == "identity" || mode == "old-sequence" || mode == "zero-sequence" {
					if !v.stateLost.Load() || returns != 0 {
						t.Fatal("malformed grant not quarantined")
					}
				} else if returns != 1 {
					t.Fatal("layout not returned exactly once", returns)
				}
				if mode == "denied" && !errors.Is(err, Status(13)) {
					t.Fatal("lost server status", err)
				}
			})
		}
	}
}

func TestPNFSIncrementalBound(t *testing.T) {
	for _, size := range []uint64{0, 64, 65} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			calls, returns := 0, 0
			state := bytes.Repeat([]byte{8}, 16)
			v := peer4(t, 1, func(op uint32, d *decoder) (encoder, Status, error) {
				if op == 51 {
					returns++
					d.take(32)
					if !bytes.Equal(d.take(16), state) {
						return nil, 0, errors.New("wrong cleanup state")
					}
					d.opaque(64)
					return encoder{0, 0, 0, 0}, 0, nil
				}
				if op != 50 || calls >= 64 {
					return nil, 0, errors.New("unbounded layout requests")
				}
				d.take(12)
				if d.u64() != uint64(calls) || d.u64() != math.MaxUint64 || d.u64() != min(size, uint64(1)) {
					return nil, 0, errors.New("incorrect bounded request")
				}
				input := d.take(16)
				if calls > 0 && !bytes.Equal(input, state) {
					return nil, 0, errors.New("layout state not chained")
				}
				d.u32()
				e := segmentReply([]layoutSegmentSpec{{uint64(calls), 1, 0, 1, 1}})
				calls++
				binary.BigEndian.PutUint32(state, uint32(calls))
				copy(e[4:20], state)
				return e, 0, nil
			})
			v.recall = &layoutRecall{}
			layouts, err := v.getLayout(context.Background(), []byte("file"), bytes.Repeat([]byte{7}, 16), size)
			if size <= 64 {
				if err != nil || len(layouts) != max(1, int(size)) {
					t.Fatal("valid bounded acquisition refused", len(layouts), err)
				}
				if err := v.returnLayout([]byte("file")); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || calls != 64 || v.recall.active || v.stateLost.Load() {
				t.Fatal("limit did not stop and clean up known state", calls, err)
			}
			if returns != 1 {
				t.Fatal("cleanup count", returns)
			}
		})
	}
}
