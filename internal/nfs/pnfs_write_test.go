package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPNFSWriteWire(t *testing.T) {
	runPNFSWriteWire(t, "")
}

func runPNFSWriteWire(t *testing.T, security string) {
	secure := strings.HasPrefix(security, "tls-")
	security = strings.TrimPrefix(security, "tls-")
	for _, parallel := range []int{1, 8} {
		for _, dense := range []bool{false, true} {
			for _, mode := range []string{"ok", "short", "unstable", "data-sync", "mds-commit", "bad-verifier", "zero", "oversize", "bad-stability", "read-layout", "recall", "commit-error", "layoutcommit-error", "return-error", "reader-error", "no-lock", "read-lock", "parallel", "past-eof", "drop", "restart", "cancel", "extend", "extend-bad-size"} {
				if security != "" && mode != "ok" && mode != "unstable" && mode != "mds-commit" && mode != "extend" {
					continue
				}
				t.Run(fmt.Sprintf("parallel=%d/dense=%t/%s", parallel, dense, mode), func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					nonce, sid := bytes.Repeat([]byte{6}, 16), bytes.Repeat([]byte{7}, 16)
					data := bytes.Repeat([]byte{'p'}, 96)
					var writes, commits, layouts, returns atomic.Int32
					var v *v4Client
					var written bytes.Buffer
					var currentHandle string
					commit := func(d *decoder) (encoder, Status, error) {
						commits.Add(1)
						offset, n := d.u64(), d.u32()
						expected := uint64(16+written.Len()) - uint64(n)
						if dense && mode != "mds-commit" {
							expected %= 64
						}
						if offset != expected || n == 0 {
							return nil, 0, errors.New("invalid COMMIT range")
						}
						if mode == "commit-error" {
							return nil, 5, nil
						}
						if mode == "bad-verifier" {
							return encoder(bytes.Repeat([]byte{2}, 8)), 0, nil
						}
						return encoder(bytes.Repeat([]byte{1}, 8)), 0, nil
					}
					ds := peer4WithHandle(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
						var e encoder
						switch code {
						case 42:
							if !bytes.Equal(d.take(8), nonce[:8]) || d.str() != fmt.Sprintf("nfs-viewer-%x", nonce) || d.u32() != 0x40000 || d.u32() != 0 || d.u32() != 0 {
								return nil, 0, errors.New("wrong DS identity")
							}
							e.u64(123)
							e.u32(2)
							e.u32(0x40000)
							e.u32(0)
							e.u64(1)
							e.opaque([]byte("server"))
							e.opaque([]byte("scope"))
							e.u32(0)
						case 43:
							d.u64()
							d.u32()
							d.u32()
							d.take(56)
							d.u32()
							d.u32()
							e = append(e, bytes.Repeat([]byte{9}, 16)...)
							e.u32(2)
							e.u32(0)
							for range 2 {
								for _, n := range []uint32{0, 1 << 20, 1 << 20, 65536, 16, 1, 0} {
									e.u32(n)
								}
							}
						case 53:
							e = append(e, d.take(16)...)
							e.u32(d.u32())
							d.take(12)
							for range 4 {
								e.u32(0)
							}
						case 38:
							writes.Add(1)
							if d.u32() != 0 || !bytes.Equal(d.take(12), sid[4:]) {
								return nil, 0, errors.New("invalid DS stateid")
							}
							off, stable, b := d.u64(), d.u32(), d.opaque(1<<20)
							logical := 16 + uint64(written.Len())
							expected := logical
							handle := "ds-file"
							if dense {
								expected %= 64
								handle = fmt.Sprintf("ds-%d", logical/64%2)
							}
							if stable != 0 || off != expected || logical+uint64(len(b)) > 112 || currentHandle != handle {
								return nil, 0, errors.New("out-of-order/out-of-range WRITE")
							}
							n := len(b)
							if mode == "short" && n > 1 {
								n /= 2
							}
							written.Write(b[:n])
							e.u32(uint32(n))
							if mode == "zero" {
								e = nil
								e.u32(0)
							}
							if mode == "oversize" {
								e = nil
								e.u32(uint32(len(b) + 1))
							}
							stable = 2
							if mode == "unstable" || mode == "mds-commit" || mode == "bad-verifier" || mode == "commit-error" {
								stable = 0
							}
							if mode == "data-sync" {
								stable = 1
							}
							if mode == "bad-stability" {
								stable = 3
							}
							e.u32(stable)
							e = append(e, bytes.Repeat([]byte{1}, 8)...)
							if mode == "restart" && writes.Load() > 1 {
								e[len(e)-1] = 2
							}
							if mode == "recall" {
								v.recall.mu.Lock()
								v.recall.recalled = true
								v.recall.mu.Unlock()
							}
						case 5:
							if mode == "mds-commit" {
								return nil, 0, errors.New("COMMIT sent to wrong server")
							}
							return commit(d)
						case 44:
							d.take(16)
						default:
							return nil, 0, fmt.Errorf("unexpected DS op %d", code)
						}
						return e, 0, nil
					}, func(fh []byte) error { currentHandle = string(fh); return nil })
					drop := 0
					if mode == "drop" {
						drop = 3
					}
					var endpoint string
					var tlsOptions []mitTLSOptions
					if secure {
						policy, server := pnfsTLSFixture(t, "data")
						tlsOptions = []mitTLSOptions{{server: server(0), client: policy}}
					}
					if security != "" {
						endpoint = pnfsMITEndpoint(t, ds.c.nfs.conn, nil, tlsOptions...)
					} else {
						endpoint = pnfsPeerEndpoint(t, ds, drop)
					}
					v = peer4(t, 1, func(code uint32, d *decoder) (encoder, Status, error) {
						var e encoder
						switch code {
						case 9:
							wanted := readBitmap4(d)
							size := uint64(128)
							if mode == "extend" || mode == "extend-bad-size" {
								size = 8
								if written.Len() > 0 {
									size = 16 + uint64(written.Len())
								}
							}
							return replacementTestReply(wanted, map[uint32]encoder{1: replacementTestU32(1), 4: replacementTestU64(size)}), 0, nil
						case 50:
							if d.u32() != 0 || d.u32() != 1 || d.u32() != 2 || d.u64() != 0 || d.u64() != ^uint64(0) || d.u64() != 1 || !bytes.Equal(d.take(16), sid) || d.u32() != 32768 {
								return nil, 0, errors.New("expected RW LAYOUTGET")
							}
							e.u32(1)
							e = append(e, bytes.Repeat([]byte{8}, 16)...)
							e.u32(1)
							e.u64(0)
							e.u64(^uint64(0))
							m := uint32(2)
							if mode == "read-layout" {
								m = 1
							}
							e.u32(m)
							e.u32(1)
							body := encoder(make([]byte, 16))
							flags := uint32(64)
							if dense {
								flags |= 1
							}
							if mode == "mds-commit" {
								flags |= 2
							}
							body.u32(flags)
							body.u32(0)
							body.u64(0)
							if dense {
								body.u32(2)
								body.opaque([]byte("ds-0"))
								body.opaque([]byte("ds-1"))
							} else {
								body.u32(1)
								body.opaque([]byte("ds-file"))
							}
							e.opaque(body)
						case 47:
							d.take(28)
							var body encoder
							indices := []uint32{1, 0, 1, 1}
							if dense {
								indices = []uint32{2, 0, 0, 1, 1}
							}
							for _, n := range indices {
								body.u32(n)
							}
							body.str("tcp")
							body.str("192.0.2.10.8.1")
							e.u32(1)
							e.opaque(body)
							e.u32(0)
						case 5:
							if mode != "mds-commit" {
								return nil, 0, errors.New("MDS COMMIT without flag")
							}
							return commit(d)
						case 49:
							layouts.Add(1)
							off, n := d.u64(), d.u64()
							if n == 0 || off < 16 || off+n > 112 || d.boolean() || !bytes.Equal(d.take(16), bytes.Repeat([]byte{8}, 16)) || !d.boolean() || d.u64() != off+n-1 || d.boolean() || d.u32() != 1 || len(d.opaque(64)) != 0 {
								return nil, 0, errors.New("invalid LAYOUTCOMMIT")
							}
							if mode == "layoutcommit-error" {
								return nil, 5, nil
							}
							if mode == "extend" || mode == "extend-bad-size" {
								e.u32(1)
								size := off + n
								if mode == "extend-bad-size" {
									size++
								}
								e.u64(size)
							} else {
								e.u32(0)
							}
						case 51:
							returns.Add(1)
							d.take(16)
							d.u64()
							d.u64()
							d.take(16)
							d.opaque(64)
							if mode == "return-error" {
								return nil, 5, nil
							}
							e.u32(0)
						default:
							return nil, 0, fmt.Errorf("unexpected MDS op %d", code)
						}
						return e, 0, nil
					})
					v.clientNonce = nonce
					v.recall = &layoutRecall{}
					v.c.config = &Config{PNFS: true, Timeout: time.Second}
					if security != "" {
						pnfsMITWrapClient(t, v.c, security, nil, tlsOptions...)
					}
					v.c.WriteSize = 64
					l := &v4Lock{info: LockInfo{ID: 1, Write: mode != "read-lock", Length: LockToEOF}, sid: sid, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}}
					v.locks = map[uint64]*v4Lock{1: l}
					if mode == "no-lock" {
						v.locks = nil
					}
					options := PNFSOptions{Parallelism: parallel, DataServers: map[string]string{"192.0.2.10:2049": endpoint}}
					if security != "" {
						options.SPNs = map[string]string{endpoint: "nfs/ds.nfs.test"}
					}
					options.Extend = mode == "extend" || mode == "extend-bad-size"
					if mode == "parallel" {
						options.Parallelism = 2
					}
					offset := uint64(16)
					if mode == "past-eof" {
						offset = 64
					}
					var input io.Reader = bytes.NewReader(data)
					if mode == "reader-error" {
						input = bytes.NewReader(data[:3])
					}
					progress := func(uint64) {
						if mode == "cancel" {
							cancel()
						}
					}
					n, err := v.c.WritePNFSRangeFromProgress(ctx, []byte("file"), offset, 96, input, options, progress)
					success := mode == "ok" || mode == "short" || mode == "unstable" || mode == "data-sync" || mode == "mds-commit" || mode == "extend" || mode == "parallel"
					if success {
						if err != nil || n != 96 || !bytes.Equal(written.Bytes(), data) || layouts.Load() < 2 || returns.Load() != 1 {
							t.Fatalf("write %d %v bytes=%d layouts=%d returns=%d", n, err, written.Len(), layouts.Load(), returns.Load())
						}
						if (mode == "unstable" || mode == "mds-commit") != (commits.Load() > 0) {
							t.Fatal("wrong durability path")
						}
					} else if err == nil {
						t.Fatal("expected refusal", mode, n)
					}
					if mode == "read-layout" || mode == "reader-error" || mode == "no-lock" || mode == "read-lock" || mode == "past-eof" {
						if writes.Load() != 0 {
							t.Fatal("write before preflight")
						}
					}
					if mode == "recall" && (writes.Load() != 1 || layouts.Load() != 1 || n != 48) {
						t.Fatal("recall must flush known prefix before stopping", writes.Load(), layouts.Load(), n)
					}
					if mode == "drop" && (writes.Load() != 1 || n != 0 || layouts.Load() != 0 || returns.Load() != 0 || !v.stateLost.Load()) {
						t.Fatal("unknown WRITE must not replay or return layout")
					}
					if mode == "restart" && (writes.Load() != 2 || n != 48 || !v.stateLost.Load()) {
						t.Fatal("changed verifier must quarantine original state")
					}
					if mode == "cancel" && (writes.Load() != 1 || n != 48 || returns.Load() != 1) {
						t.Fatal("cancellation after committed prefix", n, writes.Load(), returns.Load())
					}
					if mode == "extend-bad-size" && (writes.Load() != 1 || n != 0 || !v.stateLost.Load()) {
						t.Fatal("unexpected extension size must quarantine state")
					}
				})
			}
		}
	}
}
