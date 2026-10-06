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

func TestFlexMITWriteDeviceRefresh(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, minor := range []uint32{1, 2} {
		for _, width := range []int{1, 3} {
			for _, parallel := range []int{1, 3} {
				for _, mode := range []string{"immediate", "inflight"} {
					t.Run(fmt.Sprintf("4.%d/w%d/p%d/%s", minor, width, parallel, mode), func(t *testing.T) {
						p := newFlexMITProfile(t, "krb5p", true)
						p.refreshMode = mode
						runFlexWriteWire(t, minor, 4, 2, width, parallel, "stable", p)
					})
				}
			}
		}
	}
}

// Exercise the public transfer API through protected paths, preserving the
// original lock and requiring every mirror's stable data before publication.
func TestPNFSMITWriteFailoverPublication(t *testing.T) {
	pnfsMITConfig(t, "krb5p", "nfs/ds.nfs.test")
	for _, kind := range []uint32{1, 4} {
		for _, parallel := range []int{1, 2} {
			for _, loss := range []string{"write-loss", "commit-loss", "second-loss"} {
				t.Run(fmt.Sprintf("layout%d/p%d/%s", kind, parallel, loss), func(t *testing.T) {
					const minor = 2
					mirrors := 1
					o := PNFSOptions{WriteFailover: true, Parallelism: parallel, DataServers: map[string]string{}, SPNs: map[string]string{}}
					if kind == 4 {
						mirrors, o.Layout = 2, "flex"
					}
					sid := bytes.Repeat([]byte{7}, 16)
					states := make([]*cachedWritePeer, mirrors)
					for i := range mirrors {
						id := i + 1
						s := &cachedWritePeer{mode: loss, handle: "file"}
						if kind == 4 {
							s.handle = fmt.Sprintf("ds%d", id)
						}
						s.data = func(code uint32, d *decoder) (encoder, error) {
							if code == 5 {
								if d.u64() != 123 || d.u32() != 4 {
									return nil, errors.New("changed commit range")
								}
								return bytes.Repeat([]byte{8}, 8), nil
							}
							wantState := bytes.Clone(sid)
							clear(wantState[:4])
							stable := uint32(0)
							if kind == 4 {
								clear(wantState)
								stable = 2
							}
							if !bytes.Equal(d.take(16), wantState) || d.u64() != 123 || d.u32() != stable || string(d.opaque(128)) != "data" {
								return nil, errors.New("changed original write")
							}
							var e encoder
							e.u32(4)
							e.u32(0)
							e = append(e, bytes.Repeat([]byte{8}, 8)...)
							return e, nil
						}
						states[i] = s
						for path := range 2 {
							drop := 0
							if i == 0 && path == 0 {
								drop = 3
								if loss == "commit-loss" {
									drop = 4
								}
							}
							if i == 0 && path == 1 && loss == "second-loss" {
								drop = 3
							}
							endpoint := pnfsMITEndpoint(t, s.client(t, minor).nfs.conn, nil, mitTLSOptions{dropDataReply: drop, expectedService: 3})
							o.DataServers[fmt.Sprintf("192.0.2.%d:2049", id+path*10)] = endpoint
							o.SPNs[endpoint] = "nfs/ds.nfs.test"
						}
					}
					stableAll := func() bool {
						for _, s := range states {
							s.mu.Lock()
							ok := s.writes == 1 && s.commits == 1
							s.mu.Unlock()
							if !ok {
								return false
							}
						}
						return true
					}
					layoutState := bytes.Repeat([]byte{8}, 16)
					returns, commits, progress := 0, 0, 0
					v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
						var e encoder
						switch code {
						case 9:
							return replacementTestReply(readBitmap4(d), map[uint32]encoder{1: replacementTestU32(1), 4: replacementTestU64(128)}), 0, nil
						case 50:
							if d.u32() != 0 || d.u32() != kind || d.u32() != 2 || d.u64() != 0 || d.u64() != math.MaxUint64 || d.u64() != 1 || !bytes.Equal(d.take(16), sid) || d.u32() != 32768 {
								return nil, 0, errors.New("original write lock not retained")
							}
							e.u32(1)
							e = append(e, layoutState...)
							e.u32(1)
							e.u64(0)
							e.u64(math.MaxUint64)
							e.u32(2)
							e.u32(kind)
							body := encoder(bytes.Repeat([]byte{1}, 16))
							body.u32(128)
							body.u32(0)
							body.u64(0)
							body.u32(1)
							body.opaque([]byte("file"))
							if kind == 4 {
								body = flexTestBody(mirrors, 1)
								binary.BigEndian.PutUint32(body[len(body)-8:], 0)
							}
							e.opaque(body)
						case 47:
							id := int(d.take(16)[0])
							if d.u32() != kind || d.u32() != 32768 || d.u32() != 0 {
								return nil, 0, errors.New("wrong device request")
							}
							var body encoder
							if kind == 1 {
								body.u32(1)
								body.u32(0)
								body.u32(1)
							}
							body.u32(2)
							for _, n := range []int{id, id + 10} {
								body.str("tcp")
								body.str(fmt.Sprintf("192.0.2.%d.8.1", n))
							}
							if kind == 4 {
								for _, n := range []uint32{1, 4, minor, 128, 128, 1} {
									body.u32(n)
								}
							}
							e.u32(kind)
							e.opaque(body)
							e.u32(0)
						case 49:
							if !stableAll() {
								return nil, 0, errors.New("metadata published before all mirrors durable")
							}
							if d.u64() != 123 || d.u64() != 4 || d.boolean() || !bytes.Equal(d.take(16), layoutState) || !d.boolean() || d.u64() != 126 || d.boolean() || d.u32() != kind || len(d.opaque(128)) != 0 {
								return nil, 0, errors.New("wrong publication range")
							}
							commits++
							e.u32(0)
						case 51:
							returns++
							d.take(48)
							d.opaque(4096)
							e.u32(0)
						default:
							return nil, 0, fmt.Errorf("unsafe MDS operation %d", code)
						}
						return e, 0, nil
					})
					v.clientNonce = bytes.Repeat([]byte{6}, 16)
					v.recall = &layoutRecall{}
					pnfsMITWrapClient(t, v.c, "krb5p", nil)
					v.c.WriteSize = 128
					lock := &v4Lock{info: LockInfo{ID: 1, Write: true, Length: LockToEOF}, sid: sid, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}}
					v.locks = map[uint64]*v4Lock{1: lock}
					n, err := v.c.WritePNFSRangeFromProgress(context.Background(), []byte("file"), 123, 4, bytes.NewReader([]byte("data")), o, func(n uint64) {
						progress++
						if n != 4 || commits != 1 || !stableAll() {
							t.Error("progress before durable publication")
						}
					})
					if loss == "second-loss" {
						if err == nil || n != 0 || progress != 0 || commits != 0 || !v.stateLost.Load() {
							t.Fatal("uncertain mirror credited", n, err)
						}
					} else if err != nil || n != 4 || progress != 1 || commits != 1 || returns != 1 || v.stateLost.Load() || v.locks[1] != lock {
						t.Fatal("publication failed", n, err, progress, commits, returns)
					}
					for i, s := range states {
						s.mu.Lock()
						if s.writes > 1 || s.creates > 1 || i == 0 && (s.writes != 1 || s.replays != 1) {
							t.Error("duplicate mutation or replacement session", i, s.writes, s.creates, s.replays)
						}
						s.mu.Unlock()
					}
				})
			}
		}
	}
}
