package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"nfsclient/internal/testutil/loopback"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNLMRangeCoverage(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			fh := bytes.Repeat([]byte{1}, 32)
			c := &Client{version: version}
			c.nlm = &nlmClient{c: c, monitor: &nsmMonitor{}, locks: map[uint64]*nlmLock{
				1: {fh: fh, confirmed: true, info: LockInfo{Offset: 16, Length: 16}},
				2: {fh: fh, confirmed: true, info: LockInfo{Offset: 32, Length: 16, Write: true}},
			}}
			for _, tc := range []struct {
				offset, length uint64
				write, ok      bool
			}{
				{16, 16, false, true}, {20, 4, false, true}, {32, 16, true, true},
				{16, 1, true, false}, {15, 1, false, false}, {16, 32, false, false},
				{48, 1, false, false}, {16, 0, false, false}, {16, LockToEOF, false, false},
			} {
				if err := c.RequireRangeLock(fh, tc.offset, tc.length, tc.write); (err == nil) != tc.ok {
					t.Errorf("%+v: %v", tc, err)
				}
			}
			c.nlm.locks[2].info.Length = LockToEOF
			if err := c.RequireRangeLock(fh, maxV2File-1, 1, true); err != nil {
				t.Fatal(err)
			}
			if err := c.RequireRangeLock(fh, 1<<33, 1, true); (err == nil) != (version == "3") {
				t.Fatal(err)
			}
			c.Auth.UID = 7
			if err := c.RequireRangeLock(fh, 32, 1, true); err == nil {
				t.Fatal("changed identity accepted")
			}
			c.Auth.UID = 0
			c.nlm.locks[2].confirmed = false
			if err := c.RequireRangeLock(fh, 32, 1, true); !errors.Is(err, ErrLockUncertain) {
				t.Fatal(err)
			}
		})
	}
}

func TestNLMRangeWire(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		for _, mode := range []string{"read", "early-eof", "oversized", "trailing", "read-loss", "read-cancel", "read-identity", "write", "short-source", "short-write", "unstable", "verifier", "write-loss", "write-cancel", "write-unlock", "write-relock"} {
			if version == "2" && (mode == "short-write" || mode == "unstable" || mode == "verifier") {
				continue
			}
			t.Run(version+"/"+mode, func(t *testing.T) {
				fh := bytes.Repeat([]byte{4}, 32)
				var state atomic.Uint32
				state.Store(3)
				var calls atomic.Int32
				var transferred uint64
				read := strings.HasPrefix(mode, "read") || mode == "early-eof" || mode == "oversized" || mode == "trailing"
				c := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
					calls.Add(1)
					var e encoder
					e.u32(0)
					var gotFH []byte
					var offset uint64
					if version == "2" {
						gotFH = d.take(32)
						if proc == 8 {
							d.u32()
						}
						offset = uint64(d.u32())
					} else {
						gotFH = d.opaque(64)
						offset = d.u64()
					}
					if !bytes.Equal(gotFH, fh) || offset < 64 || offset >= 72 {
						return nil, fmt.Errorf("wrong range handle/offset: %d", offset)
					}
					if proc == 21 {
						n := d.u32()
						if n == 0 || offset+uint64(n) > 72 {
							return nil, errors.New("unbounded COMMIT")
						}
						e.u32(0)
						e.u32(0)
						v := "verifier"
						if mode == "verifier" {
							v = "changed!"
						}
						return append(e, []byte(v)...), nil
					}
					if offset != 64+transferred {
						return nil, errors.New("wrong transfer offset")
					}
					if read {
						if proc != 6 {
							return nil, errors.New("unexpected READ procedure")
						}
						limit := d.u32()
						if version == "2" {
							d.u32()
						}
						if limit == 0 || limit > 4 || offset+uint64(limit) > 72 {
							return nil, errors.New("unbounded READ")
						}
						n := limit
						if mode == "early-eof" {
							n = 1
						}
						if mode == "oversized" {
							n++
						}
						if version == "2" {
							size := uint32(96)
							if mode == "early-eof" {
								size = 65
							}
							attrReply2(&e, size)
						} else {
							e.u32(0)
							e.u32(n)
							if mode == "early-eof" {
								e.u32(1)
							} else {
								e.u32(0)
							}
						}
						e.opaque(bytes.Repeat([]byte{'R'}, int(n)))
						transferred += uint64(n)
						if mode == "trailing" {
							e = append(e, 0)
						}
					} else {
						if version == "2" {
							if proc != 8 {
								return nil, errors.New("wrong WRITE2")
							}
							d.u32()
						} else {
							if proc != 7 {
								return nil, errors.New("wrong WRITE3")
							}
							d.u32()
							if d.u32() != 2 {
								return nil, errors.New("unstable request")
							}
						}
						data := d.opaque(4)
						if len(data) == 0 || offset+uint64(len(data)) > 72 {
							return nil, errors.New("unbounded WRITE")
						}
						n := uint32(len(data))
						if mode == "short-write" {
							n = 1
						}
						transferred += uint64(n)
						if version == "2" {
							attrReply2(&e, 96)
						} else {
							e.u32(0)
							e.u32(0)
							e.u32(n)
							stable := uint32(2)
							if mode == "unstable" || mode == "verifier" {
								stable = 0
							}
							e.u32(stable)
							e = append(e, []byte("verifier")...)
						}
					}
					if d.err != nil || len(d.b) != 0 {
						return nil, errors.New("malformed request")
					}
					if strings.HasSuffix(mode, "loss") {
						state.Store(5)
					}
					return e, nil
				}, true)
				c.version = version
				c.ReadSize = 4
				c.WriteSize = 4
				cfg := Config{Version: version, Transport: "tcp", Timeout: time.Second, Host: "127.0.0.1", PortmapPort: nsmPeer(t, &state), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
				tcp, udp, err := loopback.Pair()
				if err != nil {
					t.Fatal(err)
				}
				port := tcp.Addr().(*net.TCPAddr).Port
				tcp.Close()
				udp.Close()
				monitor, err := startNSM(context.Background(), cfg, "127.0.0.1", port, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer monitor.close()
				v := uint32(4)
				if version == "2" {
					v = 1
				}
				lock := &nlmLock{confirmed: true, fh: fh, info: LockInfo{Offset: 64, Length: 8, Write: !read}}
				c.nlm = &nlmClient{c: c, version: v, monitor: monitor, locks: map[uint64]*nlmLock{1: lock}}
				if _, err := c.ReadTo(context.Background(), fh, io.Discard); !errors.Is(err, ErrPartialLockIO) || calls.Load() != 0 {
					t.Fatal("ordinary I/O bypass", err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				progress := func(uint64) {
					if strings.HasSuffix(mode, "cancel") {
						cancel()
					}
					if mode == "read-identity" {
						c.Auth.UID = 7
					}
					if mode == "write-unlock" {
						delete(c.nlm.locks, 1)
					}
					if mode == "write-relock" {
						copy := *lock
						c.nlm.locks[1] = &copy
					}
				}
				var n int64
				var out bytes.Buffer
				if read {
					n, err = c.ReadRangeToProgress(ctx, fh, 64, 8, &out, progress)
				} else {
					data := "abcdefghEXTRA"
					if mode == "short-source" {
						data = "ab"
					}
					n, err = c.WriteRangeFromProgress(ctx, fh, 64, 8, strings.NewReader(data), progress)
				}
				if mode == "read" || mode == "write" || mode == "short-write" || mode == "unstable" {
					if err != nil || n != 8 {
						t.Fatal(n, err)
					}
				} else if err == nil {
					t.Fatal("fault accepted", n)
				}
				if strings.HasSuffix(mode, "loss") || mode == "verifier" {
					if !errors.Is(err, ErrLockUncertain) || n != 0 || out.Len() != 0 {
						t.Fatal("lost state accepted", n, err)
					}
					before := calls.Load()
					if _, err := c.WriteRangeFromProgress(context.Background(), fh, 64, 8, strings.NewReader("abcdefgh"), nil); err == nil || calls.Load() != before {
						t.Fatal("uncertain mutation replayed", err)
					}
				}
				if mode == "write-unlock" || mode == "write-relock" || strings.HasSuffix(mode, "cancel") || mode == "read-identity" {
					if calls.Load() != 1 {
						t.Fatal("continued after callback", calls.Load())
					}
				}
			})
		}
	}
}
