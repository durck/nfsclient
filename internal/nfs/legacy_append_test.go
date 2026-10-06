package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestLegacyWriteAtOffsets(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			fh := bytes.Repeat([]byte{3}, 32)
			var written uint64
			c := scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
				var e encoder
				e.u32(0)
				if version == "2" {
					if proc != 8 || !bytes.Equal(d.take(32), fh) || d.u32() != 0 || d.u32() != uint32(17+written) || d.u32() != 0 {
						return nil, fmt.Errorf("wrong v2 append offset")
					}
					data := d.opaque(8192)
					written += uint64(len(data))
					attrReply2(&e, uint32(17+written))
				} else {
					if proc != 7 || !bytes.Equal(d.opaque(64), fh) || d.u64() != 17+written {
						return nil, fmt.Errorf("wrong v3 append offset")
					}
					count := d.u32()
					if d.u32() != 2 {
						return nil, fmt.Errorf("unstable request")
					}
					data := d.opaque(8192)
					if len(data) != int(count) {
						return nil, fmt.Errorf("wrong payload size")
					}
					accepted := min(count, 2)
					written += uint64(accepted)
					e.u32(0)
					e.u32(0)
					e.u32(accepted)
					e.u32(2)
					e = append(e, []byte("verifier")...)
				}
				return e, nil
			})
			c.version = version
			c.WriteSize = 4
			var progress uint64
			var n int64
			var err error
			if version == "2" {
				n, err = c.write2At(context.Background(), fh, bytes.NewBufferString("abcdef"), func(x uint64) { progress = x }, 17)
			} else {
				n, err = c.write3At(context.Background(), fh, bytes.NewBufferString("abcdef"), func(x uint64) { progress = x }, 17)
			}
			if err != nil || n != 6 || progress != 6 || written != 6 {
				t.Fatal(n, progress, written, err)
			}
		})
	}
}

func TestLegacyAppendRequiresMatchingWholeWriteLock(t *testing.T) {
	c := &Client{version: "3"}
	if err := c.RequireWriteLock([]byte("file")); err == nil {
		t.Fatal("missing NLM accepted")
	}
	c.nlm = &nlmClient{c: c, monitor: &nsmMonitor{}, locks: map[uint64]*nlmLock{1: {confirmed: true, fh: []byte("other"), info: LockInfo{Write: true, Length: LockToEOF}}}}
	if err := c.RequireWriteLock([]byte("file")); err == nil {
		t.Fatal("different file lock accepted")
	}
	l := c.nlm.locks[1]
	l.fh = []byte("file")
	if err := c.RequireWriteLock(l.fh); err != nil {
		t.Fatal(err)
	}
	l.info.Write = false
	if err := c.RequireWriteLock(l.fh); err == nil {
		t.Fatal("read lock accepted")
	}
	l.info.Write = true
	l.info.Length = 3
	if err := c.RequireWriteLock(l.fh); err == nil {
		t.Fatal("partial lock accepted")
	}
	l.info.Length = LockToEOF
	c.nlm.monitor.lost.Store(true)
	if err := c.RequireWriteLock(l.fh); err == nil {
		t.Fatal("lost lock accepted")
	}
}

// These peers acknowledge actual offsets and exercise faults absent from stock servers.
func TestLegacyAppendWire(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		for _, mode := range []string{"stable", "unstable", "verifier", "malformed", "trailing", "drop", "changed", "missing", "limit"} {
			if version == "2" && (mode == "unstable" || mode == "verifier") {
				continue
			}
			t.Run(version+"/"+mode, func(t *testing.T) {
				fh := bytes.Repeat([]byte{7}, 32)
				var attr encoder
				if version == "2" {
					attrReply2(&attr, 17)
				} else {
					for _, x := range []uint32{1, 0644, 1, 1000, 1001} {
						attr.u32(x)
					}
					attr.u64(17)
					attr.u64(17)
					attr.u32(0)
					attr.u32(0)
					attr.u64(7)
					attr.u64(123)
					for _, x := range []uint32{0, 0, 1800000000, 123000, 0, 0} {
						attr.u32(x)
					}
				}
				ad := &decoder{b: attr}
				var expected Attr
				if version == "2" {
					expected = attr2(ad)
				} else {
					expected = readAttr(ad)
				}
				if ad.err != nil {
					t.Fatal(ad.err)
				}
				calls, writes, commits := 0, 0, 0
				var c *Client
				c = scriptedClient(t, func(program, proc uint32, d *decoder) (encoder, error) {
					calls++
					var e encoder
					e.u32(0)
					if proc == 1 {
						return append(e, attr...), nil
					}
					if proc == 21 {
						commits++
						if !bytes.Equal(d.opaque(64), fh) || d.u64() != 17 || d.u32() != 3 || len(d.b) != 0 {
							return nil, fmt.Errorf("wrong COMMIT range")
						}
						e.u32(0)
						e.u32(0)
						if mode == "verifier" {
							return append(e, []byte("changed!")...), nil
						}
						return append(e, []byte("verifier")...), nil
					}
					writes++
					if version == "2" {
						if proc != 8 || !bytes.Equal(d.take(32), fh) || d.u32() != 0 || d.u32() != 17 || d.u32() != 0 || string(d.opaque(8192)) != "xyz" {
							return nil, fmt.Errorf("bad v2 WRITE")
						}
						attrReply2(&e, 20)
					} else {
						if proc != 7 || !bytes.Equal(d.opaque(64), fh) || d.u64() != 17 || d.u32() != 3 || d.u32() != 2 || string(d.opaque(8192)) != "xyz" {
							return nil, fmt.Errorf("bad v3 WRITE")
						}
						e.u32(0)
						e.u32(0)
						e.u32(3)
						if mode == "unstable" || mode == "verifier" {
							e.u32(0)
						} else {
							e.u32(2)
						}
						e = append(e, []byte("verifier")...)
					}
					if mode == "malformed" {
						e = e[:len(e)-1]
					}
					if mode == "drop" {
						c.nfs.conn.Close()
					}
					if mode == "trailing" {
						e = append(e, 0)
					}
					return e, nil
				}, true)
				c.version = version
				var state atomic.Uint32
				state.Store(3)
				cfg := Config{Version: version, Transport: "tcp", Timeout: time.Second, Host: "127.0.0.1", PortmapPort: nsmPeer(t, &state), NLMClientIP: "127.0.0.1", NLMStateDir: t.TempDir()}
				monitor, err := startNSM(context.Background(), cfg, "127.0.0.1", 0, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer monitor.close()
				nlmVersion := uint32(4)
				if version == "2" {
					nlmVersion = 1
				}
				c.nlm = &nlmClient{c: c, version: nlmVersion, monitor: monitor, locks: map[uint64]*nlmLock{1: {confirmed: true, fh: fh, info: LockInfo{Write: true, Length: LockToEOF}}}}
				if mode == "changed" {
					expected.MTime = expected.MTime.Add(time.Second)
				}
				if mode == "missing" {
					expected.HasCTime = false
				}
				if mode == "limit" {
					expected.Size = 1 << 63
					if version == "2" {
						expected.Size = 1 << 31
					}
				}
				var progress uint64
				n, err := c.AppendLegacyFromProgress(context.Background(), fh, expected, bytes.NewBufferString("xyz"), func(x uint64) { progress = x })
				switch mode {
				case "stable", "unstable":
					if err != nil || n != 3 || progress != 3 || writes != 1 || (mode == "unstable" && commits != 1) {
						t.Fatal(n, progress, writes, commits, err)
					}
				case "changed", "missing", "limit":
					if err == nil || n != 0 || writes != 0 || progress != 0 {
						t.Fatal("unsafe preflight", n, writes, err)
					}
					if mode != "changed" && calls != 0 {
						t.Fatal("invalid baseline sent RPC")
					}
				default:
					if !errors.Is(err, ErrLockUncertain) || n != 0 || progress != 0 || writes != 1 || !monitor.lost.Load() {
						t.Fatal("bad acknowledgement accepted", n, progress, writes, err)
					}
					before := calls
					if _, err = c.AppendLegacyFromProgress(context.Background(), fh, expected, bytes.NewBufferString("xyz"), nil); !errors.Is(err, ErrLockUncertain) || calls != before {
						t.Fatal("uncertain write replayed", err)
					}
				}
			})
		}
	}
}
