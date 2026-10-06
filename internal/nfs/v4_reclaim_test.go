package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestReclaimRejectsFreshStateLoss(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, flag := range []uint32{0, 0x8, 0x80, 0x100} {
			for phase := uint32(1); phase <= 5; phase++ {
				t.Run(fmt.Sprintf("4.%d/flag-%x/phase-%d", minor, flag, phase), func(t *testing.T) {
					var sequences, opens, locks, completes atomic.Uint32
					peer := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
						var e encoder
						switch code {
						case 42:
							d.take(8)
							d.str()
							d.take(12)
							e.u64(456)
							e.u32(1)
							e.u32(0x10000)
							e.u32(0)
							e.u64(1)
							e.opaque([]byte("server"))
							e.opaque([]byte("scope"))
							e.u32(0)
						case 43:
							d.u64()
							sequence := d.u32()
							d.take(68)
							e = createSequenceReply(sequence)
						case 53:
							sequences.Add(1)
							e = append(e, d.take(16)...)
							e.u32(d.u32())
							d.take(12)
							for range 3 {
								e.u32(0)
							}
							if sequences.Load() == phase {
								e.u32(flag)
							} else {
								e.u32(0)
							}
						case 24:
						case 10:
							if opens.Load() == 0 {
								e.opaque([]byte("root"))
							} else {
								e.opaque([]byte("file"))
							}
						case 18:
							opens.Add(1)
							if d.u32() != 0 || d.u32() != 1 || d.u32() != 0 || d.u64() != 456 || !bytes.Equal(d.opaque(128), bytes.Repeat([]byte{3}, 16)) || d.u32() != 0 || d.u32() != 1 || d.u32() != 0 {
								return nil, 0, errors.New("not previous OPEN reclaim")
							}
							e = append(e, bytes.Repeat([]byte{5}, 16)...)
							e.u32(1)
							e.u64(1)
							e.u64(1)
							for range 3 {
								e.u32(0)
							}
						case 12:
							locks.Add(1)
							//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
							if d.u32() != 1 || d.u32() != 1 || d.u64() != 0 || d.u64() != LockToEOF || d.u32() != 1 || d.u32() != 1 || !bytes.Equal(d.take(16), bytes.Repeat([]byte{5}, 16)) || d.u32() != 0 || d.u64() != 456 || !bytes.Equal(d.opaque(128), bytes.Repeat([]byte{4}, 16)) {
								return nil, 0, errors.New("not previous LOCK reclaim")
							}
							e = append(e, bytes.Repeat([]byte{6}, 16)...)
						case 58:
							completes.Add(1)
							d.boolean()
						case 9:
							if fmt.Sprint(readBitmap4(d)) != "[10]" {
								return nil, 0, errors.New("unexpected lease attributes")
							}
							bitmap4(&e, 10)
							var value encoder
							value.u32(60)
							e.opaque(value)
						case 44:
							d.take(16)
						case 57:
							d.u64()
						default:
							return nil, 0, fmt.Errorf("unexpected recovery operation %d", code)
						}
						return e, 0, nil
					})
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					bridged := make(chan struct{})
					go func() {
						defer close(bridged)
						conn, err := listener.Accept()
						if err != nil {
							return
						}
						defer conn.Close()
						copied := make(chan struct{})
						go func() { io.Copy(conn, peer.c.nfs.conn); close(copied) }()
						io.Copy(peer.c.nfs.conn, conn)
						peer.c.nfs.conn.Close()
						<-copied
					}()
					t.Cleanup(func() { listener.Close(); peer.c.nfs.conn.Close(); <-bridged })
					oldConn, unused := net.Pipe()
					defer unused.Close()
					cfg := &Config{Host: "127.0.0.1", Version: fmt.Sprintf("4.%d", minor), NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: time.Second}
					old := &Client{config: cfg, version: cfg.Version, nfs: &rpcClient{conn: oldConn, timeout: time.Second}}
					old.v4 = &v4Client{c: old, minor: minor, clientID: 123, clientNonce: bytes.Repeat([]byte{1}, 16), leaseSeconds: 60,
						locks: map[uint64]*v4Lock{7: {info: LockInfo{ID: 7, Length: LockToEOF}, sid: bytes.Repeat([]byte{2}, 16), owner: bytes.Repeat([]byte{4}, 16), file: &v4Open{fh: []byte("file"), owner: bytes.Repeat([]byte{3}, 16)}}}}
					now := time.Now()
					old.v4.lastLease.Store(&now)
					fresh, err := old.ReclaimLocks(context.Background())
					wantSuccess := flag == 0 || flag == 0x100 && phase < 5
					if fresh != nil {
						defer func() { fresh.v4.stateLost.Store(true); fresh.Close() }()
					}
					if (err == nil) != wantSuccess || (fresh != nil) != wantSuccess {
						t.Fatalf("reclaim publication: fresh=%t error=%v, want success=%t", fresh != nil, err, wantSuccess)
					}
					if !wantSuccess && !errors.Is(err, ErrLockUncertain) {
						t.Fatalf("expected uncertain recovery state, got %v", err)
					}
					if len(old.Locks()) != 1 || !old.Locks()[0].Uncertain || !old.v4.reclaimAttempted {
						t.Fatal("old uncertain lock inventory lost")
					}
					if wantSuccess && (len(fresh.Locks()) != 1 || fresh.Locks()[0].Uncertain || opens.Load() != 1 || locks.Load() != 1 || completes.Load() != 1) {
						t.Fatal("healthy reclaim not complete")
					}
					if !wantSuccess && phase == 1 && opens.Load() != 0 {
						t.Fatal("reclaim continued after initialization lost state")
					}
					if !wantSuccess && phase <= 2 && locks.Load() != 0 {
						t.Fatal("reclaim continued after OPEN lost state")
					}
				})
			}
		}
	}
}

func TestReclaimWire(t *testing.T) {
	for _, tc := range []string{"whole", "range", "delegation", "no-grace", "bad-reclaim", "conflict", "changed-handle", "truncated-lock"} {
		t.Run(tc, func(t *testing.T) {
			old := &v4Lock{info: LockInfo{ID: 7, Write: true, Length: LockToEOF}, file: &v4Open{fh: []byte("file"), owner: bytes.Repeat([]byte{3}, 16)}, owner: bytes.Repeat([]byte{4}, 16)}
			if tc == "range" {
				old.info.Write = false
				old.info.Offset = 13
				old.info.Length = 257
			}
			opens, locks, returns := 0, 0, 0
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 18:
					opens++
					share := uint32(3)
					if !old.info.Write {
						share = 1
					}
					if d.u32() != 0 || d.u32() != share || d.u32() != 0 || d.u64() != 123 || !bytes.Equal(d.opaque(128), old.file.owner) || d.u32() != 0 || d.u32() != 1 || d.u32() != 0 {
						return nil, 0, errors.New("not previous OPEN reclaim")
					}
					if tc == "no-grace" {
						return nil, 10033, nil
					}
					if tc == "bad-reclaim" {
						return nil, 10034, nil
					}
					if tc == "conflict" {
						return nil, 10035, nil
					}
					e = append(e, bytes.Repeat([]byte{5}, 16)...)
					e.u32(1)
					e.u64(1)
					e.u64(1)
					e.u32(4)
					e.u32(0)
					if tc == "delegation" {
						e.u32(2)
						e = append(e, bytes.Repeat([]byte{9}, 16)...)
						e.u32(1)
						e.u32(1)
						e.u64(100)
						e.u32(0)
						e.u32(0)
						e.u32(0)
						e.str("OWNER@")
					} else {
						e.u32(0)
					}
				case 10:
					if tc == "changed-handle" {
						e.opaque([]byte("other"))
					} else {
						e.opaque([]byte("file"))
					}
				case 8:
					returns++
					if !bytes.Equal(d.take(16), bytes.Repeat([]byte{9}, 16)) {
						return nil, 0, errors.New("wrong delegation return")
					}
				case 12:
					locks++
					kind := uint32(2)
					if !old.info.Write {
						kind = 1
					}
					if d.u32() != kind || d.u32() != 1 || d.u64() != old.info.Offset || d.u64() != old.info.Length || d.u32() != 1 || d.u32() != 1 || !bytes.Equal(d.take(16), bytes.Repeat([]byte{5}, 16)) || d.u32() != 0 || d.u64() != 123 || !bytes.Equal(d.opaque(128), old.owner) {
						return nil, 0, errors.New("not previous LOCK reclaim")
					}
					e = append(e, bytes.Repeat([]byte{6}, 16)...)
					if tc == "truncated-lock" {
						e = e[:15]
					}
				default:
					return nil, 0, fmt.Errorf("unexpected reclaim operation %d", code)
				}
				return e, 0, nil
			})
			v.clientID = 123
			err := v.reclaimLock(context.Background(), old)
			if opens != 1 {
				t.Fatal("OPEN replay", opens)
			}
			if tc == "whole" || tc == "range" || tc == "delegation" {
				if err != nil || locks != 1 || v.locks[7].info.Uncertain || v.locks[7].file.seq != 2 {
					t.Fatal(err, locks, v.locks)
				}
				if tc == "delegation" && returns != 1 {
					t.Fatal("delegation retained")
				}
			} else {
				if err == nil {
					t.Fatal("invalid reclaim accepted")
				}
				if tc != "truncated-lock" && locks != 0 {
					t.Fatal("replacement lock attempted")
				}
				if tc == "truncated-lock" && (!v.locks[7].info.Uncertain || locks != 1) {
					t.Fatal("uncertain lock forgotten or replayed")
				}
			}
		})
	}
}

func TestReclaimLocalRefusals(t *testing.T) {
	for _, tc := range []string{"expired", "uncertain", "untracked", "identity", "revoked", "attempted", "cancelled", "empty"} {
		t.Run(tc, func(t *testing.T) {
			c := &Client{config: &Config{Version: "4.1"}}
			v := &v4Client{c: c, clientNonce: make([]byte, 16), leaseSeconds: 30, locks: map[uint64]*v4Lock{1: {info: LockInfo{ID: 1}, sid: make([]byte, 16), file: &v4Open{owner: make([]byte, 16)}}}}
			c.v4 = v
			now := time.Now()
			v.lastLease.Store(&now)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch tc {
			case "expired":
				past := now.Add(-time.Minute)
				v.lastLease.Store(&past)
			case "uncertain":
				v.locks[1].info.Uncertain = true
			case "untracked":
				v.locks[1].file.owner = nil
			case "identity":
				c.Auth.UID = 1
			case "revoked":
				v.reclaimForbidden.Store(true)
			case "attempted":
				v.reclaimAttempted = true
			case "cancelled":
				cancel()
			case "empty":
				clear(v.locks)
			}
			if _, err := c.ReclaimLocks(ctx); err == nil {
				t.Fatal("unsafe reclaim accepted")
			}
		})
	}
}
