package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

type lockPeerState struct {
	lockStatus, unlockStatus, closeStatus        Status
	malformed                                    bool
	locks, unlocks, closes, reads, writes, freed int
	openSeq                                      uint32
	sequenceFlags                                uint32
	offset, length                               uint64
}

func lockPeer4(t *testing.T, minor uint32, p *lockPeerState) *v4Client {
	t.Helper()
	openSID, lockSID := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
	length := p.length
	if length == 0 {
		length = LockToEOF
	}
	v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 53:
			e = append(e, d.take(16)...)
			e.u32(d.u32())
			//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
			if d.u32() != 0 || d.u32() != 0 || d.u32() > 1 {
				return nil, 0, errors.New("bad SEQUENCE")
			}
			for range 3 {
				e.u32(0)
			}
			e.u32(p.sequenceFlags)
		case 18:
			if d.u32() != 0 {
				return nil, 0, errors.New("bad OPEN seq")
			}
			share := d.u32()
			if share != 1 && share != 3 {
				return nil, 0, errors.New("bad OPEN share")
			}
			if d.u32() != 0 || d.u64() != 123 || len(d.opaque(128)) != 16 || d.u32() != 0 || d.u32() != 0 || d.str() != "file" {
				return nil, 0, errors.New("bad OPEN")
			}
			e = append(e, openSID...)
			e.u32(1)
			e.u64(1)
			e.u64(2)
			flags := uint32(0)
			if minor == 0 {
				flags = 2
			}
			e.u32(flags)
			e.u32(0)
			e.u32(0)
			p.openSeq = 1
		case 20:
			if !bytes.Equal(d.take(16), openSID) || d.u32() != p.openSeq {
				return nil, 0, errors.New("bad CONFIRM")
			}
			p.openSeq++
			e = append(e, openSID...)
		case 10:
			e.opaque([]byte("file"))
		case 12:
			p.locks++
			kind := d.u32()
			if (kind != 1 && kind != 2) || d.u32() != 0 || d.u64() != p.offset || d.u64() != length || d.u32() != 1 || d.u32() != p.openSeq || !bytes.Equal(d.take(16), openSID) || d.u32() != 0 || d.u64() != 123 || len(d.opaque(128)) != 16 {
				return nil, 0, errors.New("bad LOCK")
			}
			switch p.lockStatus {
			case 10022, 10023, 10025, 10026, 10036, 10018, 10020:
			default:
				p.openSeq++
			}
			if p.malformed {
				return []byte{1}, p.lockStatus, nil
			}
			if p.lockStatus == 10010 {
				e.u64(5)
				e.u64(12)
				e.u32(2)
				e.u64(999)
				e.opaque([]byte("conflict"))
			} else if p.lockStatus == 0 {
				e = append(e, lockSID...)
			}
			return e, p.lockStatus, nil
		case 14:
			p.unlocks++
			kind := d.u32()
			if (kind != 1 && kind != 2) || d.u32() != 1 || !bytes.Equal(d.take(16), lockSID) || d.u64() != p.offset || d.u64() != length {
				return nil, 0, errors.New("bad LOCKU")
			}
			if p.unlockStatus != 0 {
				return nil, p.unlockStatus, nil
			}
			e = append(e, lockSID...)
		case 4:
			p.closes++
			if d.u32() != p.openSeq || !bytes.Equal(d.take(16), openSID) {
				return nil, 0, errors.New("bad CLOSE sequence/state")
			}
			if p.closeStatus != 0 {
				return nil, p.closeStatus, nil
			}
			e = append(e, openSID...)
		case 39:
			if minor != 0 || d.u64() != 123 || len(d.opaque(128)) != 16 {
				return nil, 0, errors.New("bad RELEASE_LOCKOWNER")
			}
			p.freed++
		case 45:
			if minor == 0 || !bytes.Equal(d.take(16), lockSID) {
				return nil, 0, errors.New("bad FREE_STATEID")
			}
			p.freed++
		case 25:
			p.reads++
			if !bytes.Equal(d.take(16), lockSID) || d.u64() != 0 {
				return nil, 0, errors.New("READ did not use lock state")
			}
			d.u32()
			e.u32(1)
			e.opaque([]byte("locked"))
		case 38:
			p.writes++
			if !bytes.Equal(d.take(16), lockSID) || d.u64() != 0 || d.u32() != 2 {
				return nil, 0, errors.New("WRITE did not use lock state")
			}
			data := d.opaque(32768)
			e.u32(uint32(len(data)))
			e.u32(2)
			e = append(e, make([]byte, 8)...)
		default:
			return nil, 0, fmt.Errorf("unexpected lock operation %d", code)
		}
		return e, 0, nil
	})
	if minor > 0 {
		v.session = bytes.Repeat([]byte{9}, 16)
		v.sequence = 1
	}
	return v
}

func TestV4WholeFileLocks(t *testing.T) {
	ctx := context.Background()
	for _, minor := range []uint32{0, 1, 2} {
		for _, write := range []bool{false, true} {
			t.Run(fmt.Sprintf("4.%d/write=%v", minor, write), func(t *testing.T) {
				p := &lockPeerState{}
				v := lockPeer4(t, minor, p)
				c := v.c
				fh := []byte("file")
				id, err := c.Lock(ctx, fh, write)
				if err != nil || id == 0 {
					t.Fatal(id, err)
				}
				if _, err = c.Lock(ctx, fh, write); err == nil || p.locks != 1 {
					t.Fatal("duplicate lock sent", err)
				}
				if _, err = c.Reconnect(ctx); !errors.Is(err, ErrLocksHeld) {
					t.Fatal(err)
				}
				if _, err = c.CaptureV4Replacement(ctx, fh); err == nil {
					t.Fatal("replacement of locked inode allowed")
				}
				var out bytes.Buffer
				if _, err = c.ReadTo(ctx, fh, &out); err != nil || out.String() != "locked" {
					t.Fatal(out.String(), err)
				}
				if p.closes != 0 || len(c.Locks()) != 1 {
					t.Fatal("READ dropped lock")
				}
				_, err = c.WriteFrom(ctx, fh, bytes.NewBufferString("written"))
				if write && (err != nil || p.writes != 1) || !write && (err == nil || p.writes != 0) {
					t.Fatal("write mode", err)
				}
				c.Auth.UID = 999
				if _, err = c.ReadTo(ctx, fh, io.Discard); err == nil || p.reads != 1 {
					t.Fatal("identity bypass", err)
				}
				if err = c.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				} // saved owner identity
				if len(c.Locks()) != 0 || p.unlocks != 1 || p.closes != 1 || p.freed != 1 {
					t.Fatalf("cleanup: %+v", p)
				}
			})
		}
	}
}

func TestV4LockDenialAndUnknownOutcome(t *testing.T) {
	for _, status := range []Status{10010, 10013, 10018} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			p := &lockPeerState{lockStatus: status}
			v := lockPeer4(t, 0, p)
			id, err := v.c.Lock(context.Background(), []byte("file"), false)
			if id != 0 || !errors.Is(err, status) || p.closes != 1 || len(v.c.Locks()) != 0 {
				t.Fatalf("denial cleanup: id=%d err=%v peer=%+v", id, err, p)
			}
		})
	}
	for _, status := range []Status{0, 10010} {
		t.Run(fmt.Sprintf("malformed-%d", status), func(t *testing.T) {
			p := &lockPeerState{lockStatus: status, malformed: true}
			v := lockPeer4(t, 0, p)
			id, err := v.c.Lock(context.Background(), []byte("file"), false)
			if id == 0 || err == nil || !v.c.Locks()[0].Uncertain {
				t.Fatal(id, err)
			}
			if !v.stateLost.Load() || !v.c.nfs.closed {
				t.Fatal("malformed compound left session reusable")
			}
			if err = v.c.Unlock(context.Background(), id); !errors.Is(err, ErrLockUncertain) || p.unlocks != 0 {
				t.Fatal("uncertain replay", err)
			}
			if _, err = v.c.ReadTo(context.Background(), []byte("file"), io.Discard); !errors.Is(err, ErrLockUncertain) || p.reads != 0 {
				t.Fatal(err)
			}
		})
	}
}

func TestV4LockDenialRetryClassification(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, cleanup := range []Status{0, 5} {
			t.Run(fmt.Sprintf("4.%d/cleanup=%d", minor, cleanup), func(t *testing.T) {
				p := &lockPeerState{lockStatus: 10010, closeStatus: cleanup}
				v := lockPeer4(t, minor, p)
				id, err := v.c.Lock(context.Background(), []byte("file"), true)
				if id != 0 || !errors.Is(err, Status(10010)) || p.locks != 1 || p.closes != 1 {
					t.Fatalf("id=%d err=%v peer=%+v", id, err, p)
				}
				if (err == Status(10010)) != (cleanup == 0) {
					t.Fatalf("unsafe retry classification: %v", err)
				}
			})
		}
	}
}

func TestV4LockUnlockFailureAndLeaseLoss(t *testing.T) {
	for _, leaseLost := range []bool{false, true} {
		t.Run(fmt.Sprint(leaseLost), func(t *testing.T) {
			p := &lockPeerState{unlockStatus: 10011}
			v := lockPeer4(t, 0, p)
			id, err := v.c.Lock(context.Background(), []byte("file"), false)
			if err != nil {
				t.Fatal(err)
			}
			if leaseLost {
				v.stateLost.Store(true)
			}
			if err = v.c.Unlock(context.Background(), id); err == nil {
				t.Fatal("unlock unexpectedly passed")
			}
			if err = v.c.Unlock(context.Background(), id); !errors.Is(err, ErrLockUncertain) {
				t.Fatal(err)
			}
			want := 1
			if leaseLost {
				want = 0
			}
			if p.unlocks != want || !v.c.Locks()[0].Uncertain {
				t.Fatal("replayed unlock")
			}
			if _, err = v.c.ReadTo(context.Background(), []byte("file"), io.Discard); !errors.Is(err, ErrLockUncertain) {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyLocksRefused(t *testing.T) {
	if _, err := (&Client{}).Lock(context.Background(), nil, false); err == nil {
		t.Fatal("legacy lock accepted")
	}
}

func TestV4LockRangeBounds(t *testing.T) {
	for _, tc := range []struct {
		offset, length uint64
		valid          bool
	}{
		{0, 0, false}, {LockToEOF, 1, false}, {LockToEOF - 1, 2, false},
		{0, 1, true}, {LockToEOF - 1, 1, true}, {0, LockToEOF, true},
		{LockToEOF, LockToEOF, true}, {1 << 40, 4096, true},
	} {
		t.Run(fmt.Sprintf("%d/%d", tc.offset, tc.length), func(t *testing.T) {
			if err := ValidateLockRange(tc.offset, tc.length); (err == nil) != tc.valid {
				t.Fatal(err)
			}
			if !tc.valid {
				// No transport exists: invalid ranges must fail before network work.
				if id, err := (&Client{v4: &v4Client{}}).LockRange(context.Background(), nil, true, tc.offset, tc.length); id != 0 || err == nil {
					t.Fatal(id, err)
				}
			}
		})
	}
}

func TestV4RangeLockWireAndTransferGuard(t *testing.T) {
	ctx := context.Background()
	for _, minor := range []uint32{0, 1, 2} {
		for _, r := range [][2]uint64{{0, 8}, {1 << 40, 4096}, {123, LockToEOF}, {LockToEOF - 1, 1}, {LockToEOF, LockToEOF}} {
			t.Run(fmt.Sprintf("4.%d/%d/%d", minor, r[0], r[1]), func(t *testing.T) {
				p := &lockPeerState{offset: r[0], length: r[1]}
				v := lockPeer4(t, minor, p)
				id, err := v.c.LockRange(ctx, []byte("file"), true, r[0], r[1])
				if err != nil {
					t.Fatal(err)
				}
				info := v.c.Locks()[0]
				if info.Offset != r[0] || info.Length != r[1] || info.Uncertain {
					t.Fatal(info)
				}
				if n, err := v.c.ReadTo(ctx, []byte("file"), io.Discard); n != 0 || !errors.Is(err, ErrPartialLockIO) || p.reads != 0 {
					t.Fatal("partial lock READ", n, err)
				}
				source := bytes.NewBufferString("unchanged")
				if n, err := v.c.WriteFrom(ctx, []byte("file"), source); n != 0 || !errors.Is(err, ErrPartialLockIO) || p.writes != 0 || source.Len() != 9 {
					t.Fatal("partial lock WRITE", n, err)
				}
				if err := v.c.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
				if p.unlocks != 1 || p.closes != 1 || p.freed != 1 || len(v.c.Locks()) != 0 {
					t.Fatal("range cleanup", p)
				}
			})
		}
	}
}

func TestV4LockConnectionLoss(t *testing.T) {
	p := &lockPeerState{}
	v := lockPeer4(t, 0, p)
	id, err := v.c.Lock(context.Background(), []byte("file"), false)
	if err != nil {
		t.Fatal(err)
	}
	v.c.nfs.conn.Close()
	if _, err := v.c.ReadTo(context.Background(), []byte("file"), io.Discard); err == nil {
		t.Fatal("closed connection read succeeded")
	}
	if !v.c.Locks()[0].Uncertain {
		t.Fatal("connection loss not visible")
	}
	if err := v.c.Unlock(context.Background(), id); !errors.Is(err, ErrLockUncertain) || p.unlocks != 0 {
		t.Fatal("unlock replay after disconnect", err)
	}
	v.c.DiscardLocks()
	if len(v.c.Locks()) != 0 {
		t.Fatal("discard retained local locks")
	}
}

func TestV4LockSequenceRevocation(t *testing.T) {
	for _, flag := range []uint32{8, 16, 32, 64, 128, 256} {
		t.Run(fmt.Sprint(flag), func(t *testing.T) {
			p := &lockPeerState{}
			v := lockPeer4(t, 1, p)
			if _, err := v.c.Lock(context.Background(), []byte("file"), false); err != nil {
				t.Fatal(err)
			}
			p.sequenceFlags = flag
			var out bytes.Buffer
			if _, err := v.c.ReadTo(context.Background(), []byte("file"), &out); !errors.Is(err, ErrLockUncertain) || out.Len() != 0 || !v.c.Locks()[0].Uncertain {
				t.Fatal("revoked-state data exposed", err, out.String())
			}
		})
	}
}
