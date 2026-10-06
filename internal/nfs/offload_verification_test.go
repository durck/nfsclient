package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// This peer generates bytes and metadata independently of the recovery code.
// READ is accepted only after COMMIT and while the exact read lock is held.
type offloadVerificationPeer struct {
	mode                                  string
	attrs, commits, reads, locks, unlocks int
	opened, locked                        bool
}

func (p *offloadVerificationPeer) operation(code uint32, d *decoder) (encoder, Status, error) {
	var e encoder
	open, lock := bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{8}, 16)
	switch code {
	case 42:
		d.take(8)
		d.str()
		d.take(12)
		e.u64(123)
		e.u32(22)
		e.u32(0x10000)
		e.u32(0)
		e.u64(1)
		e.str("verification")
		e.str("scope")
		e.u32(0)
	case 43:
		if d.u64() != 123 || d.u32() != 22 {
			return nil, 0, errors.New("bad CREATE")
		}
		d.take(68)
		e = createSequenceReply(22)
	case 53:
		e = append(e, d.take(16)...)
		e.u32(d.u32())
		d.take(12)
		for range 4 {
			e.u32(0)
		}
	case 58:
		d.u32()
	case 24:
	case 44:
		d.take(16)
	case 57:
		d.u64()
	case 9:
		wanted := readBitmap4(d)
		fields := map[uint32]encoder{}
		u32 := func(bit, n uint32) { var x encoder; x.u32(n); fields[bit] = x }
		u64 := func(bit uint32, n uint64) { var x encoder; x.u64(n); fields[bit] = x }
		u32(1, 1)
		u64(3, 40)
		u64(4, 13)
		u64(20, 8)
		u32(33, 0600)
		u32(10, 90)
		u64(30, 32768)
		u64(31, 32768)
		var fs encoder
		fs.u64(7)
		fs.u64(9)
		fields[8] = fs
		for _, bit := range []uint32{36, 37} {
			var x encoder
			x.str("0")
			fields[bit] = x
		}
		for _, bit := range []uint32{52, 53} {
			var x encoder
			x.u64(100)
			x.u32(0)
			fields[bit] = x
		}
		for _, bit := range wanted {
			if bit == 3 {
				p.attrs++
				break
			}
		}
		if p.mode == "identity" {
			u64(20, 99)
		}
		if p.mode == "changed" && p.attrs > 1 {
			u64(3, 41)
		}
		return replacementTestReply(wanted, fields), 0, nil
	case 18:
		openSeq, share := d.u32(), d.u32()
		if openSeq != 0 || share != 1 && share != 0x401 || d.u32() != 0 || d.u64() != 123 || len(d.opaque(128)) != 16 || d.u32() != 0 || d.u32() != 0 || d.str() != "file" {
			return nil, 0, errors.New("wrong read OPEN")
		}
		p.opened = true
		e = append(e, open...)
		e.u32(1)
		e.u64(1)
		e.u64(2)
		e.u32(0)
		e.u32(0)
		e.u32(0)
	case 10:
		if p.opened {
			if p.mode == "renamed" {
				e.opaque([]byte("replacement"))
			} else {
				e.opaque([]byte("file"))
			}
		} else {
			e.opaque([]byte("root"))
		}
	case 12:
		p.locks++
		if d.u32() != 1 || d.u32() != 0 || d.u64() != 0 || d.u64() != LockToEOF || d.u32() != 1 || d.u32() != 1 || !bytes.Equal(d.take(16), open) || d.u32() != 0 || d.u64() != 123 || len(d.opaque(128)) != 16 {
			return nil, 0, errors.New("wrong read LOCK")
		}
		if p.mode == "denied" {
			e.u64(0)
			e.u64(LockToEOF)
			e.u32(2)
			e.u64(999)
			e.str("other")
			return e, 10010, nil
		}
		p.locked = true
		e = append(e, lock...)
	case 5:
		if !p.locked || d.u64() != 7 || d.u32() != 0 {
			return nil, 0, errors.New("COMMIT without lock or wrong range")
		}
		p.commits++
		if p.mode == "commit" {
			return nil, 5, nil
		}
		e = append(e, make([]byte, 8)...)
	case 25:
		if !p.locked || p.commits != p.locks || !bytes.Equal(d.take(16), lock) {
			return nil, 0, errors.New("unprotected READ")
		}
		off, count := d.u64(), d.u32()
		data := []byte("ababab")
		if p.mode == "mismatch" {
			data = []byte("abcbab")
		}
		if off < 7 || off >= 13 || count == 0 || uint64(count) > 13-off {
			return nil, 0, errors.New("wrong read range")
		}
		p.reads++
		end := off - 7 + uint64(count)
		e.u32(uint32(0))
		e.opaque(data[off-7 : end])
	case 14:
		//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
		if d.u32() != 1 || d.u32() != 1 || !bytes.Equal(d.take(16), lock) || d.u64() != 0 || d.u64() != LockToEOF {
			return nil, 0, errors.New("wrong UNLOCK")
		}
		p.unlocks++
		if p.mode == "unlock" {
			return nil, 5, nil
		}
		p.locked = false
		e = append(e, lock...)
	case 45:
		if !bytes.Equal(d.take(16), lock) {
			return nil, 0, errors.New("wrong FREE_STATEID")
		}
	case 4:
		d.u32()
		if !bytes.Equal(d.take(16), open) {
			return nil, 0, errors.New("wrong CLOSE")
		}
		e = append(e, open...)
	default:
		return nil, 0, fmt.Errorf("unexpected verification operation %d", code)
	}
	return e, 0, nil
}

func offloadExpectedFixture() *OffloadExpectation {
	h := sha256.Sum256([]byte("ababab"))
	return &OffloadExpectation{SHA256: hex.EncodeToString(h[:]), Size: 13, FSID: 7, FSIDMinor: 9, FileID: 8, Parent: []byte("root"), Name: "file"}
}

func TestOffloadVerificationRequiresLockedStableExactContent(t *testing.T) {
	for _, mode := range []string{"ok", "identity", "changed", "renamed", "denied", "commit", "mismatch", "unlock"} {
		t.Run(mode, func(t *testing.T) {
			p := &offloadVerificationPeer{mode: mode}
			v := peer4(t, 2, p.operation)
			v.parents = nil
			v.c.ReadSize = 2
			r := OffloadRecord{Destination: []byte("file"), Offset: 7, Length: 6, Expectation: offloadExpectedFixture()}
			err := verifyOffloadExpectation(context.Background(), v.c, r)
			if (err == nil) != (mode == "ok") {
				t.Fatal(mode, err)
			}
			if mode == "ok" && (p.commits != 1 || p.reads != 3 || p.locks != 1 || p.unlocks != 1 || p.locked) {
				t.Fatalf("bad ordering/counters: %+v", p)
			}
			if (mode == "identity" || mode == "renamed" || mode == "denied") && (p.commits != 0 || p.reads != 0) {
				t.Fatal("unverified identity reached data", p)
			}
			if mode == "commit" && p.reads != 0 {
				t.Fatal("failed stabilization reached READ")
			}
		})
	}
}
