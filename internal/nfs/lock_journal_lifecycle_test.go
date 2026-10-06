package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// This peer independently frames replies and records execution by sequence.
// A lost reply is replayed from the cache without invoking the operation again.
func TestLockLifecycleLostReplyAtEveryPhase(t *testing.T) {
	for _, lost := range []string{"open", "lock", "unlock", "free", "close", "open-sync", "lock-sync", "unlock-sync", "free-sync", "close-sync"} {
		t.Run(lost, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "locks")
			j, err := loadLockJournal(path, true)
			if err != nil {
				t.Fatal(err)
			}
			r := validSavedLockRecord()
			r.Channel = sessionChannelLimits{4096, 4096, 4096, 16}
			r.Armed = true
			lostPhase := strings.TrimSuffix(lost, "-sync")
			acquire := lostPhase == "open" || lostPhase == "lock"
			if acquire {
				r.Locks = nil
				r.Namespace.Paths = map[uint64]string{}
			}
			if err := j.append(r); err != nil {
				t.Fatal(err)
			}
			defer func() { j.file.Close() }()
			calls := map[string]int{}
			cached := map[uint32][]byte{}
			requests := map[uint32][]byte{}
			dropped := false
			peer := func(request []byte) []byte {
				inner := request[72:]
				seq := binary.BigEndian.Uint32(request[104:])
				if binary.BigEndian.Uint32(request[116:]) != 1 {
					t.Error("lifecycle mutation was not cached")
				}
				// Observe the actual on-disk checkpoint before accepting any bytes.
				data := make([]byte, j.size)
				_, e := j.file.ReadAt(data, 0)
				if e != nil {
					t.Error(e)
					return nil
				}
				var disk lockRecord
				for len(data) > 0 {
					n := int(binary.BigEndian.Uint32(data))
					if e := json.Unmarshal(data[4:4+n], &disk); e != nil {
						t.Error(e)
					}
					data = data[4+n+32:]
				}
				if disk.PendingRequest == nil || !bytes.Equal(disk.PendingRequest.Inner, inner) || disk.Slot != seq {
					t.Error("request transmitted before exact durable checkpoint")
				}
				if old, ok := cached[seq]; ok {
					if !bytes.Equal(requests[seq], inner) {
						t.Error("retry changed original request bytes")
					}
					out := bytes.Clone(old)
					copy(out[:4], request[:4])
					return out
				}
				pos := 120
				code := binary.BigEndian.Uint32(request[pos:])
				pos += 4
				putfh := code == 22
				if putfh {
					n := int(binary.BigEndian.Uint32(request[pos:]))
					pos += 4 + (n+3)&^3
					code = binary.BigEndian.Uint32(request[pos:])
					pos += 4
				}
				phase := map[uint32]string{18: "open", 12: "lock", 14: "unlock", 45: "free", 4: "close"}[code]
				if phase == "" {
					t.Errorf("unexpected lifecycle operation %d", code)
					return nil
				}
				calls[phase]++
				count := uint32(2)
				if putfh {
					count++
				}
				if code == 18 {
					count++
				}
				out := append(bytes.Clone(request[:4]), channelWords(1, 0, 0, 0, 0, 0, 0, count, 53, 0)...)
				out = append(out, request[88:104]...)
				out = append(out, channelWords(seq, 0, 0, 0, 0)...)
				if putfh {
					out = append(out, channelWords(22, 0)...)
				}
				out = append(out, channelWords(code, 0)...)
				switch code {
				case 18:
					if binary.BigEndian.Uint32(request[pos+4:])&0x400 == 0 {
						t.Error("durable OPEN permitted a delegation")
					}
					out = append(out, bytes.Repeat([]byte{3}, 16)...)
					out = append(out, channelWords(1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 4)...)
					out = append(out, []byte("file")...)
				case 12, 14, 4:
					out = append(out, bytes.Repeat([]byte{5}, 16)...)
				}
				requests[seq], cached[seq] = bytes.Clone(inner), bytes.Clone(out)
				if phase == lostPhase && !dropped {
					dropped = true
					if strings.HasSuffix(lost, "-sync") {
						j.file.Close()
						return out
					}
					return nil
				}
				return out
			}
			attach := func() *v4Client {
				v, _ := channelWirePeer(t, r.Channel, peer)
				v.c.v4 = v
				v.session = bytes.Clone(j.record.Session)
				v.sequence = j.record.Slot
				v.clientID = r.ClientID
				v.journal = j
				v.parents = map[string]v4Name{"file": {dir: []byte("dir"), name: "file"}}
				v.locks = map[uint64]*v4Lock{}
				for _, l := range j.record.Locks {
					v.locks[l.Info.ID] = restoreSavedLock(l, r.Auth)
				}
				return v
			}
			v := attach()
			if acquire {
				_, err = v.c.LockRangeNamed(context.Background(), []byte("file"), "/file", true, 0, LockToEOF)
			} else {
				err = v.c.Unlock(context.Background(), 1)
			}
			if err == nil || !dropped || j.record.Intent == nil || j.record.PendingRequest == nil || !v.stateLost.Load() {
				t.Fatalf("lost phase not quarantined: %v %+v", err, j.record)
			}
			j.file.Close()
			j, err = loadLockJournal(path, false)
			if err != nil {
				t.Fatal(err)
			}
			v = attach()
			j.transaction = true
			if err = v.runLockIntent(context.Background()); err != nil {
				t.Fatal(err)
			}
			if j.record.Pending || j.record.Intent != nil || j.record.PendingRequest != nil {
				t.Fatal("resolved phase remained pending")
			}
			if acquire {
				if len(v.locks) != 1 || calls["open"] != 1 || calls["lock"] != 1 {
					t.Fatalf("acquisition was replaced or missing: %v", calls)
				}
			} else if len(v.locks) != 0 || calls["unlock"] != 1 || calls["free"] != 1 || calls["close"] != 1 {
				t.Fatalf("release was replaced or missing: %v", calls)
			}
			j.file.Close()
			j, err = loadLockJournal(path, false)
			if err != nil {
				t.Fatal("completed durable lifecycle is unreadable:", err)
			}
		})
	}
}

func TestLockLifecycleInsufficientChannelPreservesArmedJournal(t *testing.T) {
	j, err := loadLockJournal(filepath.Join(t.TempDir(), "locks"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	r := validSavedLockRecord()
	r.Armed = true
	r.Locks = nil
	r.Namespace.Paths = map[uint64]string{}
	if err = j.append(r); err != nil {
		t.Fatal(err)
	}
	c := &Client{nfs: &rpcClient{}}
	v := &v4Client{c: c, minor: 1, session: r.Session, sequence: r.Slot, clientID: r.ClientID, journal: j, channel: sessionChannelLimits{512, 512, 128, 4}, parents: map[string]v4Name{"file": {dir: []byte("dir"), name: "file"}}}
	c.v4 = v
	id, err := c.LockRangeNamed(context.Background(), []byte("file"), "/file", true, 0, LockToEOF)
	if id != 0 || !channelNotSent(err) || v.stateLost.Load() || j.record.Serial != 1 || j.record.Pending || j.record.Intent != nil {
		t.Fatalf("local budget refusal changed armed state: id=%d err=%v record=%+v", id, err, j.record)
	}
}
