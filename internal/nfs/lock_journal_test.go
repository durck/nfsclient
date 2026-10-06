package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validSavedLockRecord() lockRecord {
	return lockRecord{Version: 1, Serial: 1, Profile: strings.Repeat("a", 64), Identity: "selected identity", Peer: "127.0.0.1:2049", Nonce: bytes.Repeat([]byte{1}, 16), Session: bytes.Repeat([]byte{2}, 16), Root: []byte("/"), ClientID: 1, ServerMinor: 1, Owner: []byte("server-owner"), Scope: []byte("scope"), Slot: 1, ReadSize: 32768, WriteSize: 32768, Lease: 60, Confirmed: time.Now(), Namespace: LockNamespace{Export: "/data", CWD: "/", Root: []byte("/data"), Paths: map[uint64]string{1: "/file"}}, Locks: []savedLock{{Info: LockInfo{ID: 1, Length: LockToEOF}, Handle: []byte("file"), OpenState: bytes.Repeat([]byte{3}, 16), OpenOwner: bytes.Repeat([]byte{4}, 16), LockState: bytes.Repeat([]byte{5}, 16), LockOwner: bytes.Repeat([]byte{6}, 16), OpenSequence: 1}}}
}

func savedLockFrame(r lockRecord) []byte {
	body, _ := json.Marshal(r)
	h := sha256.Sum256(body)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	frame = append(frame, body...)
	return append(frame, h[:]...)
}

func TestLockJournalBoundsAndFraming(t *testing.T) {
	for _, mode := range []string{"valid", "truncated-header", "truncated-body", "checksum", "unknown-field", "serial", "slot-zero", "slot-exhausted", "owner", "session", "duplicate-lock", "uncertain-lock", "zero-range", "overflow-range", "relative-path", "dot-path", "invalid-utf8", "too-many-path-components", "empty-active", "identity-change", "slot-backwards", "after-retired"} {
		t.Run(mode, func(t *testing.T) {
			r := validSavedLockRecord()
			switch mode {
			case "serial":
				r.Serial = 2
			case "slot-zero":
				r.Slot = 0
			case "slot-exhausted":
				r.Slot = ^uint32(0)
			case "owner":
				r.Owner = nil
			case "session":
				r.Session = r.Session[:15]
			case "duplicate-lock":
				r.Locks = append(r.Locks, r.Locks[0])
			case "uncertain-lock":
				r.Locks[0].Info.Uncertain = true
			case "zero-range":
				r.Locks[0].Info.Length = 0
			case "overflow-range":
				r.Locks[0].Info.Offset = LockToEOF - 3
				r.Locks[0].Info.Length = 5
			case "relative-path":
				r.Namespace.Paths[1] = "file"
			case "dot-path":
				r.Namespace.Paths[1] = "/../file"
			case "too-many-path-components":
				r.Namespace.Paths[1] = "/" + strings.Repeat("a/", 65)
			case "empty-active":
				r.Locks = nil
			case "after-retired":
				r.Retired = true
			}
			data := savedLockFrame(r)
			switch mode {
			case "truncated-header":
				data = data[:3]
			case "truncated-body":
				data = data[:len(data)-1]
			case "checksum":
				data[len(data)-1] ^= 1
			case "invalid-utf8":
				body, _ := json.Marshal(r)
				body = bytes.Replace(body, []byte("/file"), []byte{'/', 255}, 1)
				h := sha256.Sum256(body)
				data = binary.BigEndian.AppendUint32(nil, uint32(len(body)))
				data = append(data, body...)
				data = append(data, h[:]...)
			case "unknown-field":
				body, _ := json.Marshal(r)
				body = append([]byte(`{"Unexpected":1,`), body[1:]...)
				h := sha256.Sum256(body)
				data = binary.BigEndian.AppendUint32(nil, uint32(len(body)))
				data = append(data, body...)
				data = append(data, h[:]...)
			case "identity-change", "slot-backwards", "after-retired":
				r.Serial++
				if mode == "identity-change" {
					r.Identity = "other"
				}
				if mode == "slot-backwards" {
					r.Slot = 0
				}
				data = append(data, savedLockFrame(r)...)
			}
			path := filepath.Join(t.TempDir(), "state")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			j, err := loadLockJournal(path, false)
			if j != nil {
				j.file.Close()
			}
			if (err == nil) != (mode == "valid") {
				t.Fatal("journal framing outcome", err)
			}
		})
	}
}

func TestLockJournalOwnershipAndCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	j, err := loadLockJournal(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	if err = j.append(validSavedLockRecord()); err != nil {
		t.Fatal(err)
	}
	if other, err := loadLockJournal(path, false); err == nil {
		other.file.Close()
		t.Fatal("concurrent journal owner accepted")
	}
	if _, err = loadLockJournal(path, true); err == nil {
		t.Fatal("existing state replaced")
	}
	if err = j.file.Truncate(maxLockJournal); err != nil {
		t.Fatal(err)
	}
	j.size = maxLockJournal
	if err = j.append(j.record); err == nil {
		t.Fatal("full journal accepted append")
	}
}

func TestLockJournalExpiredAndRetired(t *testing.T) {
	for _, mode := range []string{"expired", "future", "retired", "pending", "profile"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Host: "127.0.0.1", Version: "4.1", Security: "sys", TLS: TLSConfig{Enabled: true, ServerName: "fixture.test"}}
			r := validSavedLockRecord()
			profile, err := lockProfile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			r.Profile = profile
			switch mode {
			case "expired":
				r.Confirmed = time.Now().Add(-time.Hour)
			case "future":
				r.Confirmed = time.Now().Add(time.Hour)
			case "retired":
				r.Retired = true
			case "pending":
				r.Pending = true
			case "profile":
				cfg.Auth.UID = 99
			}
			path := filepath.Join(t.TempDir(), "state")
			if err = os.WriteFile(path, savedLockFrame(r), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			if _, err = RecoverLocks(context.Background(), cfg, path, func(*Client, LockNamespace) error { called = true; return nil }); err == nil || called {
				t.Fatal("unsafe saved state reached connection/validator", err)
			}
		})
	}
}
