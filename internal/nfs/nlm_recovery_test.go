package nfs

import (
	"bytes"
	"testing"
)

func TestNSMRecoveryJournal(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		dir := t.TempDir()
		s, err := openNSMState(dir, "192.0.2.10", "192.0.2.20")
		if err != nil {
			t.Fatal(err)
		}
		s.record.Locks = []nsmSavedLock{{Version: 4, Info: LockInfo{ID: 1, Write: true, Length: LockToEOF}, FH: bytes.Repeat([]byte{1}, 32), Owner: bytes.Repeat([]byte{2}, 16), SVID: 42, Auth: Auth{UID: 21, GID: 22}, Confirmed: confirmed}}
		s.record.Dirty = true
		s.record.LastSVID = 42
		if err := s.append(); err != nil {
			t.Fatal(err)
		}
		s.close()
		if x, err := openNSMState(dir, "192.0.2.10", "192.0.2.20"); err == nil {
			x.close()
			t.Fatal("ordinary open accepted dirty state")
		}
		x, err := openNSMStateMode(dir, "192.0.2.10", "192.0.2.20", true)
		if !confirmed {
			if err == nil {
				x.close()
				t.Fatal("unknown acquisition admitted to recovery")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(x.record.Locks) != 1 || x.record.State != 1 || x.record.Locks[0].Auth.UID != 21 {
			t.Fatal("recovery identity changed")
		}
		x.record.Locks = nil
		x.record.Dirty = false
		if err := x.append(); err != nil {
			t.Fatal(err)
		}
		x.close()
		x, err = openNSMState(dir, "192.0.2.10", "192.0.2.20")
		if err != nil {
			t.Fatal(err)
		}
		defer x.close()
		if x.record.State != 3 || x.record.Dirty || len(x.record.Locks) != 0 || x.record.LastSVID != 42 {
			t.Fatal("clean recovery not durable")
		}
	}
}

func TestNSMLegacyJournalMigration(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		dir := t.TempDir()
		s, err := openNSMState(dir, "192.0.2.10", "192.0.2.20")
		if err != nil {
			t.Fatal(err)
		}
		s.record.Version = 1
		s.record.Dirty = dirty
		if err := s.append(); err != nil {
			t.Fatal(err)
		}
		s.close()
		x, err := openNSMStateMode(dir, "192.0.2.10", "192.0.2.20", true)
		if dirty {
			if err == nil {
				x.close()
				t.Fatal("legacy unknown owner recovered")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if x.record.Version != 2 || x.record.State != 3 {
			t.Fatal("clean migration failed")
		}
		x.close()
	}
}
