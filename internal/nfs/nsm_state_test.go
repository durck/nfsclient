package nfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNSMDurableState(t *testing.T) {
	dir := t.TempDir()
	s, err := openNSMState(dir, "192.0.2.10", "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if s.record.State != 1 || s.record.Dirty {
		t.Fatal(s.record)
	}
	if other, err := openNSMState(dir, "192.0.2.10", "192.0.2.20"); err == nil {
		other.close()
		t.Fatal("concurrent owner admitted")
	}
	if err := s.dirty(true); err != nil {
		t.Fatal(err)
	}
	s.close()
	if other, err := openNSMState(dir, "192.0.2.10", "192.0.2.20"); err == nil {
		other.close()
		t.Fatal("unclean state reused")
	}
}

func TestNSMCleanRestartAndCorruption(t *testing.T) {
	dir := t.TempDir()
	s, err := openNSMState(dir, "192.0.2.10", "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.dirty(true); err != nil {
		t.Fatal(err)
	}
	if err := s.dirty(false); err != nil {
		t.Fatal(err)
	}
	s.close()
	s, err = openNSMState(dir, "192.0.2.10", "192.0.2.20")
	if err != nil || s.record.State != 3 {
		t.Fatalf("restart: %+v %v", s, err)
	}
	s.close()
	if other, err := openNSMState(dir, "192.0.2.11", "192.0.2.20"); err == nil {
		other.close()
		t.Fatal("changed local address accepted")
	}
	if other, err := openNSMState(dir, "192.0.2.10", "192.0.2.21"); err == nil {
		other.close()
		t.Fatal("changed peer accepted")
	}
	p := filepath.Join(dir, "nsm-state")
	good, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, good[:len(good)-1], append(append([]byte{}, good...), 0), append([]byte("bad!"), good[4:]...)} {
		if err := os.WriteFile(p, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if other, err := openNSMState(dir, "192.0.2.10", "192.0.2.20"); err == nil {
			other.close()
			t.Fatal("corrupt state accepted")
		}
	}
}
