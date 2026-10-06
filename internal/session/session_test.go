package session

import (
	"bytes"
	"testing"
)

func TestRootCandidates(t *testing.T) {
	for _, fh := range [][]byte{nil, {1}, {2, 0, 0, 0}, {1, 1, 0, 0}, {1, 0, 9, 0}, {1, 0, 7, 0}} {
		if len(RootCandidates(fh)) != 0 {
			t.Fatalf("accepted unsupported handle %x", fh)
		}
	}
	fh := []byte{1, 0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11}
	original := append([]byte(nil), fh...)
	got := RootCandidates(fh)
	if len(got) != 18 {
		t.Fatalf("got %d candidates", len(got))
	}
	for _, c := range got {
		if !bytes.Equal(c[:3], fh[:3]) || !bytes.Equal(c[4:8], fh[4:8]) {
			t.Fatal("filesystem identity changed")
		}
	}
	got[0][4] = 99
	if !bytes.Equal(fh, original) || got[1][4] == 99 {
		t.Fatal("candidate aliases another handle")
	}
}

func TestSplitDestination(t *testing.T) {
	for _, value := range []string{"", "a/", ".", "..", "/a/..", "a\x00b"} {
		if _, _, err := splitDestination(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	parent, name, err := splitDestination("link/../file")
	if err != nil || parent != "link/../" || name != "file" {
		t.Fatalf("%q %q %v", parent, name, err)
	}
}
