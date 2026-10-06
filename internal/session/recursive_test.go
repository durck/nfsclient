package session

import (
	"errors"
	"testing"
)

func TestPortableTreeNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", "a\\b", "C:x", "a\x00b", "a\nb", "a.", "a ", "NUL", "con.txt", "COM1", "lpt9.txt", "COM¹", "CONIN$", "a?b"} {
		if portableTreeName(name) {
			t.Errorf("accepted unsafe name %q", name)
		}
	}
	for _, name := range []string{"file", ".config", "my report.txt", "COM10", "файл.txt", "a-b"} {
		if !portableTreeName(name) {
			t.Errorf("rejected name %q", name)
		}
	}
}

func TestPortableTreeLink(t *testing.T) {
	for _, target := range []string{"", "a\\b", "a\x00b"} {
		if portableTreeLink(target) == nil {
			t.Errorf("accepted %q", target)
		}
	}
	for _, target := range []string{"target", "../other", "/absolute", "dangling", "."} {
		if err := portableTreeLink(target); err != nil {
			t.Errorf("refused %q: %v", target, err)
		}
	}
}

func TestMergeNames(t *testing.T) {
	m := treeMergeNames{}
	calls := 0
	list := func() ([]string, error) { calls++; return []string{"Readme", "sub"}, nil }
	if err := m.check("root", "Readme", list); err != nil {
		t.Fatal(err)
	}
	if err := m.check("root", "README", list); err == nil {
		t.Fatal("case collision accepted")
	}
	if err := m.check("root", "new", list); err != nil || calls != 1 {
		t.Fatal("cache failed", err, calls)
	}
	if err := m.check("ambiguous", "other", func() ([]string, error) { return []string{"a", "A"}, nil }); err == nil {
		t.Fatal("ambiguous existing names accepted")
	}
	want := errors.New("read denied")
	if err := m.check("denied", "x", func() ([]string, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	m.total = treeEntryLimit
	if err := m.check("bounded", "x", list); err == nil {
		t.Fatal("unbounded merge inventory")
	}
}
