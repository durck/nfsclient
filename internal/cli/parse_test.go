package cli

import (
	"reflect"
	"testing"
)

func TestSplitLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
		bad  bool
	}{
		{`put C:\Users\me\file.txt '/folder/file name'`, []string{"put", `C:\Users\me\file.txt`, "/folder/file name"}, false},
		{`put "C:\My Files\a.txt" a\ b`, []string{"put", `C:\My Files\a.txt`, "a b"}, false},
		{`cat 'it"s.txt'`, []string{"cat", `it"s.txt`}, false},
		{`uid 1 2 ""`, []string{"uid", "1", "2", ""}, false},
		{" \t ", nil, false},
		{`cat "unterminated`, nil, true},
		{"cat x\x00y", nil, true},
		{`cat $(whoami);`, []string{"cat", "$(whoami);"}, false},
	} {
		t.Run(tc.line, func(t *testing.T) {
			got, err := SplitLine(tc.line)
			if (err != nil) != tc.bad || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, %v; want %#v (bad=%t)", got, err, tc.want, tc.bad)
			}
		})
	}
}

func TestModeAndGroups(t *testing.T) {
	for _, v := range []string{"755", "0644", "4755", "0000", "7777"} {
		if _, err := parseMode(v); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"888", "10000", "-1", "u+x", ""} {
		if _, err := parseMode(v); err == nil {
			t.Fatalf("accepted mode %q", v)
		}
	}
	for _, v := range []string{"1,,2", "-1", "4294967296", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"} {
		if _, err := parseGroups(v); err == nil {
			t.Fatalf("accepted groups %q", v)
		}
	}
	g, err := parseGroups("0,4294967295")
	if err != nil || !reflect.DeepEqual(g, []uint32{0, 4294967295}) {
		t.Fatalf("%v %v", g, err)
	}
}

func FuzzSplitLine(f *testing.F) {
	for _, seed := range []string{"ls", `put "C:\My Files\x" 'remote x'`, "\x00", `cat \"x`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) { SplitLine(line) })
}
