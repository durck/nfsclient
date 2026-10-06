package client

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestCAPathsParser(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       []string
		bad        bool
	}{
		{name: "absent", text: "[libdefaults]\n default_realm = HOME"},
		{name: "empty", text: "[capaths]", bad: true}, // parsed, but denies a foreign realm
		{name: "direct", text: "[capaths]\n HOME = {\n TARGET = .\n }", want: []string{"HOME", "TARGET"}},
		{name: "ordered repeated", text: "# comment\n[capaths]\n HOME = {\n TARGET = FIRST ; comment\n TARGET = SECOND THIRD\n }", want: []string{"HOME", "FIRST", "SECOND", "THIRD", "TARGET"}},
		{name: "case sensitive", text: "[capaths]\n home = {\n TARGET = .\n }", bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseCAPaths(tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "absent" {
				if p != nil {
					t.Fatal("absent section enabled policy")
				}
				return
			}
			got, err := p.route("HOME", "TARGET")
			if tc.bad {
				if err == nil {
					t.Fatal("unlisted route allowed")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("route=%v err=%v", got, err)
			}
			local, err := p.route("HOME", "HOME")
			if err != nil || !reflect.DeepEqual(local, []string{"HOME"}) {
				t.Fatal("local realm denied")
			}
			got[1] = "ALTERED"
			again, _ := p.route("HOME", "TARGET")
			if !reflect.DeepEqual(again, tc.want) {
				t.Fatal("caller mutated policy")
			}
		})
	}
	invalid := []string{
		"include /tmp/other", "includedir /tmp/other", "module plugin", "[capaths]*", "[CAPATHS]", "[capaths]\n[capaths]",
		"[capaths]\n HOME = {\n TARGET = .", "[capaths]\n }", "[capaths]\n HOME = {\n[realms]",
		"[capaths]\n HOME = {\n }\n HOME = {\n }", "[capaths]\n HOME = { TARGET = . }",
		"[capaths]\n HOME* = {\n }", "[capaths]\n HOME = {\n TARGET* = .\n }",
		"[capaths]\n HOME = {\n TARGET = .\n }*", "[capaths]\n HOME = {\n TARGET = A\n TARGET = A\n }",
		"[capaths]\n HOME = {\n TARGET = .\n TARGET = A\n }", "[capaths]\n HOME = {\n TARGET = A\n TARGET = .\n }",
		"[capaths]\n HOME = {\n TARGET = .\n TARGET = .\n }", strings.Repeat("x", 1<<20+1), "#" + strings.Repeat("x", 65536),
	}
	for _, value := range []string{"", "HOME", "TARGET", ". A", "A .", "A B A", "A B C D E F", "A/B", "\"A\"", "*", "РЕАЛМ"} {
		invalid = append(invalid, "[capaths]\n HOME = {\n TARGET = "+value+"\n }")
	}
	for i, text := range invalid {
		t.Run(fmt.Sprintf("invalid-%d", i), func(t *testing.T) {
			if _, err := ParseCAPaths(text); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	for _, limit := range []string{"blocks", "routes"} {
		t.Run(limit, func(t *testing.T) {
			text := "[capaths]\n"
			n := 65
			if limit == "routes" {
				n = 1
			}
			for i := 0; i < n; i++ {
				text += fmt.Sprintf("HOME%d = {\n", i)
				for j := 0; j < 257 && limit == "routes"; j++ {
					text += fmt.Sprintf(" TARGET%d = .\n", j)
				}
				text += "}\n"
			}
			if _, err := ParseCAPaths(text); err == nil {
				t.Fatal("unbounded policy accepted")
			}
		})
	}
}
