package cli

import (
	"reflect"
	"testing"

	"nfsclient/internal/session"
)

func TestTreeOptionsPositionAndLiteralPaths(t *testing.T) {
	for _, args := range [][]string{
		{"--merge", "--hardlinks", "source", "destination", "--skip-offline"},
		{"source", "--merge", "destination", "--hardlinks", "--skip-offline"},
	} {
		opts, paths, err := parseTreeOptions("gettree", args)
		want := session.TreeOptions{Merge: true, Hardlinks: true, SkipOffline: true}
		if err != nil || opts != want || !reflect.DeepEqual(paths, []string{"source", "destination"}) {
			t.Fatalf("%q: %+v %q %v", args, opts, paths, err)
		}
	}
	opts, paths, err := parseTreeOptions("puttree", []string{"--links=false", "--", "--links", "--destination"})
	if err != nil || opts.Links || !reflect.DeepEqual(paths, []string{"--links", "--destination"}) {
		t.Fatalf("literal paths: %+v %q %v", opts, paths, err)
	}
	for _, args := range [][]string{
		{"source", "destination", "--skip-offline"},
		{"--unknown", "source", "destination"},
		{"--merge=invalid", "source", "destination"},
		{"source"},
		{"source", "destination", "extra"},
	} {
		if _, _, err := parseTreeOptions("puttree", args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
}
