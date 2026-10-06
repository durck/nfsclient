package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalListingAndCompletion(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "folder"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notes with spaces.txt", ".env.example"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	sh := &Shell{LocalDir: root, Out: &out}
	cwd, _ := os.Getwd()
	if _, err := sh.Execute(context.Background(), "lls"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "folder/") || !strings.Contains(out.String(), `"notes with spaces.txt"`) || !strings.Contains(out.String(), "4 B") {
		t.Fatal(out.String())
	}
	if strings.Index(out.String(), "folder/") > strings.Index(out.String(), ".env.example") {
		t.Fatal("local directories not first")
	}
	if strings.Contains(out.String(), "OWNER") {
		t.Fatal("invented portable owner IDs")
	}
	after, _ := os.Getwd()
	if cwd != after || sh.LocalDir != root {
		t.Fatal("lls changed cwd")
	}
	out.Reset()
	if _, err := sh.Execute(context.Background(), `lls "notes with spaces.txt"`); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "folder/") {
		t.Fatal("single-file listing included siblings")
	}
	for _, line := range []string{"lls missing", "lls a b"} {
		if _, err := sh.Execute(context.Background(), line); err == nil {
			t.Fatalf("accepted %q", line)
		}
	}
	c := &completer{shell: sh, ctx: context.Background()}
	for _, tc := range []struct{ input, want string }{{"ll", "s "}, {"lls no", `tes\ with\ spaces.txt `}, {"lls fo", "lder" + string(filepath.Separator)}} {
		got, _ := c.Do([]rune(tc.input), len([]rune(tc.input)))
		found := false
		for _, v := range got {
			if string(v) == tc.want {
				found = true
			}
		}
		if !found {
			t.Fatalf("completion %q: %q", tc.input, got)
		}
	}
	if _, err := sh.Execute(context.Background(), "lcd folder"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if _, err := sh.Execute(context.Background(), "lls"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "0 entries") {
		t.Fatal(out.String())
	}
}

func TestLocalListingSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "folder"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("folder", filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("absent", filepath.Join(root, "broken")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sh := &Shell{Out: &out, LocalDir: root}
	if _, err := sh.Execute(context.Background(), "lls"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"link@ -> folder", "broken@ -> absent [missing]"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal(out.String())
		}
	}
	out.Reset()
	if _, err := sh.Execute(context.Background(), "lls link/"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "0 entries") {
		t.Fatal(out.String())
	}
}
