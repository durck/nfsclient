package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestConvertRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "source.kt")
	original := syntheticKeytab(true)
	if err := os.WriteFile(input, original, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.kt")
	if err := os.Symlink(input, link); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "absent.kt")
	if err := convert(link, out); err == nil {
		t.Fatal("symlink input accepted")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("symlink input created output")
	}
	if err := convert(input, link); err == nil {
		t.Fatal("symlink output accepted")
	}
	dangling := filepath.Join(dir, "dangling.kt")
	if err := os.Symlink(out, dangling); err != nil {
		t.Fatal(err)
	}
	if err := convert(input, dangling); err == nil {
		t.Fatal("dangling symlink output accepted")
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatal("dangling symlink target created")
	}
	if got, err := os.ReadFile(input); err != nil || !bytes.Equal(got, original) {
		t.Fatal("source changed during symlink refusals")
	}
}
