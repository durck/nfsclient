package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishDownloadDoesNotClobber(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "stage"), filepath.Join(dir, "result")
	if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishDownload(source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("collision: %v", err)
	}
	for path, want := range map[string]string{source: "new", destination: "original"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("%s changed: %q %v", path, data, err)
		}
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := publishDownload(source, destination); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "new" {
		t.Fatalf("publish: %q %v", data, err)
	}
}
