package session

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUploadReaderDetectsChangedSource(t *testing.T) {
	for _, change := range []string{"grow", "shrink", "rewrite"} {
		t.Run(change, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			r := &uploadReader{f: f, before: info, remaining: info.Size()}
			data := []byte("changed!")
			if change == "grow" {
				data = append(data, 'x')
			}
			if change == "shrink" {
				data = data[:3]
			}
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(name, time.Now(), info.ModTime().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, r); !errors.Is(err, ErrUploadSourceChanged) {
				t.Fatalf("accepted %s: %v", change, err)
			}
		})
	}
}
