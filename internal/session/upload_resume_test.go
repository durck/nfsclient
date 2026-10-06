package session

import (
	"bytes"
	"errors"
	"testing"
)

func TestUploadPrefixWriter(t *testing.T) {
	for _, tt := range []struct {
		name, local, first, second string
		size                       uint64
		bad                        bool
	}{
		{"matching", "abcdef", "ab", "cd", 4, false},
		{"mismatch", "abcdef", "ab", "cX", 4, true},
		{"short-local", "abc", "ab", "cd", 4, true},
		{"remote-growth", "abcdef", "ab", "cde", 4, true},
		{"empty", "", "", "", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader([]byte(tt.local))
			w := &uploadPrefixWriter{r: r, remaining: tt.size}
			if n, err := w.Write([]byte(tt.first)); err != nil || n != len(tt.first) {
				t.Fatal(n, err)
			}
			n, err := w.Write([]byte(tt.second))
			if tt.bad {
				if !errors.Is(err, ErrUploadPrefix) || n != 0 {
					t.Fatal(n, err)
				}
			} else if err != nil || w.remaining != 0 || n != len(tt.second) {
				t.Fatal(n, err, w.remaining)
			}
		})
	}
}
