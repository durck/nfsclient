package cli

import (
	"io"
	"strings"
	"sync"
)

// Limit readline's read-ahead to one byte so a prompt can change input modes
// without consuming the following answer. A valid choice injects a newline at
// the terminal-reader layer, which pauses readline exactly like a real Enter.
type choiceInput struct {
	io.ReadCloser
	mu     sync.Mutex
	keys   string
	enter  bool
	escape int
}

func (r *choiceInput) choices(keys string) {
	r.mu.Lock()
	r.keys, r.escape = keys, 0
	r.mu.Unlock()
}

func (r *choiceInput) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		r.mu.Lock()
		if r.enter {
			r.enter = false
			r.mu.Unlock()
			b[0] = '\n'
			return 1, nil
		}
		r.mu.Unlock()
		n, err := r.ReadCloser.Read(b[:1])
		if n == 0 {
			return n, err
		}
		r.mu.Lock()
		if r.keys == "" {
			r.mu.Unlock()
			return n, err
		}
		c := b[0]
		// Preserve interrupt, EOF, and the default (Enter) cancellation.
		if c == 3 || c == 4 || c == '\r' || c == '\n' {
			r.escape = 0
			r.mu.Unlock()
			return n, err
		}
		if r.escape != 0 {
			if r.escape == 1 && (c == '[' || c == 'O') {
				r.escape = 2
			} else if r.escape == 1 || c >= 0x40 && c <= 0x7e {
				r.escape = 0
			}
			r.mu.Unlock()
			continue
		}
		if c == 27 {
			r.escape = 1
			r.mu.Unlock()
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if strings.IndexByte(r.keys, c) >= 0 {
			b[0] = c
			r.enter = true
			r.mu.Unlock()
			return n, err
		}
		r.mu.Unlock()
		// Ignore unsupported keys, including history and completion controls.
	}
}
