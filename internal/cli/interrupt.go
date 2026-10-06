package cli

import (
	"context"
	"sync"

	"github.com/chzyer/readline"
)

// Interrupts arrive as raw input while readline is active, and as OS signals
// while a command owns the terminal. Both paths share this state.
type interruptState struct {
	mu             sync.Mutex
	armed, exiting bool
	quit           context.CancelFunc
	operation      context.CancelFunc
}

func (s *interruptState) press() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.armed {
		s.exiting = true
		s.quit()
		return
	}
	s.armed = true
	if s.operation != nil {
		s.operation()
	}
}

func (s *interruptState) filter(r rune) (rune, bool) {
	if r == readline.CharInterrupt {
		s.press()
	} else {
		s.mu.Lock()
		s.armed = false
		s.mu.Unlock()
	}
	return r, true
}

func (s *interruptState) status() (armed, exiting bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.armed, s.exiting
}

func (s *interruptState) begin(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	s.operation = cancel
	if s.armed {
		cancel()
	}
	s.mu.Unlock()
	return ctx, func() {
		s.mu.Lock()
		s.operation = nil
		s.mu.Unlock()
		cancel()
	}
}
