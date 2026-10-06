package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chzyer/readline"
)

func TestConsecutiveInterrupts(t *testing.T) {
	ctx, quit := context.WithCancel(context.Background())
	defer quit()
	s := &interruptState{quit: quit}
	operation, finish := s.begin(ctx)
	s.press() // OS signal while executing a command.
	if operation.Err() == nil || ctx.Err() != nil {
		t.Fatal("first interrupt must cancel only the operation")
	}
	finish()
	s.filter('x')
	s.filter(readline.CharBackspace)
	s.filter(readline.CharInterrupt)
	if ctx.Err() != nil {
		t.Fatal("typing did not reset the exit confirmation")
	}
	s.filter(readline.CharInterrupt)
	if ctx.Err() == nil {
		t.Fatal("second consecutive interrupt did not exit")
	}
}

func inputConfig(input string) func(*readline.Config) {
	return func(cfg *readline.Config) {
		cfg.Stdin = readline.NewCancelableStdin(strings.NewReader(input))
		cfg.FuncIsTerminal = func() bool { return true }
		cfg.FuncMakeRaw = func() error { return nil }
		cfg.FuncExitRaw = func() error { return nil }
		cfg.FuncOnWidthChanged = func(func()) {}
		cfg.FuncGetWidth = func() int { return 100 }
	}
}

func TestInteractiveDoubleCtrlCAndHistory(t *testing.T) {
	for _, tc := range []struct{ name, input, history string }{
		{"empty", "\x03\x03", ""},
		{"discard input", "not-a-command\x03\x03", ""},
		{"command resets", "\x03pwd\n\x03\x03", "pwd"},
		{"typing then delete resets", "\x03x\x7f\x03pwd\n\x03\x03", "pwd"},
		{"cancel collision", "get source taken\n\x03\x03", "get source taken"},
		{"overwrite answer omitted", "get source taken\no\n\x03\x03", "get source taken"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sh, root, _ := testShell(t)
			sh.Out, sh.Err = io.Discard, io.Discard
			if err := os.WriteFile(filepath.Join(root, "source"), []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(sh.LocalDir, "taken"), []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			history := filepath.Join(t.TempDir(), "history")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := sh.runInteractive(ctx, history, inputConfig(tc.input)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(history)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(data)); got != tc.history {
				t.Fatalf("history: %q, want %q", got, tc.history)
			}
			if strings.Contains(tc.name, "collision") {
				data, err := os.ReadFile(filepath.Join(sh.LocalDir, "taken"))
				if err != nil || string(data) != "original" {
					t.Fatal("Ctrl+C changed destination")
				}
			}
		})
	}
}
