package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestImmediateTransferChoices(t *testing.T) {
	for _, operation := range []string{"get", "put"} {
		for _, tc := range []struct {
			name, keys, target string
			replaced           bool
		}{
			{"overwrite", "o", "taken", true},
			{"uppercase", "O", "taken", true},
			{"ignore other keys and arrows", "x\t\x1b[Co", "taken", true},
			{"cancel", "c", "", false},
			{"enter cancels", "\n", "", false},
			{"rename", "rother name\n", "other name", false},
			{"rename collision", "rtaken\no", "taken", true},
		} {
			if operation == "put" {
				// This peer is NFSv3: replacing an existing file cannot preserve
				// its unobservable ACL. Exercise immediate rename/cancel keys.
				switch tc.name {
				case "overwrite":
					tc.keys, tc.target, tc.replaced = "oc", "", false
				case "uppercase":
					tc.keys, tc.target, tc.replaced = "Rother name\n", "other name", false
				case "ignore other keys and arrows":
					tc.keys, tc.target, tc.replaced = "x\t\x1b[Cc", "", false
				case "rename collision":
					tc.keys, tc.target, tc.replaced = "rtaken\nrother name\n", "other name", false
				}
			}
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				sh, root, _ := testShell(t)
				sh.Out, sh.Err = io.Discard, io.Discard
				source, destination := root, sh.LocalDir
				if operation == "put" {
					source, destination = sh.LocalDir, root
				}
				if err := os.WriteFile(filepath.Join(source, "source"), []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(destination, "taken"), []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
				history := filepath.Join(t.TempDir(), "history")
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				line := operation + " source taken"
				// No Enter after the choice; EOF follows immediately. A line-based
				// prompt would cancel instead of performing the selected action.
				if err := sh.runInteractive(ctx, history, inputConfig(line+"\n"+tc.keys)); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Join(destination, "taken"))
				want := "original"
				if tc.replaced {
					want = "new"
				}
				if err != nil || string(data) != want {
					t.Fatalf("taken = %q %v", data, err)
				}
				if tc.target != "" {
					data, err = os.ReadFile(filepath.Join(destination, tc.target))
					if err != nil || string(data) != "new" {
						t.Fatalf("target = %q %v", data, err)
					}
				}
				data, err = os.ReadFile(history)
				if err != nil || strings.TrimSpace(string(data)) != line {
					t.Fatalf("dialog leaked into history: %q %v", data, err)
				}
			})
		}
	}
}
