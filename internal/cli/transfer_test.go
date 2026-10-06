package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chzyer/readline"
	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func TestTransferConflictChoices(t *testing.T) {
	for _, operation := range []string{"get", "put"} {
		for _, choice := range []string{"overwrite", "rename", "cancel", "empty", "interrupt", "eof", "batch"} {
			t.Run(operation+"/"+choice, func(t *testing.T) {
				sh, root, _ := testShell(t)
				sourceDir, destinationDir := root, sh.LocalDir
				if operation == "put" {
					sourceDir, destinationDir = sh.LocalDir, root
				}
				if err := os.MkdirAll(filepath.Join(destinationDir, "sub"), 0755); err != nil {
					t.Fatal(err)
				}
				source := filepath.Join(sourceDir, "source")
				destination := filepath.Join(destinationDir, "sub", "existing")
				if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destination, []byte("old and much longer"), 0600); err != nil {
					t.Fatal(err)
				}
				calls := 0
				sh.Ask = func(prompt string) (string, error) {
					calls++
					if strings.Contains(sh.Err.(*bytes.Buffer).String(), "GET ") || strings.Contains(sh.Err.(*bytes.Buffer).String(), "PUT ") {
						t.Fatal("progress started before confirmation")
					}
					switch choice {
					case "overwrite":
						if operation == "put" && calls > 1 {
							return "c", nil // Legacy upload offers rename/cancel only.
						}
						return "o", nil
					case "rename":
						if calls == 1 {
							return "r", nil
						}
						return "new name", nil
					case "interrupt":
						return "", readline.ErrInterrupt
					case "eof":
						return "", io.EOF
					case "empty":
						return "", nil
					default:
						return "c", nil
					}
				}
				if choice == "batch" {
					sh.Ask = nil
				}
				_, err := sh.Execute(context.Background(), operation+" source sub/existing")
				if choice == "batch" {
					if !errors.Is(err, session.ErrDestinationExists) {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				want := "old and much longer"
				if choice == "overwrite" && operation == "get" {
					want = "new"
				}
				if choice == "overwrite" && operation == "put" {
					notice := sh.Err.(*bytes.Buffer).String()
					if calls != 2 || !strings.Contains(notice, "cannot preserve ACLs") || strings.Contains(notice, "PUT ") {
						t.Fatalf("legacy choice did not explain refusal before transfer: %s", notice)
					}
				}
				data, err := os.ReadFile(destination)
				if err != nil || string(data) != want {
					t.Fatalf("destination = %q, %v", data, err)
				}
				if choice == "rename" {
					data, err := os.ReadFile(filepath.Join(destinationDir, "sub", "new name"))
					if err != nil || string(data) != "new" {
						t.Fatalf("renamed = %q, %v", data, err)
					}
				}
				if choice != "batch" && calls == 0 {
					t.Fatal("no collision prompt")
				}
				matches, _ := filepath.Glob(filepath.Join(destinationDir, "sub", ".nfs-*"))
				if len(matches) != 0 {
					t.Fatalf("leaked temp files: %v", matches)
				}
			})
		}
	}
}

func TestReplacementCancellationOrLegacyRefusalPreservesOriginal(t *testing.T) {
	for _, operation := range []string{"get", "put"} {
		t.Run(operation, func(t *testing.T) {
			sh, root, _ := testShell(t)
			sourceDir, destDir := root, sh.LocalDir
			if operation == "put" {
				sourceDir, destDir = sh.LocalDir, root
			}
			if err := os.WriteFile(filepath.Join(sourceDir, "source"), bytes.Repeat([]byte("data"), 20000), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(destDir, "existing"), []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			options := session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
				if done > 0 {
					cancel()
				}
			}}
			var err error
			if operation == "get" {
				_, err = sh.Session.GetWithOptions(ctx, "source", filepath.Join(destDir, "existing"), options)
			} else {
				_, err = sh.Session.PutWithOptions(ctx, filepath.Join(sourceDir, "source"), "existing", options)
			}
			if err == nil {
				t.Fatal("canceled replacement succeeded")
			}
			if operation == "put" && !errors.Is(err, nfs.ErrLegacyReplacementUnsupported) {
				t.Fatalf("expected explicit legacy refusal: %v", err)
			}
			data, readErr := os.ReadFile(filepath.Join(destDir, "existing"))
			if readErr != nil || string(data) != "original" {
				t.Fatalf("original changed: %q %v", data, readErr)
			}
			matches, _ := filepath.Glob(filepath.Join(destDir, ".nfs-*"))
			if len(matches) != 0 {
				t.Fatalf("leaked temp files: %v; error: %v", matches, err)
			}
		})
	}
}

func TestRenameRechecksAndNonRegularDestination(t *testing.T) {
	for _, operation := range []string{"get", "put"} {
		t.Run(operation, func(t *testing.T) {
			sh, root, _ := testShell(t)
			sourceDir, destDir := root, sh.LocalDir
			if operation == "put" {
				sourceDir, destDir = sh.LocalDir, root
			}
			if err := os.WriteFile(filepath.Join(sourceDir, "source"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(destDir, "directory"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(destDir, "taken"), []byte("preserved"), 0600); err != nil {
				t.Fatal(err)
			}
			answers := []string{"o", "r", "taken", "invalid", "r", "fresh"}
			sh.Ask = func(string) (string, error) {
				if len(answers) == 0 {
					return "", fmt.Errorf("unexpected question")
				}
				a := answers[0]
				answers = answers[1:]
				return a, nil
			}
			if _, err := sh.Execute(context.Background(), operation+" source directory"); err != nil {
				t.Fatal(err)
			}
			if len(answers) != 0 {
				t.Fatal("skipped expected collision prompt")
			}
			info, err := os.Stat(filepath.Join(destDir, "fresh"))
			if err != nil || info.Size() != 0 {
				t.Fatalf("empty renamed transfer: %v %v", info, err)
			}
			data, err := os.ReadFile(filepath.Join(destDir, "taken"))
			if err != nil || string(data) != "preserved" {
				t.Fatal("renaming overwrote another collision")
			}
		})
	}
}
