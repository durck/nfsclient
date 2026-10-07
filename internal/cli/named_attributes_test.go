package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestNamedAttributeExportNoClobberBeforeRemoteRead(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "existing")
	want := []byte{0, 255, 4}
	if err := os.WriteFile(destination, want, 0600); err != nil {
		t.Fatal(err)
	}
	// A nil session makes any attempt to inspect remote content a test failure.
	sh := &Shell{LocalDir: dir}
	err := sh.exportNamedAttribute(context.Background(), "/file", "binary", "existing")
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("no-clobber: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("destination changed: %x %v", got, err)
	}
}

func TestNamedAttributeExportCleansFailedRead(t *testing.T) {
	for _, name := range []string{"binary", ".."} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			sh := &Shell{LocalDir: dir, Session: &session.Session{Client: &nfs.Client{}}}
			err := sh.exportNamedAttribute(context.Background(), "/file", name, "new")
			if err == nil {
				t.Fatal("failed resolution/invalid name accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "new")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed export left local file: %v", err)
			}
		})
	}
}
