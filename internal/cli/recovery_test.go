package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"nfsclient/internal/session"
)

func TestReconnectRestoresDirectoryAndCredentials(t *testing.T) {
	sh, root, _ := testShell(t)
	ctx := context.Background()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(ctx, "cd sub"); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(ctx, "uid 123 456 7,8"); err != nil {
		t.Fatal(err)
	}
	old := sh.Session.Client
	old.Close()
	if _, err := sh.Execute(ctx, "reconnect"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sh.Session.Client.Close)
	if sh.Session.Client == old || sh.Session.CWD != "/sub" || sh.Session.Client.Auth.UID != 123 || sh.Session.Client.Auth.GID != 456 {
		t.Fatalf("state changed: cwd=%s auth=%+v", sh.Session.CWD, sh.Session.Client.Auth)
	}
	if _, err := sh.Execute(ctx, "ls"); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectFailureDoesNotRedirectWorkingDirectory(t *testing.T) {
	sh, root, _ := testShell(t)
	ctx := context.Background()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := sh.Session.CD(ctx, "sub"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "sub")); err != nil {
		t.Fatal(err)
	}
	old := sh.Session.Client
	if err := sh.Session.Reconnect(ctx); err == nil {
		t.Fatal("missing cwd accepted")
	}
	if sh.Session.Client != old || sh.Session.CWD != "/sub" {
		t.Fatal("failed reconnect changed session")
	}
}

func TestResumeInterruptedDownloadAndReconnect(t *testing.T) {
	sh, root, _ := testShell(t)
	payload := bytes.Repeat([]byte("resume-prefix-content"), 32000)
	if err := os.WriteFile(filepath.Join(root, "source"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(sh.LocalDir, "out")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n, err := sh.Session.GetResume(ctx, "source", dest, func(done, total uint64) {
		if done >= 32768 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || n <= 0 || n >= int64(len(payload)) {
		t.Fatalf("interrupt: %d %v", n, err)
	}
	part, err := os.ReadFile(dest + ".nfs-part")
	if err != nil || !bytes.Equal(part, payload[:n]) {
		t.Fatalf("partial: %d %v", len(part), err)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published incomplete file")
	}
	if err := sh.Session.Reconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sh.Session.Client.Close)
	if _, err := sh.Execute(context.Background(), "reget source out"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("resumed bytes differ", err)
	}
	for _, suffix := range []string{".nfs-part", ".nfs-part.lock"} {
		if _, err := os.Lstat(dest + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("left %s: %v", suffix, err)
		}
	}
}

func TestResumeRefusesChangedPrefixAndKeepsOriginal(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "source"), []byte("new contents"), 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(sh.LocalDir, "out")
	if err := os.WriteFile(dest+".nfs-part", []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Session.GetResume(context.Background(), "source", dest, nil); !errors.Is(err, session.ErrResumePrefix) {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest + ".nfs-part")
	if err != nil || string(got) != "old" {
		t.Fatal("changed retained partial", err)
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published mismatch")
	}
}

func TestResumeRefusesDestinationAndLock(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "source"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(sh.LocalDir, "out")
	if err := os.WriteFile(dest+".nfs-part.lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Session.GetResume(context.Background(), "source", dest, nil); err == nil {
		t.Fatal("ignored resume lock")
	}
	if err := os.Remove(dest + ".nfs-part.lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Session.GetResume(context.Background(), "source", dest, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Session.GetResume(context.Background(), "source", dest, nil); !errors.Is(err, session.ErrDestinationExists) {
		t.Fatal(err)
	}
}
