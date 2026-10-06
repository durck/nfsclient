package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/session"
)

func TestRecursiveRoundTripAndCollision(t *testing.T) {
	sh, _, _ := testShell(t)
	source := filepath.Join(sh.LocalDir, "source")
	if err := os.MkdirAll(filepath.Join(source, "sub", "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("tree-content\x00"), 20000)
	if err := os.WriteFile(filepath.Join(source, "sub", "data"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "zero"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, cmd := range []string{"puttree source remote", "gettree remote downloaded"} {
		if _, err := sh.Execute(ctx, cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(sh.LocalDir, "downloaded", "sub", "data"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("different tree payload", err)
	}
	if info, err := os.Stat(filepath.Join(sh.LocalDir, "downloaded", "sub", "empty")); err != nil || !info.IsDir() {
		t.Fatal("missing empty directory", err)
	}
	for _, cmd := range []string{"puttree source remote", "gettree remote downloaded"} {
		if _, err := sh.Execute(ctx, cmd); err == nil {
			t.Fatalf("overwrote tree: %s", cmd)
		}
	}
}

func recursiveMetadataFlow(t *testing.T, s *session.Session, hardlinks bool) {
	t.Helper()
	ctx := context.Background()
	local := t.TempDir()
	source := filepath.Join(local, "source")
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sub", "file"), []byte("metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"file2", "file3"} {
		if err := os.Link(filepath.Join(source, "sub", "file"), filepath.Join(source, "sub", name)); err != nil {
			t.Fatal(err)
		}
	}
	links := runtime.GOOS != "windows"
	if links {
		if err := os.Symlink("file", filepath.Join(source, "sub", "link")); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Unix(1700000000, 123456700)
	if s.Client.Version() == "3" {
		// UNFS3 0.11.0 SETATTR stores whole seconds. Finer values must fail
		// the production readback guard; this success case uses its precision.
		stamp = stamp.Truncate(time.Second)
	}
	for _, name := range []string{"sub/file", "sub", "."} {
		if err := os.Chtimes(filepath.Join(source, name), stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			mode := os.FileMode(0550)
			if name == "sub/file" {
				mode = 0440
			}
			if err := os.Chmod(filepath.Join(source, name), mode); err != nil {
				t.Fatal(err)
			}
		}
	}
	opts := session.TreeOptions{Merge: true, Links: links, Hardlinks: hardlinks, MTime: true, Mode: runtime.GOOS != "windows"}
	if err := s.Mkdir(ctx, "metadata"); err != nil {
		t.Fatal(err)
	}
	if err := s.Mkdir(ctx, "metadata/sub"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(local, "result", "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	wantBytes := int64(24)
	if hardlinks {
		wantBytes = 8
	}
	if n, err := s.PutTreeWithOptions(ctx, source, "metadata", opts, nil); err != nil || n != wantBytes {
		t.Fatal("metadata upload", n, err)
	}
	if n, err := s.GetTreeWithOptions(ctx, "metadata", filepath.Join(local, "result"), opts, nil); err != nil || n != wantBytes {
		t.Fatal("metadata download", n, err)
	}
	for _, name := range []string{"sub/file", "sub", "."} {
		info, err := os.Stat(filepath.Join(local, "result", name))
		if err != nil || !info.ModTime().Equal(stamp) {
			t.Fatal("mtime changed", name, info, err)
		}
		if opts.Mode {
			original, err := os.Stat(filepath.Join(source, name))
			if err != nil || info.Mode().Perm() != original.Mode().Perm() {
				t.Fatal("mode changed", name, err)
			}
		}
	}
	if links {
		if target, err := os.Readlink(filepath.Join(local, "result", "sub", "link")); err != nil || target != "file" {
			t.Fatal("link round trip", target, err)
		}
	}
	// Restore write permission on result/sub so t.TempDir cleanup can remove it.
	// GetTreeWithOptions preserves mode (0550 → no write), which blocks RemoveAll.
	if opts.Mode {
		_ = filepath.WalkDir(filepath.Join(local, "result"), func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	}
	first, err := os.Stat(filepath.Join(local, "result", "sub", "file"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"file2", "file3"} {
		other, err := os.Stat(filepath.Join(local, "result", "sub", name))
		if err != nil || opts.Hardlinks && !os.SameFile(first, other) {
			t.Fatal("hardlink group was copied independently", name, err)
		}
	}
	// Explicitly restore only these test directories so the fixed UID can unlink.
	for _, name := range []string{"metadata", "metadata/sub"} {
		if err := s.Chmod(ctx, name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Remove(ctx, "metadata/sub/file"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"file2", "file3"} {
		if err := s.Remove(ctx, "metadata/sub/"+name); err != nil {
			t.Fatal(err)
		}
	}
	if links {
		if err := s.Remove(ctx, "metadata/sub/link"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Rmdir(ctx, "metadata/sub"); err != nil {
		t.Fatal(err)
	}
	if err := s.Rmdir(ctx, "metadata"); err != nil {
		t.Fatal(err)
	}
}

func TestRecursiveMetadata(t *testing.T) {
	sh, _, _ := testShell(t)
	// go-nfs v0.0.4 decodes LINK as SYMLINK. Native servers cover hardlinks.
	recursiveMetadataFlow(t, sh.Session, false)
}

func TestRecursiveLinksAndMergeRefusal(t *testing.T) {
	sh, root, _ := testShell(t)
	source := filepath.Join(sh.LocalDir, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "target"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"link": "target", "dangling": "missing", "loop": ".", "outside": "../../outside"} {
		if err := os.Symlink(target, filepath.Join(source, name)); err != nil {
			t.Skipf("OS symlink privilege unavailable: %v", err)
		}
		// On Windows, directory symlinks may be expanded to absolute paths on readback,
		// producing backslash targets that portableTreeLink correctly rejects.
		if got, rerr := os.Readlink(filepath.Join(source, name)); rerr != nil || strings.ContainsAny(got, "\\\x00") {
			t.Skipf("symlink target %q reads back as %q (not portable): %v", target, got, rerr)
		}
	}
	ctx := context.Background()
	for _, cmd := range []string{"puttree --links source remote", "gettree --links remote result"} {
		if _, err := sh.Execute(ctx, cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
	for _, base := range []string{filepath.Join(root, "remote"), filepath.Join(sh.LocalDir, "result")} {
		for name, target := range map[string]string{"link": "target", "dangling": "missing", "loop": ".", "outside": "../../outside"} {
			if got, err := os.Readlink(filepath.Join(base, name)); err != nil || got != target {
				t.Fatal("link was followed or rewritten", name, got, err)
			}
		}
	}
	// Existing directory links must never redirect a merge, even inside its root.
	if err := os.Mkdir(filepath.Join(source, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(sh.LocalDir, "merge"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(sh.LocalDir, "merge", "sub")); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(ctx, "puttree --links source withsub"); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(ctx, "gettree --merge --links withsub merge"); err == nil || !strings.Contains(err.Error(), "not a link") {
		t.Fatal("followed destination directory link", err)
	}
}

func TestRecursiveRejectsLinksBeforeCreatingDestination(t *testing.T) {
	sh, root, _ := testShell(t)
	for _, dir := range []string{filepath.Join(sh.LocalDir, "source"), filepath.Join(root, "remote")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("..", filepath.Join(dir, "loop")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	ctx := context.Background()
	if _, err := sh.Execute(ctx, "puttree source newremote"); err == nil {
		t.Fatal("followed upload link")
	}
	if _, err := os.Stat(filepath.Join(root, "newremote")); !os.IsNotExist(err) {
		t.Fatal("created remote before preflight")
	}
	if _, err := sh.Execute(ctx, "gettree remote newlocal"); err == nil {
		t.Fatal("followed download link")
	}
	if _, err := os.Stat(filepath.Join(sh.LocalDir, "newlocal")); !os.IsNotExist(err) {
		t.Fatal("created local before preflight")
	}
}

func TestRecursiveMerge(t *testing.T) {
	sh, root, _ := testShell(t)
	for _, dir := range []string{filepath.Join(sh.LocalDir, "source", "sub"), filepath.Join(sh.LocalDir, "downloaded", "sub"), filepath.Join(root, "remote", "sub")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{filepath.Join(sh.LocalDir, "downloaded"), filepath.Join(root, "remote")} {
		if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("untouched"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sh.LocalDir, "source", "sub", "new"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, cmd := range []string{"puttree --merge source remote", "gettree --merge remote downloaded"} {
		// The download source includes keep, so remove only its local copy first.
		if cmd[0] == 'g' {
			if err := os.Remove(filepath.Join(sh.LocalDir, "downloaded", "keep")); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := sh.Execute(ctx, cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
	for _, dir := range []string{filepath.Join(sh.LocalDir, "downloaded"), filepath.Join(root, "remote")} {
		if b, err := os.ReadFile(filepath.Join(dir, "sub", "new")); err != nil || string(b) != "payload" {
			t.Fatal("merged content", err)
		}
		if b, err := os.ReadFile(filepath.Join(dir, "keep")); err != nil || string(b) != "untouched" {
			t.Fatal("unrelated file changed", err)
		}
	}
	for _, cmd := range []string{"puttree --merge source remote", "gettree --merge remote downloaded", "puttree --unknown source remote"} {
		if _, err := sh.Execute(ctx, cmd); err == nil {
			t.Fatal("accepted collision or invalid flag", cmd)
		}
	}
}
