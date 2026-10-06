package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
	"nfs-viewer/internal/testutil/nfsv2"
)

func TestNamespaceCommands(t *testing.T) {
	sh, root, _ := testShell(t)
	ctx := context.Background()
	run := func(line string) {
		t.Helper()
		if _, err := sh.Execute(ctx, line); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	fail := func(line string) {
		t.Helper()
		if _, err := sh.Execute(ctx, line); err == nil {
			t.Fatalf("accepted %s", line)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	run("rm empty")
	if _, err := os.Stat(filepath.Join(root, "empty")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty file remains", err)
	}
	fail("rm empty")
	run("mkdir old")
	run("mkdir destination")
	fail("rm old")
	if err := os.WriteFile(filepath.Join(root, "old", "file"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	fail("rmdir old")
	fail("mv old/file")
	run("mv old/file destination/file")
	got, err := os.ReadFile(filepath.Join(root, "destination", "file"))
	if err != nil || string(got) != "payload" {
		t.Fatal("move changed bytes", err)
	}
	if err := os.WriteFile(filepath.Join(root, "old", "replacement"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	run("mv old/replacement destination/file")
	got, err = os.ReadFile(filepath.Join(root, "destination", "file"))
	if err != nil || string(got) != "new" {
		t.Fatal("explicit replacement failed", err)
	}
	run("cd old")
	fail("rmdir /old")
	fail("mv /old /renamed")
	run("cd /")
	run("rmdir old")
	run("mv destination renamed")
	fail("rmdir renamed")
	run("rm renamed/file")
	run("rmdir renamed")
	for _, line := range []string{"rm /", "rm .", "rm ..", "rmdir /", "mv / x", "mv x /", "rm", "rmdir", "mv"} {
		fail(line)
	}
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "link")); err == nil {
		run("rm link")
		got, err := os.ReadFile(filepath.Join(root, "target"))
		if err != nil || string(got) != "keep" {
			t.Fatal("followed removal symlink", err)
		}
	} else {
		t.Logf("OS symlink privilege unavailable: %v", err)
	}
}

func namespaceFlow(t *testing.T, s *session.Session, permissions bool) {
	t.Helper()
	ctx := context.Background()
	sh := &Shell{Session: s, Out: io.Discard, Err: io.Discard, LocalDir: t.TempDir()}
	run := func(line string) {
		t.Helper()
		if _, err := sh.Execute(ctx, line); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	fail := func(line string) {
		t.Helper()
		if _, err := sh.Execute(ctx, line); err == nil {
			t.Fatalf("accepted %s", line)
		}
	}
	for name, body := range map[string]string{"a": "first", "b": "replacement", "empty": ""} {
		if err := os.WriteFile(filepath.Join(sh.LocalDir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run("mkdir work")
	run("cd work")
	run("put empty empty")
	run("rm empty")
	if _, _, err := s.Resolve(ctx, "empty", false); !errors.Is(err, nfs.Status(2)) {
		t.Fatal("removed empty file remains", err)
	}
	run("mkdir src")
	run("mkdir dst")
	run("put a src/a")
	run("put b dst/b")
	fail("rm src")
	fail("rmdir src")
	fail("rmdir src/a")
	run("mv dst/b src/a")
	run("get src/a result")
	if b, err := os.ReadFile(filepath.Join(sh.LocalDir, "result")); err != nil || string(b) != "replacement" {
		t.Fatal("replacement bytes", string(b), err)
	}
	run("mv src/a src/a")
	fail("mv src src/child")
	run("mv src renamed")
	if permissions {
		dir, _, err := s.Resolve(ctx, "renamed", true)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Client.Symlink(ctx, dir.Handle, "link", "a"); err != nil {
			t.Fatal(err)
		}
		run("mv renamed/link dst/link")
		run("rm dst/link")
		if _, _, err := s.Resolve(ctx, "renamed/a", false); err != nil {
			t.Fatal("symlink operation removed target", err)
		}
		id, err := s.Lock(ctx, "renamed/a", false)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range []string{"rm renamed/a", "mv renamed/a dst/b", "rmdir dst"} {
			if _, err := sh.Execute(ctx, line); !errors.Is(err, nfs.ErrLocksHeld) {
				t.Fatal("mutation with retained lock", line, err)
			}
		}
		if err := s.Client.Unlock(ctx, id); err != nil {
			t.Fatal(err)
		}
		delete(s.LockPaths, id)
		run("chmod 500 renamed")
		// Automatic identity selection must not bypass parent permissions.
		auth := s.Client.Auth
		s.AutoUID = true
		fail("rm renamed/a")
		fail("mv renamed/a dst/b")
		if !s.AutoUID || !reflect.DeepEqual(auth, s.Client.Auth) {
			t.Fatal("namespace operation changed identity policy")
		}
		s.AutoUID = false
		run("chmod 700 renamed")
	}
	run("rm renamed/a")
	run("rmdir renamed")
	run("rmdir dst")
	fail("rmdir ../work")
	fail("mv ../work ../moved")
	run("cd ..")
	run("rmdir work")
}

func TestNamespaceV2(t *testing.T) {
	for _, udp := range []bool{false, true} {
		t.Run(fmt.Sprint("udp=", udp), func(t *testing.T) {
			server := nfsv2.Start(t, nfsv2.Options{UDP: udp})
			namespaceFlow(t, v2Session(t, server), false)
			if len(server.Names()) != 0 {
				t.Fatal("namespace leftovers", server.Names())
			}
		})
	}
}

func TestNamespaceFreeBSD(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NAMESPACE_FREEBSD") != "1" {
		t.Skip("disposable FreeBSD namespace fixture not selected")
	}
	host, port, _, _ := pnfsFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			ctx := context.Background()
			c, err := nfs.Connect(ctx, nfs.Config{Host: host, NFSPort: port, Version: version, Timeout: 3 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}})
			if err != nil {
				t.Fatal(err)
			}
			s := session.New(c, host, false, false, nil)
			defer s.Client.Close()
			if err := s.Use(ctx, pnfsFixtureExport()); err != nil {
				t.Fatal(err)
			}
			root := fmt.Sprintf("namespace-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			if err := s.Mkdir(ctx, root); err != nil {
				t.Fatal(err)
			}
			if err := s.CD(ctx, root); err != nil {
				t.Fatal(err)
			}
			namespaceFlow(t, s, true)
			recursiveMetadataFlow(t, s, true)
			multiRangeFlow(t, s)
			if err := s.CD(ctx, "/"); err != nil {
				t.Fatal(err)
			}
			if err := s.Rmdir(ctx, root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNamespaceFreeBSDCLI(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NAMESPACE_FREEBSD") != "1" {
		t.Skip("disposable FreeBSD namespace fixture not selected")
	}
	host, port, _, _ := pnfsFixture(t)
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			source, dest := filepath.Join(dir, "source"), filepath.Join(dir, "dest")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "file"), []byte("release payload"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(source, "file"), filepath.Join(source, "alias")); err != nil {
				t.Fatal(err)
			}
			patch := filepath.Join(dir, "patch")
			if err := os.WriteFile(patch, []byte("patched"), 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("namespace-cli-%s-%s-%d", runtime.GOOS, version, time.Now().UnixNano())
			args := []string{host, "--nfs-version", version, "--nfs-port", strconv.Itoa(port), "--export", pnfsFixtureExport(), "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--no-banner", "--progress", "never", "--color", "never"}
			linked := filepath.Join(dir, "linked")
			for _, command := range []string{
				"mkdir " + name,
				"puttree --merge --hardlinks --preserve-mtime " + strconv.Quote(source) + " " + name,
				"gettree --hardlinks " + name + " " + strconv.Quote(linked),
				"put " + strconv.Quote(filepath.Join(source, "file")) + " " + name + "/replacement",
				"mv " + name + "/replacement " + name + "/file",
				"lock " + name + "/file write 0 7", "lock " + name + "/file write 7 8",
				"getrange " + name + "/file " + strconv.Quote(filepath.Join(dir, "chunk")) + " 0 7",
				"putrange " + strconv.Quote(patch) + " " + name + "/file 0",
				"unlock 1", "unlock 2",
				"gettree --hardlinks --preserve-mtime " + name + " " + strconv.Quote(dest),
				"rm " + name + "/file", "rm " + name + "/alias", "rmdir " + name,
			} {
				args = append(args, "-c", command)
			}
			out, err := runKerberosCLI(t, args)
			if err != nil {
				t.Fatal(err, out)
			}
			if b, err := os.ReadFile(filepath.Join(dest, "file")); err != nil || string(b) != "patched payload" {
				t.Fatal("CLI bytes", err)
			}
			if b, err := os.ReadFile(filepath.Join(dir, "chunk")); err != nil || string(b) != "release" {
				t.Fatal("CLI range bytes", err)
			}
			left, err := os.Stat(filepath.Join(linked, "file"))
			if err != nil {
				t.Fatal(err)
			}
			right, err := os.Stat(filepath.Join(linked, "alias"))
			if err != nil || !os.SameFile(left, right) {
				t.Fatal("CLI hardlink identity", err)
			}
			if b, err := os.ReadFile(filepath.Join(dest, "alias")); err != nil || string(b) != "release payload" {
				t.Fatal("rename modified another hardlink", err)
			}
			t.Logf("NAMESPACE_CLI platform=%s version=%s binary=%t verified", runtime.GOOS, version, os.Getenv("NFS_VIEWER_TEST_BINARY") != "")
		})
	}
}
