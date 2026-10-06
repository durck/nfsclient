package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	server "github.com/willscott/go-nfs"
	"github.com/willscott/go-nfs/helpers"
	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

type changeFS struct{ billy.Filesystem }

func (f changeFS) Chmod(p string, m os.FileMode) error {
	return os.Chmod(filepath.Join(f.Root(), p), m)
}
func (f changeFS) Chown(p string, u, g int) error { return os.Chown(filepath.Join(f.Root(), p), u, g) }
func (f changeFS) Lchown(p string, u, g int) error {
	return os.Lchown(filepath.Join(f.Root(), p), u, g)
}
func (f changeFS) Chtimes(p string, a, m time.Time) error {
	return os.Chtimes(filepath.Join(f.Root(), p), a, m)
}

type sysHandler struct{ server.Handler }

func (h sysHandler) Mount(ctx context.Context, conn net.Conn, req server.MountRequest) (server.MountStatus, billy.Filesystem, []server.AuthFlavor) {
	status, fs, _ := h.Handler.Mount(ctx, conn, req)
	return status, fs, []server.AuthFlavor{server.AuthFlavor(1)}
}

func testServer(t *testing.T) (string, int) {
	t.Helper()
	root := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := helpers.NewCachingHandler(sysHandler{helpers.NewNullAuthHandler(changeFS{osfs.New(root)})}, 1024)
	done := make(chan error, 1)
	go func() { done <- server.Serve(l, handler) }()
	t.Cleanup(func() { l.Close(); <-done })
	return root, l.Addr().(*net.TCPAddr).Port
}

func testShell(t *testing.T) (*Shell, string, *bytes.Buffer) {
	t.Helper()
	root, port := testServer(t)
	client, err := nfs.Connect(context.Background(), nfs.Config{Host: "127.0.0.1", MountPort: port, NFSPort: port, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	var out, notices bytes.Buffer
	sess := session.New(client, "127.0.0.1", false, false, &notices)
	if err := sess.Use(context.Background(), "/"); err != nil {
		t.Fatal(err)
	}
	return &Shell{Session: sess, Out: &out, Err: &notices, LocalDir: t.TempDir()}, root, &out
}

func TestFileRoundTrip(t *testing.T) {
	sh, root, out := testShell(t)
	payload := bytes.Repeat([]byte("NFS\x00 round trip\n"), 6000)
	if err := os.WriteFile(filepath.Join(sh.LocalDir, "local source.bin"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{`mkdir "remote dir"`, `cd "remote dir"`, `put "local source.bin" "remote file.bin"`, `ls`, `stat "remote file.bin"`, `chmod 600 "remote file.bin"`, `get "remote file.bin" "downloaded.bin"`} {
		if _, err := sh.Execute(context.Background(), line); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	for _, filename := range []string{filepath.Join(sh.LocalDir, "downloaded.bin"), filepath.Join(root, "remote dir", "remote file.bin")} {
		got, err := os.ReadFile(filename)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("round trip %s: bytes=%d err=%v", filename, len(got), err)
		}
	}
	out.Reset()
	if _, err := sh.Execute(context.Background(), `cat "remote file.bin"`); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatal("cat output differs from binary payload")
	}
	for _, line := range []string{`get "remote file.bin" "downloaded.bin"`, `put "local source.bin" "remote file.bin"`} {
		if _, err := sh.Execute(context.Background(), line); err == nil {
			t.Fatalf("overwrite accepted: %s", line)
		}
	}
	got, err := os.ReadFile(filepath.Join(root, "remote dir", "remote file.bin"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("failed upload changed existing destination")
	}
	if _, err := sh.Execute(context.Background(), `get missing failed.bin`); err == nil {
		t.Fatal("missing remote file accepted")
	}
	if _, err := os.Stat(filepath.Join(sh.LocalDir, "failed.bin")); !os.IsNotExist(err) {
		t.Fatal("failed download was published")
	}
	matches, _ := filepath.Glob(filepath.Join(sh.LocalDir, ".nfs-download-*"))
	if len(matches) != 0 {
		t.Fatal("download temporary files leaked")
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(root, "remote dir", "remote file.bin"))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("chmod: %v %v", st, err)
		}
	}
}

func TestPathRequiresDirectory(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"file/..", "file/.", "file/", "file//"} {
		if _, _, err := sh.Session.Resolve(context.Background(), p, true); err == nil {
			t.Errorf("accepted non-directory traversal %q", p)
		}
	}
}

func TestSymlinkResolution(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a/b", filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("cycle", filepath.Join(root, "cycle")); err != nil {
		t.Fatal(err)
	}
	n, resolved, err := sh.Session.Resolve(context.Background(), "link/..", true)
	if err != nil || resolved != "/a" || n.Attr.Type != 2 {
		t.Fatalf("link/.. = %q %v", resolved, err)
	}
	if _, _, err := sh.Session.Resolve(context.Background(), "cycle", true); err == nil {
		t.Fatal("symlink cycle accepted")
	}
}

func TestBatchFailureAndIdentity(t *testing.T) {
	sh, _, out := testShell(t)
	for _, line := range []string{"uid 123 456 7,8", "id", "auto-uid on", "auto-uid off"} {
		if _, err := sh.Execute(context.Background(), line); err != nil {
			t.Fatal(err)
		}
	}
	if sh.Session.Client.Auth.UID != 123 || sh.Session.Client.Auth.GID != 456 || sh.Session.AutoUID {
		t.Fatal("identity not restored")
	}
	if !strings.Contains(out.String(), "UID 123  /  GID 456") || !strings.Contains(out.String(), "7, 8") {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := sh.RunBatch(context.Background(), strings.NewReader("not-a-command\nhelp\n")); err == nil {
		t.Fatal("batch accepted unknown command")
	}
	if out.Len() != 0 {
		t.Fatal("batch continued after failure")
	}
}

func TestCommandEndToEnd(t *testing.T) {
	root, port := testServer(t)
	payload := []byte("contents without a newline")
	if err := os.WriteFile(filepath.Join(root, "message.txt"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	var out, notices bytes.Buffer
	cmd := NewCommand(strings.NewReader(""), &out, &notices)
	cmd.SetArgs([]string{"127.0.0.1", "--nfs-version", "3", "--mount-port", fmt.Sprint(port), "--nfs-port", fmt.Sprint(port), "--export", "/", "--auto-uid=false", "--auto-escape=false", "-c", "cat message.txt"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatalf("stdout contaminated: %q", out.String())
	}
}

func TestCompletion(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "hello world.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	c := completer{shell: sh, ctx: context.Background()}
	for _, tc := range []struct{ line, suffix string }{{"exi", "t "}, {"cat hel", `lo\ world.txt `}} {
		result, _ := c.Do([]rune(tc.line), len([]rune(tc.line)))
		if len(result) != 1 || string(result[0]) != tc.suffix {
			t.Fatalf("%q => %q", tc.line, result)
		}
	}
}
