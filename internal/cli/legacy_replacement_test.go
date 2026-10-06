package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/osfs"
	server "github.com/willscott/go-nfs"
	"github.com/willscott/go-nfs/helpers"
	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
	"nfs-viewer/internal/testutil/nfsv2"
)

func TestLegacyReplacementRefusesBeforeMutation(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			var s *session.Session
			var peer *nfsv2.Server
			var root string
			if version == "2" {
				peer = nfsv2.Start(t, nfsv2.Options{})
				peer.Seed("existing", []byte("original"), 0640)
				s = v2Session(t, peer)
			} else {
				var sh *Shell
				sh, root, _ = testShell(t)
				s = sh.Session
				if err := os.WriteFile(filepath.Join(root, "existing"), []byte("original"), 0640); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			before, _, err := s.Resolve(ctx, "existing", true)
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(source, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			var positive bool
			count, err := s.PutWithOptions(ctx, source, "existing", session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) { positive = positive || done != 0 }})
			if !errors.Is(err, nfs.ErrLegacyReplacementUnsupported) || count != 0 || positive {
				t.Fatalf("unsafe replacement: bytes=%d progress=%t err=%v", count, positive, err)
			}
			after, _, err := s.Resolve(ctx, "existing", true)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("refusal changed object: %v", err)
			}
			var out bytes.Buffer
			if _, err := s.Cat(ctx, "existing", &out); err != nil || out.String() != "original" {
				t.Fatalf("refusal changed bytes: %q %v", out.String(), err)
			}
			entries, err := s.LS(ctx, ".")
			if err != nil || len(entries) != 1 || entries[0].Name != "existing" {
				t.Fatalf("refusal left staging: %v %v", entries, err)
			}
			if peer != nil {
				start := len(peer.Events())
				reader := &observedLegacyReader{}
				count, err := s.Client.UploadV2(ctx, s.Root.Handle, "existing", 0640, reader, 5, true, nil)
				if !errors.Is(err, nfs.ErrLegacyReplacementUnsupported) || count != 0 || reader.read {
					t.Fatalf("direct API bypass: bytes=%d read=%t err=%v", count, reader.read, err)
				}
				for _, proc := range peer.Events()[start:] {
					if proc != 4 {
						t.Fatalf("refusal issued mutating procedure %d", proc)
					}
				}
			}
		})
	}
}

type observedLegacyReader struct{ read bool }

func (r *observedLegacyReader) Read(p []byte) (int, error) {
	r.read = true
	return copy(p, "bytes"), io.EOF
}

func TestV2MissingOverwriteUsesNoReplace(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, direct := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "tcp", true: "udp"}[udp], map[bool]string{false: "session", true: "direct"}[direct]}, "/"), func(t *testing.T) {
				peer := nfsv2.Start(t, nfsv2.Options{UDP: udp, RaceName: "raced"})
				s := v2Session(t, peer)
				var err error
				if direct {
					_, err = s.Client.UploadV2(context.Background(), s.Root.Handle, "raced", 0644, strings.NewReader("new"), 3, true, nil)
				} else {
					source := filepath.Join(t.TempDir(), "source")
					if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
						t.Fatal(err)
					}
					_, err = s.PutWithOptions(context.Background(), source, "raced", session.TransferOptions{Overwrite: true})
				}
				data, _, exists := peer.File("raced")
				if !errors.Is(err, nfs.Status(17)) || !exists || string(data) != "competing writer" || len(peer.Names()) != 1 {
					t.Fatalf("later writer replaced: %q %v %v names=%v", data, exists, err, peer.Names())
				}
				for _, proc := range peer.Events() {
					if proc == 11 {
						t.Fatal("missing destination published through replacement RENAME")
					}
				}
			})
		}
	}
}

// Return the first absent LOOKUP result after a concurrent writer publishes.
// The subsequent server CREATE observes the actual newly existing file.
type legacyRacingFS struct {
	changeFS
	once sync.Once
}

func (f *legacyRacingFS) Lstat(path string) (os.FileInfo, error) {
	info, err := f.changeFS.Lstat(path)
	if filepath.Base(path) == "raced" && os.IsNotExist(err) {
		f.once.Do(func() {
			if e := os.WriteFile(filepath.Join(f.Root(), "raced"), []byte("competing writer"), 0600); e != nil {
				err = e
			}
		})
	}
	return info, err
}

func TestV3MissingOverwriteUsesGuardedCreate(t *testing.T) {
	root := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := helpers.NewCachingHandler(sysHandler{helpers.NewNullAuthHandler(&legacyRacingFS{changeFS: changeFS{osfs.New(root)}})}, 1024)
	done := make(chan error, 1)
	go func() { done <- server.Serve(l, handler) }()
	t.Cleanup(func() { l.Close(); <-done })
	port := l.Addr().(*net.TCPAddr).Port
	c, err := nfs.Connect(context.Background(), nfs.Config{Host: "127.0.0.1", Version: "3", NFSPort: port, MountPort: port, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	s := session.New(c, "127.0.0.1", false, false, nil)
	if err := s.Use(context.Background(), "/"); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	count, err := s.PutWithOptions(context.Background(), source, "raced", session.TransferOptions{Overwrite: true})
	if !errors.Is(err, session.ErrDestinationExists) || count != 0 {
		t.Fatalf("later writer overwritten: %d %v", count, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "raced"))
	entries, listErr := os.ReadDir(root)
	if err != nil || string(data) != "competing writer" || listErr != nil || len(entries) != 1 {
		t.Fatalf("destination/staging changed: %q %v %v", data, err, listErr)
	}
}
