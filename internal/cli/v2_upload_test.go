package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
	"nfsclient/internal/testutil/nfsv2"
)

func v2Session(t *testing.T, server *nfsv2.Server) *session.Session {
	t.Helper()
	c, err := nfs.Connect(context.Background(), nfs.Config{Host: "127.0.0.1", Version: "2", Transport: server.Transport, NFSPort: server.Port, MountPort: server.Port, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	s := session.New(c, "127.0.0.1", false, false, nil)
	if err := s.Use(context.Background(), "/"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestV2UploadRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 4096, 8193, 32771} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			server := nfsv2.Start(t, nfsv2.Options{MkdirCollisions: 1})
			s := v2Session(t, server)
			payload := bytes.Repeat([]byte{0, 255, 27, 13, 10, 1, 42}, (size+6)/7)[:size]
			local := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			var progress []uint64
			written, err := s.PutWithOptions(context.Background(), local, "dest", session.TransferOptions{Progress: func(done, total uint64) {
				if total != uint64(size) {
					t.Errorf("total %d", total)
				}
				progress = append(progress, done)
			}})
			if err != nil || written != int64(size) {
				t.Fatalf("put: %d %v", written, err)
			}
			data, mode, ok := server.File("dest")
			if !ok || !bytes.Equal(data, payload) || mode != 0644 || !slices.Equal(server.Names(), []string{"dest"}) {
				t.Fatalf("published: %q %o %v %v", data, mode, ok, server.Names())
			}
			if progress[0] != 0 || progress[len(progress)-1] != uint64(size) || !slices.IsSorted(progress) {
				t.Fatalf("progress %v", progress)
			}
			if n, err := s.Get(context.Background(), "dest", local+".get"); err != nil || n != written {
				t.Fatalf("get: %d %v", n, err)
			}
			got, err := os.ReadFile(local + ".get")
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("round trip: %v", err)
			}
			if _, err := s.Put(context.Background(), local, "dest"); !errors.Is(err, session.ErrDestinationExists) {
				t.Fatalf("collision: %v", err)
			}
			server.Seed("dest", []byte("original"), 0640)
			if n, err := s.PutWithOptions(context.Background(), local, "dest", session.TransferOptions{Overwrite: true}); n != 0 || !errors.Is(err, nfs.ErrLegacyReplacementUnsupported) {
				t.Fatalf("replacement must refuse before payload: %d %v", n, err)
			}
			data, mode, _ = server.File("dest")
			if string(data) != "original" || mode != 0640 || len(server.Names()) != 1 {
				t.Fatal("refusal changed bytes/mode or leaked staging")
			}
		})
	}
}

func TestV2UploadFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		options   nfsv2.Options
		overwrite bool
		want      string
		published bool
		leftovers bool
	}{
		{"competing destination", nfsv2.Options{RaceName: "dest"}, false, "destination exists", false, false},
		{"write denied", nfsv2.Options{FailProcedure: 8}, false, "destination unchanged", false, false},
		{"link denied", nfsv2.Options{FailProcedure: 12}, false, "publication rejected", false, false},
		{"missing overwrite link denied", nfsv2.Options{FailProcedure: 12}, true, "publication rejected", false, false},
		{"lost link reply", nfsv2.Options{DropProcedure: 12}, false, "outcome unknown", true, true},
		{"missing overwrite lost link reply", nfsv2.Options{DropProcedure: 12}, true, "outcome unknown", true, true},
		{"cleanup denied", nfsv2.Options{FailProcedure: 15}, false, "published successfully", true, true},
		{"staging collisions", nfsv2.Options{MkdirCollisions: 4}, false, "four attempts", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := nfsv2.Start(t, tc.options)
			s := v2Session(t, server)
			local := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(local, []byte("new data"), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := s.PutWithOptions(context.Background(), local, "dest", session.TransferOptions{Overwrite: tc.overwrite})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
			data, _, exists := server.File("dest")
			want := ""
			if tc.options.RaceName != "" {
				want = "competing writer"
			}
			if tc.published {
				want = "new data"
			}
			if string(data) != want || exists != (want != "") {
				t.Fatalf("destination %q, want %q (exists %v)", data, want, exists)
			}
			var leftovers bool
			for _, name := range server.Names() {
				if strings.HasPrefix(name, ".nfs-upload-") {
					leftovers = true
				}
			}
			if leftovers != tc.leftovers {
				t.Fatalf("staging: %v", server.Names())
			}
			if tc.options.DropProcedure != 0 {
				count := 0
				for _, p := range server.Events() {
					if p == tc.options.DropProcedure {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("uncertain mutation retried %d times", count)
				}
			}
		})
	}
}

type failedV2Reader struct{}

func (failedV2Reader) Read(p []byte) (int, error) { copy(p, "partial"); return 7, io.ErrUnexpectedEOF }

func TestV2UploadSizeAndReaderFailures(t *testing.T) {
	server := nfsv2.Start(t, nfsv2.Options{})
	s := v2Session(t, server)
	for _, size := range []int64{-1, 1 << 31, 1 << 32} {
		before := len(server.Events())
		if _, err := s.Client.UploadV2(context.Background(), s.Root.Handle, "dest", 0644, strings.NewReader(""), size, false, nil); err == nil {
			t.Fatal("oversized source accepted")
		}
		if len(server.Events()) != before {
			t.Fatal("size rejection performed network requests")
		}
	}
	for _, tc := range []struct {
		reader io.Reader
		size   int64
	}{{strings.NewReader("short"), 10}, {strings.NewReader("longer"), 2}, {failedV2Reader{}, 7}, {strings.NewReader(""), 1<<31 - 1}} {
		if _, err := s.Client.UploadV2(context.Background(), s.Root.Handle, "dest", 0644, tc.reader, tc.size, false, nil); err == nil {
			t.Fatal("changed/failed source accepted")
		}
		if len(server.Names()) != 0 {
			t.Fatalf("failed source published/leaked: %v", server.Names())
		}
	}
}

// Optional black-box check of each rebuilt OS binary against the same peer.
func TestV2UploadBinary(t *testing.T) {
	binary := os.Getenv("NFS_VIEWER_TEST_BINARY")
	if binary == "" {
		t.Skip("set NFS_VIEWER_TEST_BINARY to a rebuilt executable")
	}
	transport := os.Getenv("NFS_VIEWER_TEST_TRANSPORT")
	if transport == "" {
		transport = "tcp"
	}
	server := nfsv2.Start(t, nfsv2.Options{UDP: transport == "udp"})
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("binary\x00\xff\n"), 1400)
	if err := os.WriteFile(filepath.Join(dir, "source"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "127.0.0.1", "--nfs-version", "2", "--transport", transport, "--nfs-port", fmt.Sprint(server.Port), "--mount-port", fmt.Sprint(server.Port), "--export", "/", "--no-banner", "--color", "never", "-c", "put source remote", "-c", "get remote downloaded")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("binary: %v\n%s", err, output)
	}
	got, err := os.ReadFile(filepath.Join(dir, "downloaded"))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("binary round trip: %v", err)
	}
	if !slices.Equal(server.Names(), []string{"remote"}) {
		t.Fatal(server.Names())
	}
}

func TestV2UDPRoundTrip(t *testing.T) {
	server := nfsv2.Start(t, nfsv2.Options{UDP: true})
	s := v2Session(t, server)
	if s.Client.Transport() != "udp" || s.Client.ReadSize > 4096 || s.Client.WriteSize > 4096 {
		t.Fatal("wrong UDP limits")
	}
	local := filepath.Join(t.TempDir(), "source")
	data := bytes.Repeat([]byte{0, 255, 27, 1}, 4097)
	if err := os.WriteFile(local, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(context.Background(), local, "remote"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), "remote", local+".get"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(local + ".get")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip %v", err)
	}
	var out bytes.Buffer
	sh := &Shell{Session: s, Out: &out, Err: &out}
	if _, err := sh.Execute(context.Background(), "id"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "NFSv2 / UDP") {
		t.Fatal(out.String())
	}
}

func TestV2UDPLostPublication(t *testing.T) {
	server := nfsv2.Start(t, nfsv2.Options{UDP: true, DropProcedure: 12})
	s := v2Session(t, server)
	local := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(local, []byte("complete payload"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Put(context.Background(), local, "remote")
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("missing uncertainty: %v", err)
	}
	count := 0
	for _, proc := range server.Events() {
		if proc == 12 {
			count++
		}
	}
	got, _, ok := server.File("remote")
	if count != 1 || !ok || string(got) != "complete payload" || !slices.Equal(server.Names(), []string{"remote"}) {
		t.Fatalf("lost publication: count=%d data=%q names=%v", count, got, server.Names())
	}
}
