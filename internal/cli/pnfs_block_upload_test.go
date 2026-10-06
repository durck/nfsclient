package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
	"nfs-viewer/internal/testiscsi"
)

func TestBlockNewUpload(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli", "empty", "empty-cli", "collision", "create-denied", "create-truncated", "create-close-error", "initial-identity", "identity", "eof-identity", "cwd", "source-change", "source-alias", "missing-volume", "no-approval", "commit-error", "commit-size", "return-failure", "cancel"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runBlockUploadFlow(t, minor, mode, false) })
		}
	}
}

func TestBlockGrowthUpload(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli", "no-extend", "initial-identity", "identity", "cwd", "source-change", "gap-source-change", "commit-error", "commit-size", "return-failure", "cancel"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) { runBlockUploadFlow(t, minor, mode, true) })
		}
	}
}

func runBlockUploadFlow(t *testing.T, minor uint32, mode string, growth bool) {
	t.Helper()
	secure := strings.HasPrefix(mode, "secure-")
	mode = strings.TrimPrefix(mode, "secure-")
	security, storageOptions, profile := secureStorageFixture(t, secure)
	journaled := strings.HasPrefix(mode, "journal-")
	mode = strings.TrimPrefix(mode, "journal-")
	transport := strings.HasPrefix(mode, "iscsi-")
	mode = strings.TrimPrefix(mode, "iscsi-")
	dir := t.TempDir()
	path := filepath.Join(dir, "volume")
	source := filepath.Join(dir, "patch")
	image := make([]byte, 16384)
	for i := range image {
		image[i] = byte(i*13 + 5)
	}
	patch := bytes.Repeat([]byte("new-file!"), 114)[:1025]
	if strings.HasPrefix(mode, "empty") {
		patch = nil
	}
	for name, data := range map[string][]byte{path: image, source: patch} {
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := bytes.Clone(image)
	p := &blockCLIPeer{minor: minor, mode: mode, write: true, upload: !growth, growth: growth, signature: bytes.Clone(image[:8]), length: uint64(len(patch))}
	oldSize, offset := uint64(0), uint64(0)
	if growth {
		oldSize = 700
		offset = 2701
		p.size.Store(oldSize)
	}
	end := offset + uint64(len(patch))
	var storage *testiscsi.Target
	if transport {
		base := uint64(4096)
		if growth {
			base = 8192
		}
		storageOptions.InvalidStart = base
		storageOptions.InvalidEnd = base + (end+511)/512*512
		storage = testiscsi.Start(t, path, storageOptions)
	}
	p.commitCheck = func(logical uint64) error {
		if storage != nil {
			events := storage.Events()
			if len(events) == 0 || events[len(events)-1] != 0x91 || bytes.Count(events, []byte{0x91}) != int(p.committed.Load()) {
				return errors.New("upload metadata before SCSI cache sync")
			}
		}
		block := make([]byte, 512)
		for i := range block {
			pos := logical + uint64(i)
			if pos < oldSize {
				block[i] = image[1024+pos]
			}
			if pos >= offset && pos < end {
				block[i] = patch[pos-offset]
			}
		}
		destination := uint64(4096)
		if growth {
			destination = 8192
		}
		copy(want[destination+logical:destination+logical+512], block)
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, want) {
			return fmt.Errorf("gap/new-file bytes corrupted: %v", err)
		}
		if mode == "gap-source-change" && logical == 512 {
			if err := os.Truncate(source, 5); err != nil {
				return err
			}
		}
		return nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.serve(listener) }()
	t.Cleanup(func() {
		listener.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	options := nfs.PNFSOptions{Layout: "block", BlockWrite: mode != "no-approval", BlockVolumes: []string{path}, Extend: growth && mode != "no-extend"}
	if journaled {
		options.BlockJournal = filepath.Join(dir, "journal")
	}
	if storage != nil {
		options.BlockVolumes = nil
		options.BlockTargets = []string{storage.URL()}
		options.BlockInitiator = testiscsi.Initiator
		if secure {
			options.BlockSecurity = storagePolicies(storage.URL(), security)
		}
	}
	if mode == "missing-volume" {
		options.BlockVolumes = []string{path + "-missing"}
	}
	cli := mode == "cli" || mode == "empty-cli"
	if cli {
		command := "putpnfs " + strconv.Quote(source) + " target --layout block --block-write --block-volume " + strconv.Quote(path)
		args := []string{"127.0.0.1", "--nfs-version", fmt.Sprintf("4.%d", minor), "--nfs-port", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), "--pnfs", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--progress", "never", "--color", "never"}
		if growth {
			command = "putrangepnfs " + strconv.Quote(source) + " target 2701 --layout block --block-write --extend --block-volume " + strconv.Quote(path)
			args = append(args, "-c", "lock target write")
		}
		if storage != nil {
			command = strings.Replace(command, "--block-volume "+strconv.Quote(path), "--block-target "+strconv.Quote(storage.URL())+" --block-initiator "+testiscsi.Initiator, 1)
		}
		if secure {
			command += " --block-security " + strconv.Quote(storage.URL()+"="+profile)
		}
		if journaled {
			command += " --block-journal " + strconv.Quote(options.BlockJournal)
		}
		args = append(args, "-c", command)
		if growth {
			args = append(args, "-c", "unlock 1")
		}
		output, err := runKerberosCLI(t, args)
		if err != nil {
			t.Fatal(err, output)
		}
	} else {
		c, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: fmt.Sprintf("4.%d", minor), Transport: "tcp", NFSPort: listener.Addr().(*net.TCPAddr).Port, Timeout: 2 * time.Second, PNFS: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		s := session.New(c, "127.0.0.1", false, false, io.Discard)
		if err := s.Use(ctx, "/"); err != nil {
			t.Fatal(err)
		}
		if growth {
			if _, err := s.Lock(ctx, "target", true); err != nil {
				t.Fatal(err)
			}
		}
		progress := func(n, total uint64) {
			if mode == "initial-identity" && n == 0 {
				s.BaseAuth.UID++
			}
			if n == 0 {
				return
			}
			switch mode {
			case "identity":
				s.BaseAuth.GID++
			case "eof-identity":
				if n == total {
					s.BaseAuth.GID++
				}
			case "cwd":
				s.CWD = "/changed"
			case "source-change":
				if err := os.Truncate(source, 5); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
		}
		local := source
		if mode == "source-alias" {
			local = path
		}
		var n int64
		if growth {
			n, err = s.PutPNFSRange(ctx, local, "target", offset, options, progress)
		} else {
			n, err = s.PutPNFS(ctx, local, "target", options, progress)
		}
		if mode == "api" || mode == "empty" {
			if err != nil || n != int64(len(patch)) {
				t.Fatal(n, err)
			}
		} else if err == nil {
			t.Fatal("unsafe upload succeeded", mode, n)
		}
		if mode == "collision" && !errors.Is(err, session.ErrDestinationExists) {
			t.Fatal("guarded collision lost", err)
		}
		if (mode == "api" || mode == "empty") && !growth && (len(c.Locks()) != 0 || len(s.LockPaths) != 0) {
			t.Fatal("temporary upload lock leaked")
		}
	}
	actual, err := os.ReadFile(path)
	if journaled {
		info, e := nfs.InspectBlockJournal(options.BlockJournal)
		if e != nil {
			t.Fatal(e)
		}
		phase := "completed"
		if len(patch) == 0 {
			phase = ""
		} else if mode == "commit-error" {
			phase = "commit-issued"
		}
		if info.Phase != phase {
			t.Fatal("upload journal phase", info)
		}
		if phase == "completed" && info.Progress != uint64(len(patch)) {
			t.Fatal("upload journal progress", info)
		}
	}
	if err != nil || !bytes.Equal(actual, want) {
		t.Fatal("physical image changed outside initialized blocks", err)
	}
	if mode == "gap-source-change" && (p.committed.Load() != 1 || p.size.Load() != 1024) {
		t.Fatal("source guard did not stop gap initialization", p.committed.Load(), p.size.Load())
	}
	if mode == "commit-error" || mode == "commit-size" {
		if p.committed.Load() != 1 || p.returned.Load() != 0 {
			t.Fatal("unknown mutation replay/return", p.committed.Load(), p.returned.Load())
		}
	}
	if !growth && (mode == "initial-identity" || mode == "source-alias" || mode == "missing-volume" || mode == "no-approval") && p.created.Load() != 0 {
		t.Fatal("invalid profile reached CREATE", p.created.Load())
	}
	if (mode == "api" || mode == "cli" || strings.HasPrefix(mode, "empty")) && p.size.Load() != end {
		t.Fatal("final destination size", p.size.Load(), end)
	}
	if strings.HasPrefix(mode, "empty") && (p.layouts.Load() != 0 || p.committed.Load() != 0) {
		t.Fatal("empty upload wrote data")
	}
	t.Logf("BLOCK_UPLOAD_FLOW transport=%t platform=%s minor=%d mode=%s growth=%t size=%d commits=%d binary=%t verified", transport, runtime.GOOS, minor, mode, growth, p.size.Load(), p.committed.Load(), os.Getenv("NFS_VIEWER_TEST_BINARY") != "")
}
