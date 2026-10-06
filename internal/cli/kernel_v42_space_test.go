package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func spaceExpected() []byte {
	b := make([]byte, 393216)
	for i := 0; i < 262144; i++ {
		if i < 65536 || i >= 131072 {
			b[i] = 0x5a
		}
	}
	return b
}

func TestKernelV42Space(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	connect := func(version string) *session.Session {
		c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: version, Timeout: 15 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}})
		if err != nil {
			t.Fatal(err)
		}
		s := session.New(c, host, false, false, nil)
		t.Cleanup(func() { s.Client.Close() })
		if err := s.Use(ctx, "/data"); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, version := range []string{"4.0", "4.1"} {
		s := connect(version)
		if s.Allocate(ctx, "seed", 0, 1) != nfs.ErrRequiresV42 || s.Deallocate(ctx, "seed", 0, 1) != nfs.ErrRequiresV42 {
			t.Fatal("older minor accepted space mutation")
		}
		if _, err := s.Seek(ctx, "seed", 0, false); !errors.Is(err, nfs.ErrRequiresV42) {
			t.Fatal(err)
		}
	}
	s := connect("4.2")
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprint(locked), func(t *testing.T) {
			dir := t.TempDir()
			src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "result")
			if err := os.WriteFile(src, bytes.Repeat([]byte{0x5a}, 262144), 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("space-api-%s-%t-%d", runtime.GOOS, locked, time.Now().UnixNano())
			if _, err := s.Put(ctx, src, name); err != nil {
				t.Fatal(err)
			}
			var id uint64
			if locked {
				var err error
				id, err = s.Lock(ctx, name, true)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Allocate(ctx, name, 262144, 131072); err != nil {
				t.Fatal(err)
			}
			if err := s.Deallocate(ctx, name, 65536, 65536); err != nil {
				t.Fatal(err)
			}
			if err := s.Deallocate(ctx, name, 524288, 65536); err != nil {
				t.Fatal("deallocation past EOF", err)
			}
			for _, query := range []struct {
				offset uint64
				hole   bool
				want   uint64
				eof    bool
			}{{0, true, 65536, false}, {65536, false, 131072, false}, {262144, true, 262144, false}} {
				got, err := s.Seek(ctx, name, query.offset, query.hole)
				if err != nil || got.Offset != query.want || got.EOF != query.eof {
					t.Fatalf("seek %+v: %+v %v", query, got, err)
				}
			}
			// Linux 6.8 returns NXIO for DATA after the final written extent;
			// preserve that server status rather than fabricating an EOF result.
			last, lastErr := s.Seek(ctx, name, 262144, false)
			if !errors.Is(lastErr, nfs.Status(6)) && (lastErr != nil || !last.EOF || last.Offset != 393216) {
				t.Fatal("no later data", last, lastErr)
			}
			if _, err := s.Seek(ctx, name, 393217, false); !errors.Is(err, nfs.Status(6)) {
				t.Fatal("past EOF", err)
			}
			if locked {
				if err := s.Client.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Get(ctx, name, dst); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(dst)
			if err != nil || !bytes.Equal(got, spaceExpected()) {
				t.Fatal("allocated/deallocated content differs", err)
			}
			n, _, err := s.Resolve(ctx, name, false)
			if err != nil || n.Attr.Size != 393216 {
				t.Fatal(n.Attr, err)
			}
			id, err = s.Lock(ctx, name, false)
			if err != nil {
				t.Fatal(err)
			}
			if s.Allocate(ctx, name, 0, 1) == nil || s.Deallocate(ctx, name, 0, 1) == nil {
				t.Fatal("write under read lock accepted")
			}
			if err := s.Client.Unlock(ctx, id); err != nil {
				t.Fatal(err)
			}
			t.Logf("V42_SPACE platform=%s locked=%t size=393216 hole=65536:131072 server_allocated_and_deallocated bytes_verified", runtime.GOOS, locked)
		})
	}
	for _, name := range []string{"link", "."} {
		if s.Allocate(ctx, name, 0, 1) == nil || s.Deallocate(ctx, name, 0, 1) == nil {
			t.Fatal("non-regular file accepted", name)
		}
		if _, err := s.Seek(ctx, name, 0, false); err == nil {
			t.Fatal("non-regular seek accepted", name)
		}
	}
	for _, mutate := range []func(context.Context, string, uint64, uint64) error{s.Allocate, s.Deallocate} {
		if err := mutate(ctx, "readonly", 0, 4096); !errors.Is(err, nfs.Status(13)) {
			t.Fatal("write-denied fixture", err)
		}
	}
}

func TestKernelV42SpaceCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	local := t.TempDir()
	src, dst := filepath.Join(local, "source"), filepath.Join(local, "result")
	if err := os.WriteFile(src, bytes.Repeat([]byte{0x5a}, 262144), 0600); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("space-cli-%s-%d", runtime.GOOS, time.Now().UnixNano())
	args := []string{host, "--nfs-version", "4.2", "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "15s"}
	commands := []string{"put " + strconv.Quote(src) + " " + name, "allocate " + name + " 262144 131072", "deallocate " + name + " 65536 65536", "seek " + name + " 65536 data", "seek " + name + " 0 hole", "get " + name + " " + strconv.Quote(dst)}
	for _, cmd := range commands {
		args = append(args, "-c", cmd)
	}
	out, err := runKerberosCLI(t, args)
	if err != nil {
		t.Fatal(err, out)
	}
	var found []nfs.SeekResult
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "{\"offset\"") {
			var r nfs.SeekResult
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatal(err)
			}
			found = append(found, r)
		}
	}
	if len(found) != 2 || found[0].Offset != 131072 || found[1].Offset != 65536 || found[0].EOF || found[1].EOF {
		t.Fatal("CLI seek result", found, out)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, spaceExpected()) {
		t.Fatal("CLI content differs", err)
	}
	t.Logf("V42_SPACE_CLI platform=%s size=393216 hole=65536:131072 bytes_verified", runtime.GOOS)
}
