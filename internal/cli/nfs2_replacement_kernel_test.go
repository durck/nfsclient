package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func replacement2Host() string {
	if host := os.Getenv("NFS_VIEWER_REPLACE2_HOST"); host != "" {
		return host
	}
	return "127.0.0.1"
}

func replacement2Session(t *testing.T, transport string) *session.Session {
	t.Helper()
	if os.Getenv("NFS_VIEWER_REPLACE2") != "1" {
		t.Skip("requires independent NFSv2/NFSACL kernel fixture")
	}
	port, mount := 19449, 19448
	if os.Getenv("NFS_VIEWER_REPLACE2_NATIVE") == "1" {
		port, mount = 2049, 20048
	}
	c, err := nfs.Connect(context.Background(), nfs.Config{Host: replacement2Host(), Version: "2", Transport: transport, NFSPort: port, MountPort: mount, Timeout: 10 * time.Second, Auth: nfs.Auth{UID: 20001, GID: 20001}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	s := session.New(c, replacement2Host(), false, false, io.Discard)
	if err := s.Use(context.Background(), "/data"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNFS2ReplacementKernel(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			s := replacement2Session(t, transport)
			ctx := context.Background()
			payload := append(copySource(), []byte("v2-replacement-end")...)
			full := filepath.Join(t.TempDir(), "full")
			if err := os.WriteFile(full, payload, 0600); err != nil {
				t.Fatal(err)
			}
			name := func(kind string) string { return runtime.GOOS + "-" + transport + "-" + kind }
			for _, kind := range []string{"hardlink", "special"} {
				if _, err := s.Replace(ctx, full, name(kind), nil); err == nil {
					t.Fatal("unsafe target accepted", kind)
				}
			}
			changed := false
			_, err := s.Replace(ctx, full, name("local-change"), func(done, total uint64) {
				if done > 0 && !changed {
					changed = true
					if err := os.Chtimes(full, time.Now(), time.Now().Add(time.Hour)); err != nil {
						t.Error(err)
					}
				}
			})
			if !changed || !errors.Is(err, session.ErrUploadSourceChanged) {
				t.Fatal("changed local source accepted", changed, err)
			}
			var old bytes.Buffer
			if _, err := s.Cat(ctx, name("local-change"), &old); err != nil || old.String() != "old-data\n" {
				t.Fatal("destination modified on source change", err, old.String())
			}
			for _, kind := range []string{"api", "empty"} {
				data := payload
				if kind == "empty" {
					data = nil
				}
				local := filepath.Join(t.TempDir(), kind)
				if err := os.WriteFile(local, data, 0600); err != nil {
					t.Fatal(err)
				}
				before, _, err := s.Resolve(ctx, name(kind), false)
				if err != nil {
					t.Fatal(err)
				}
				n, err := s.Replace(ctx, local, name(kind), nil)
				if err != nil || n != int64(len(data)) {
					t.Fatal("replace", kind, n, err)
				}
				after, _, err := s.Resolve(ctx, name(kind), false)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(before.Handle, after.Handle) || before.Attr.UID != after.Attr.UID || before.Attr.GID != after.Attr.GID || before.Attr.Mode != after.Attr.Mode {
					t.Fatal("replacement identity/ownership/mode")
				}
				var got bytes.Buffer
				if _, err := s.Cat(ctx, name(kind), &got); err != nil || !bytes.Equal(got.Bytes(), data) {
					t.Fatal("replacement bytes", err)
				}
				t.Logf("REPLACE2 platform=%s transport=%s file=%s bytes=%d", runtime.GOOS, transport, name(kind), n)
			}
		})
	}
}

func TestNFS2ReplacementKernelCLI(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			s := replacement2Session(t, transport)
			s.Client.Close()
			if os.Getenv("NFS_VIEWER_TEST_BINARY") == "" {
				t.Fatal("standalone binary required")
			}
			payload := append(copySource(), []byte("v2-replacement-end")...)
			dir := t.TempDir()
			local, out := filepath.Join(dir, "full"), filepath.Join(dir, "result")
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("%s-%s-cli", runtime.GOOS, transport)
			port, mount := "19449", "19448"
			if os.Getenv("NFS_VIEWER_REPLACE2_NATIVE") == "1" {
				port, mount = "2049", "20048"
			}
			args := []string{replacement2Host(), "--nfs-version", "2", "--transport", transport, "--nfs-port", port, "--mount-port", mount, "--export", "/data", "--uid", "20001", "--gid", "20001", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never", "-c", "replace " + strconv.Quote(local) + " " + name, "-c", "get " + name + " " + strconv.Quote(out)}
			if output, err := runKerberosCLI(t, args); err != nil {
				t.Fatal(err, output)
			}
			if got, err := os.ReadFile(out); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("CLI bytes", err)
			}
			t.Logf("REPLACE2_CLI platform=%s transport=%s file=%s bytes=%d", runtime.GOOS, transport, name, len(payload))
		})
	}
}
