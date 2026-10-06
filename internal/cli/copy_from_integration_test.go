package cli

import (
	"bytes"
	"context"
	"fmt"
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
)

func TestServerCopyFrom(t *testing.T) {
	sourceEndpoint, destinationEndpoint := os.Getenv("NFS_VIEWER_COPY_SOURCE"), os.Getenv("NFS_VIEWER_COPY_DESTINATION")
	if sourceEndpoint == "" || destinationEndpoint == "" {
		t.Skip("dedicated two-server COPY fixture not selected")
	}
	options := nfs.CopyFromOptions{Destination: "10.78.0.2:2049", SourceServers: []string{"10.77.1.15:2049"}}
	for _, mode := range []string{"session", "locked", "cli"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			connect := func(endpoint string) *session.Session {
				host, port, err := net.SplitHostPort(endpoint)
				if err != nil {
					t.Fatal(err)
				}
				p, err := strconv.Atoi(port)
				if err != nil {
					t.Fatal(err)
				}
				c, err := nfs.Connect(ctx, nfs.Config{Host: host, NFSPort: p, Version: "4.2", Offload: true, Timeout: 10 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				s := session.New(c, host, false, false, nil)
				if err := s.Use(ctx, "/"); err != nil {
					t.Fatal(err)
				}
				return s
			}
			source, destination := connect(sourceEndpoint), connect(destinationEndpoint)
			dir := t.TempDir()
			src, dst, out := filepath.Join(dir, "src"), filepath.Join(dir, "dst"), filepath.Join(dir, "out")
			if err := os.WriteFile(src, copySource(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, bytes.Repeat([]byte{'D'}, 65536), 0600); err != nil {
				t.Fatal(err)
			}
			name := "copyfrom-" + runtime.GOOS + "-" + mode
			if _, err := source.Put(ctx, src, name+"-src"); err != nil {
				t.Fatal(err)
			}
			if _, err := destination.Put(ctx, dst, name+"-dst"); err != nil {
				t.Fatal(err)
			}
			if mode == "locked" {
				if _, err := source.Lock(ctx, name+"-src", false); err != nil {
					t.Fatal(err)
				}
				if _, err := destination.Lock(ctx, name+"-dst", true); err != nil {
					t.Fatal(err)
				}
			}
			copyRange := func(sourceOffset, destinationOffset, length uint64, o nfs.CopyFromOptions) (uint64, error) {
				if mode != "locked" {
					return destination.CopyFrom(ctx, sourceEndpoint, "/", name+"-src", name+"-dst", sourceOffset, destinationOffset, length, 30*time.Second, o)
				}
				src, _, err := source.Resolve(ctx, name+"-src", true)
				if err != nil {
					return 0, err
				}
				dst, _, err := destination.Resolve(ctx, name+"-dst", true)
				if err != nil {
					return 0, err
				}
				return destination.Client.CopyRangeFrom(ctx, source.Client, src.Handle, dst.Handle, sourceOffset, destinationOffset, length, 30*time.Second, o)
			}
			refused := options
			refused.SourceServers = []string{"192.0.2.99:2049"}
			if n, err := copyRange(0, 0, 8192, refused); n != 0 || err == nil || !strings.Contains(err.Error(), "unapproved source") {
				t.Fatal("source address refusal", n, err)
			}
			var preserved bytes.Buffer
			if _, err := destination.Cat(ctx, name+"-dst", &preserved); err != nil || !bytes.Equal(preserved.Bytes(), bytes.Repeat([]byte{'D'}, 65536)) {
				t.Fatal("refusal changed destination", err)
			}
			if mode == "cli" {
				host, port, _ := net.SplitHostPort(destinationEndpoint)
				args := []string{host, "--nfs-port", port, "--nfs-version", "4.2", "--offload", "--export", "/", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--color", "never", "--progress", "never"}
				for _, span := range []string{"65536 32768 131072", "0 262144 65536"} {
					args = append(args, "-c", fmt.Sprintf("copyfrom %s / %s-src %s-dst %s 30s %s %s", sourceEndpoint, name, name, span, options.Destination, options.SourceServers[0]))
				}
				args = append(args, "-c", "get "+name+"-dst "+strconv.Quote(out))
				if output, err := runKerberosCLI(t, args); err != nil {
					t.Fatal(err, output)
				}
				if b, err := os.ReadFile(out); err != nil || !bytes.Equal(b, copyExpected()) {
					t.Fatal("CLI bytes", err)
				}
			} else {
				if n, err := copyRange(65536, 32768, 131072, options); err != nil || n != 131072 {
					t.Fatal(n, err)
				}
				if n, err := copyRange(0, 262144, 65536, options); err != nil || n != 65536 {
					t.Fatal(n, err)
				}
			}
			var result bytes.Buffer
			if _, err := destination.Cat(ctx, name+"-dst", &result); err != nil || !bytes.Equal(result.Bytes(), copyExpected()) {
				t.Fatal("destination bytes", err)
			}
			for _, s := range []*session.Session{source, destination} {
				for _, lock := range s.Client.Locks() {
					if err := s.Client.Unlock(ctx, lock.ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Logf("COPY_FROM_NATIVE platform=%s mode=%s two_ranges source_allowlist_refusal_preserved", runtime.GOOS, mode)
		})
	}
}
