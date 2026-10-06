package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func unfsCLIConfig(t *testing.T, transport string) nfs.Config {
	t.Helper()
	if os.Getenv("NFS_VIEWER_UNFS") != "1" {
		t.Skip("requires disposable tests/unfs fixture")
	}
	port := func(key string) int {
		t.Helper()
		n, err := strconv.Atoi(os.Getenv("NFS_VIEWER_UNFS_" + key))
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid UNFS fixture port %s", key)
		}
		return n
	}
	return nfs.Config{Host: "127.0.0.1", Version: "3", Transport: transport, NFSPort: port("PORT"), MountPort: port("MOUNT_PORT"), Timeout: 3 * time.Second, Auth: nfs.Auth{UID: 20001, GID: 20001, Groups: []uint32{20003}}}
}

func TestUNFSStagedReplacement(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			cfg := unfsCLIConfig(t, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client, err := nfs.Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			s := session.New(client, cfg.Host, false, false, nil)
			if err := s.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("staged-%d", time.Now().UnixNano())
			if err := s.Mkdir(ctx, name); err != nil {
				t.Fatal(err)
			}
			if err := s.CD(ctx, name); err != nil {
				t.Fatal(err)
			}
			src := filepath.Join(t.TempDir(), "source")
			old := bytes.Repeat([]byte("original"), 1000)
			if err := os.WriteFile(src, old, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, src, "file"); err != nil {
				t.Fatal(err)
			}
			file, _, err := s.Resolve(ctx, "file", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Chmod(ctx, file.Handle, 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(src, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, src, "file"); !errors.Is(err, session.ErrDestinationExists) {
				t.Fatalf("collision: %v", err)
			}
			kernelLegacyReplacementRefusal(t, ctx, s, src, "file")
			var out bytes.Buffer
			if _, err := s.Cat(ctx, "file", &out); err != nil || !bytes.Equal(out.Bytes(), old) {
				t.Fatalf("refusal changed original: %v", err)
			}
			entries, err := s.LS(ctx, ".")
			if err != nil || len(entries) != 1 || entries[0].Name != "file" {
				t.Fatalf("refusal left staging: %+v %v", entries, err)
			}
			kernelNewDestinationOverwriteIntent(t, ctx, s, src, "new-file")
			out.Reset()
			if _, err := s.Cat(ctx, "new-file", &out); err != nil || out.String() != "replacement" {
				t.Fatalf("new-name upload: %v", err)
			}
			entries, err = s.LS(ctx, ".")
			if err != nil || len(entries) != 2 || entries[0].Name != "file" || entries[0].Attr.Mode&0777 != 0640 {
				t.Fatalf("refusal/new-name namespace: %+v %v", entries, err)
			}
		})
	}
}

// NFS_VIEWER_TEST_BINARY exercises the release executable as well.
func TestUNFSCLI(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, version := range []string{"3", "auto"} {
			t.Run(transport+"/"+version, func(t *testing.T) {
				cfg := unfsCLIConfig(t, transport)
				base := []string{"127.0.0.1", "--nfs-version", version, "--transport", transport, "--nfs-port", strconv.Itoa(cfg.NFSPort), "--mount-port", strconv.Itoa(cfg.MountPort), "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--groups", "20003", "--no-banner", "--color", "never", "--progress", "never", "--timeout", "3s"}
				run := func(args []string, commands ...string) (string, error) {
					t.Helper()
					a := append([]string(nil), args...)
					for _, command := range commands {
						a = append(a, "-c", command)
					}
					return runKerberosCLI(t, a)
				}
				dir := t.TempDir()
				src, dst, empty, emptyDest := filepath.Join(dir, "source"), filepath.Join(dir, "download"), filepath.Join(dir, "empty"), filepath.Join(dir, "empty-download")
				payload := bytes.Repeat([]byte{0, 255, 27, 'u', 'n', 'f', 's'}, 14000)
				if err := os.WriteFile(src, payload, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(empty, nil, 0600); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("cli-%s-%d", transport, time.Now().UnixNano())
				out, err := run(base, "ls wide", "cat link.txt", "mkdir "+name, "put "+strconv.Quote(src)+" "+name+"/file", "get "+name+"/file "+strconv.Quote(dst), "put "+strconv.Quote(empty)+" "+name+"/empty", "get "+name+"/empty "+strconv.Quote(emptyDest), "id")
				if err != nil || !strings.Contains(out, "300 entries") || !strings.Contains(out, "UNFS fixture") || !strings.Contains(out, "NFSv3 / "+strings.ToUpper(transport)) {
					t.Fatalf("CLI round trip: %v (output tail) %s", err, out[max(0, len(out)-3000):])
				}
				got, err := os.ReadFile(dst)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("download differs: %v", err)
				}
				got, err = os.ReadFile(emptyDest)
				if err != nil || len(got) != 0 {
					t.Fatalf("empty download: %v", err)
				}
				out, err = run(base, "put "+strconv.Quote(src)+" "+name+"/file")
				if err == nil || !strings.Contains(out+err.Error(), "destination exists") {
					t.Fatalf("CLI collision: %v %s", err, out)
				}
				out, err = run(base, "chmod 600 "+name+"/file")
				if err != nil {
					t.Fatalf("owner chmod: %v %s", err, out)
				}
				bob := append(append([]string(nil), base...), "--uid", "20002", "--gid", "20002", "--groups", "")
				deniedDir := t.TempDir()
				out, err = run(bob, "get "+name+"/file "+strconv.Quote(filepath.Join(deniedDir, "denied")))
				if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
					t.Fatalf("CLI denied read: %v %s", err, out)
				}
				entries, err := os.ReadDir(deniedDir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("denied download left files: %v %v", entries, err)
				}
				out, err = run(bob, "put "+strconv.Quote(src)+" "+name+"/forbidden")
				if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
					t.Fatalf("CLI denied create: %v %s", err, out)
				}
				out, err = run(base, "ls "+name)
				if err != nil || !strings.Contains(out, "2 entries") {
					t.Fatalf("denied upload changed namespace: %v %s", err, out)
				}
				if runtime.GOOS == "linux" && os.Getenv("NFS_VIEWER_UNFS_RESERVED") == "1" {
					secure := append(append([]string(nil), base...), "--reserved-port", "--export", "/secure")
					if out, err := run(secure, "ls"); err != nil {
						t.Fatalf("reserved CLI MOUNT: %v %s", err, out)
					}
				}
			})
		}
	}
}
