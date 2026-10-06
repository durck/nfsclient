package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestLockTestCommandRefusals(t *testing.T) {
	sh, root, _ := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"locktest", "locktest file", "locktest file bad", "locktest file write 0", "locktest file write 0 0", "locktest file read -1 eof", "locktest . read", "locktest missing write"} {
		if _, err := sh.Execute(context.Background(), line); err == nil {
			t.Fatalf("accepted %s", line)
		}
	}
	cmd := NewCommand(strings.NewReader(""), io.Discard, io.Discard)
	cmd.SetArgs([]string{"127.0.0.1", "--nlm-port", "65536"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid nlm port") {
		t.Fatal("bad NLM port", err)
	}
}

func TestNLMFreeBSD(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NLM_FREEBSD") != "1" {
		t.Skip("requires the independent FreeBSD native-lock fixture")
	}
	host, export := os.Getenv("NFS_VIEWER_NLM_HOST"), os.Getenv("NFS_VIEWER_NLM_EXPORT")
	if host == "" || export == "" {
		t.Fatal("NLM host and export must be explicit")
	}
	port := 0
	if raw := os.Getenv("NFS_VIEWER_NLM_PORT"); raw != "" {
		var err error
		port, err = strconv.Atoi(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	released := os.Getenv("NFS_VIEWER_NLM_RELEASED") == "1"
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(version+"/"+transport, func(t *testing.T) {
				ctx := context.Background()
				cfg := nfs.Config{Host: host, Version: version, Transport: transport, PortmapPort: 111, NLMPort: port, Timeout: 3 * time.Second, Auth: nfs.Auth{UID: 20001, GID: 20001, Groups: []uint32{20003}}}
				client, err := nfs.Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				s := session.New(client, host, true, false, io.Discard)
				if err := s.Use(ctx, export); err != nil {
					t.Fatal(err)
				}
				auth := client.Auth
				auto := s.AutoUID
				for _, tc := range []struct {
					name                       string
					write                      bool
					offset, length             uint64
					conflict                   bool
					holderWrite                bool
					holderOffset, holderLength uint64
				}{
					{"free", true, 0, nfs.LockToEOF, false, false, 0, 0},
					{"locked-write", true, 0, nfs.LockToEOF, true, true, 8, 8},
					{"locked-write", false, 8, 1, true, true, 8, 8},
					{"locked-write", true, 0, 8, false, false, 0, 0},
					{"locked-write", true, 16, nfs.LockToEOF, false, false, 0, 0},
					{"locked-read", false, 16, nfs.LockToEOF, false, false, 0, 0},
					{"locked-read", true, 16, 1, true, false, 16, nfs.LockToEOF},
				} {
					got, err := s.TestLock(ctx, tc.name, tc.write, tc.offset, tc.length)
					if err != nil {
						t.Fatalf("%+v: %v", tc, err)
					}
					if (got != nil) != (tc.conflict && !released) {
						t.Fatalf("%+v: %+v", tc, got)
					}
					if got != nil && (got.Write != tc.holderWrite || got.Offset != tc.holderOffset || got.Length != tc.holderLength || got.SVID <= 0) {
						t.Fatalf("wrong native holder: %+v", got)
					}
				}
				if version == "3" {
					got, err := s.TestLock(ctx, "locked-high", true, (1<<33)+7, 11)
					if err != nil || (got != nil) == released {
						t.Fatalf("64-bit lock: %+v %v", got, err)
					}
					if got != nil && (got.Offset != (1<<33)+7 || got.Length != 11) {
						t.Fatalf("truncated range: %+v", got)
					}
				}
				if len(client.Locks()) != 0 || s.AutoUID != auto || !reflect.DeepEqual(auth, client.Auth) {
					t.Fatal("inspection changed client state or identity")
				}
				for _, name := range []string{".", "link", "missing"} {
					if _, err := s.TestLock(ctx, name, true, 0, nfs.LockToEOF); err == nil {
						t.Fatalf("accepted %s", name)
					}
				}
				var out bytes.Buffer
				sh := &Shell{Session: s, Out: &out, Err: io.Discard}
				if _, err := sh.Execute(ctx, "locktest locked-write write"); err != nil {
					t.Fatal(err)
				}
				want := "Conflict: write lock, offset=8 length=8"
				if released {
					want = "No conflict reported"
				}
				if !strings.Contains(out.String(), want) || !strings.Contains(out.String(), "no lock acquired") {
					t.Fatal(out.String())
				}
				args := []string{host, "--nfs-version", version, "--transport", transport, "--nlm-port", fmt.Sprint(port), "--export", export, "--uid", "20001", "--gid", "20001", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--color", "never", "-c", "locktest locked-write write", "-c", "locks"}
				stdout, err := runKerberosCLI(t, args)
				if err != nil || !strings.Contains(stdout, want) || !strings.Contains(stdout, "No file locks.") {
					t.Fatalf("CLI: %v\n%s", err, stdout)
				}
				t.Logf("native POSIX conflicts verified: version=%s transport=%s explicit_port=%d released=%t", version, transport, port, released)
			})
		}
	}
}

func TestNLMFreeBSDUnavailable(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NLM_UNAVAILABLE") != "1" {
		t.Skip("requires fixture lockd stopped while NFS remains running")
	}
	host, export := os.Getenv("NFS_VIEWER_NLM_HOST"), os.Getenv("NFS_VIEWER_NLM_EXPORT")
	if host == "" || export == "" {
		t.Fatal("NLM host and export must be explicit")
	}
	for _, version := range []string{"2", "3"} {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(version+"/"+transport, func(t *testing.T) {
				ctx := context.Background()
				c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: version, Transport: transport, PortmapPort: 111, Timeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				s := session.New(c, host, false, false, io.Discard)
				if err := s.Use(ctx, export); err != nil {
					t.Fatal(err)
				}
				if conflict, err := s.TestLock(ctx, "free", true, 0, nfs.LockToEOF); err == nil || conflict != nil {
					t.Fatal("unavailable NLM reported success", conflict, err)
				}
				if _, err := c.GetAttr(ctx, s.Root.Handle); err != nil {
					t.Fatal("inspection failure damaged NFS connection", err)
				}
				for _, port := range []string{"0", "20021"} {
					out, err := runKerberosCLI(t, []string{host, "--nfs-version", version, "--transport", transport, "--nlm-port", port, "--export", export, "--timeout", "1s", "--auto-uid=false", "--auto-escape=false", "--no-banner", "--color", "never", "-c", "locktest free write"})
					if err == nil || strings.Contains(out, "No conflict reported") {
						t.Fatalf("unavailable NLM CLI: %v %s", err, out)
					}
				}
			})
		}
	}
}
