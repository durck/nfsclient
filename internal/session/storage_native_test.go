package session

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
)

// TestNativeStorageRoots targets only the explicitly selected disposable
// tests/storage guest. The guest's native stat/mount evidence is a separate
// oracle; these checks exercise public mounting, discovery and transfer APIs.
func TestNativeStorageRoots(t *testing.T) {
	portText := os.Getenv("NFS_VIEWER_STORAGE_PORT")
	if portText == "" {
		t.Skip("set explicit disposable storage fixture ports")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		t.Fatal("invalid storage fixture port")
	}
	mountPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_STORAGE_MOUNT_PORT"))
	if err != nil || mountPort < 1 || mountPort > 65535 {
		t.Fatal("invalid storage fixture mount port")
	}
	host := os.Getenv("NFS_VIEWER_STORAGE_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	for _, fs := range []string{"ext4", "xfs", "btrfs"} {
		for _, policy := range []string{"open", "restricted"} {
			t.Run(fs+"/"+policy, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: "3", Transport: "tcp", Security: "sys", NFSPort: port, MountPort: mountPort, Timeout: 5 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				s := New(c, host, false, false, nil)
				if err := s.Use(ctx, "/storage/"+fs+"-"+policy+"/export"); err != nil {
					t.Fatal(err)
				}
				original := cloneRoot(s.Root)
				t.Logf("export=%s handle=%x", RootObjectID(original), original.Handle)
				inside, _, err := s.Resolve(ctx, "/inside-marker", true)
				if err != nil {
					t.Fatal(err)
				}
				var contents bytes.Buffer
				if _, err := c.ReadTo(ctx, inside.Handle, &contents); err != nil || contents.String() != fs+"-"+policy+"-export\n" {
					t.Fatalf("export data: %q %v", contents.String(), err)
				}
				found, err := s.Escape(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("discovered=%t attempts=%d selected=%s", found, s.DiscoveryAttempts, RootObjectID(s.Root))
				// Fresh ext4/XFS roots accept canonical zero-generation
				// candidates. This Btrfs profile rejects the bounded probes;
				// generation guessing is not part of this discovery contract.
				wantFound := fs != "btrfs" && policy == "open"
				if found != wantFound {
					t.Fatalf("unexpected discovery result: %t", found)
				}
				if !wantFound {
					if !bytes.Equal(s.Root.Handle, original.Handle) || s.Escaped || s.DiscoveredRoot != nil {
						t.Fatal("refused candidate changed navigation")
					}
					if _, _, err := s.Resolve(ctx, "/root-marker", true); err == nil {
						t.Fatal("outside marker visible through restricted export")
					}
				} else {
					wantInode := uint64(2)
					if fs == "xfs" {
						wantInode = 128
					}
					if fs == "btrfs" {
						wantInode = 256
					}
					if s.Root.Attr.FileID != wantInode {
						t.Fatalf("candidate is not native root inode: %d", s.Root.Attr.FileID)
					}
					marker, _, err := s.Resolve(ctx, "/root-marker", true)
					if err != nil {
						t.Fatal(err)
					}
					contents.Reset()
					if _, err := c.ReadTo(ctx, marker.Handle, &contents); err != nil || contents.String() != fs+"-"+policy+"-native-root\n" {
						t.Fatalf("native root marker: %q %v", contents.String(), err)
					}
					if err := s.SelectRoot(ctx, false); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(s.Root.Handle, original.Handle) {
						t.Fatal("root reset did not restore export")
					}
				}
				// Publication occurs only inside the selected export on each FS.
				payload := bytes.Repeat([]byte("native-"+fs+"-"+policy+"\x00"), 257)
				local := filepath.Join(t.TempDir(), "upload")
				if err := os.WriteFile(local, payload, 0600); err != nil {
					t.Fatal(err)
				}
				remote := fmt.Sprintf("/%s-published-%d", runtime.GOOS, time.Now().UnixNano())
				if n, err := s.Put(ctx, local, remote); err != nil || n != int64(len(payload)) {
					t.Fatalf("publish %d: %v", n, err)
				}
				out := filepath.Join(t.TempDir(), "download")
				if n, err := s.Get(ctx, remote, out); err != nil || n != int64(len(payload)) {
					t.Fatalf("download %d: %v", n, err)
				}
				got, err := os.ReadFile(out)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("published bytes differ", err)
				}
			})
		}
	}
}

// The destination roots are freshly formatted guest FAT32/exFAT filesystems,
// not directories that merely have those names on the host filesystem.
func TestNativeLocalPublication(t *testing.T) {
	root := os.Getenv("NFS_VIEWER_STORAGE_LOCAL_DIR")
	if root == "" {
		t.Skip("requires formatted disposable guest destination filesystems")
	}
	// Read-only native generation evidence explains why a syntactically
	// valid zero-generation candidate can still be refused by the server.
	for _, fs := range []string{"ext4", "xfs", "btrfs"} {
		out, err := exec.Command("lsattr", "-dv", filepath.Join(root, fs+"-open")).CombinedOutput()
		if err != nil {
			t.Fatalf("native generation oracle: %s %v", out, err)
		}
		t.Logf("native-generation %s", bytes.TrimSpace(out))
	}
	port, err := strconv.Atoi(os.Getenv("NFS_VIEWER_STORAGE_PORT"))
	if err != nil || port < 1 {
		t.Fatal("explicit storage port required")
	}
	mountPort, err := strconv.Atoi(os.Getenv("NFS_VIEWER_STORAGE_MOUNT_PORT"))
	if err != nil || mountPort < 1 {
		t.Fatal("explicit mount port required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: "3", Transport: "tcp", Security: "sys", NFSPort: port, MountPort: mountPort, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := New(c, "127.0.0.1", false, false, nil)
	if err := s.Use(ctx, "/storage/ext4-open/export"); err != nil {
		t.Fatal(err)
	}
	for _, fs := range []string{"fat32", "exfat"} {
		t.Run(fs, func(t *testing.T) {
			dir, err := os.MkdirTemp(filepath.Join(root, fs), "publication-")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "download-published")
			want := []byte("ext4-open-export\n")
			if n, err := s.Get(ctx, "/inside-marker", path); err != nil || n != int64(len(want)) {
				t.Fatalf("new publication: %d %v", n, err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("new publication bytes", err)
			}
			if _, err := s.Get(ctx, "/inside-marker", path); err == nil {
				t.Fatal("existing target silently overwritten")
			}
			old := []byte("existing destination must survive refusal\n")
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(ctx, "/inside-marker", path); err == nil {
				t.Fatal("collision accepted")
			}
			got, err = os.ReadFile(path)
			if err != nil || !bytes.Equal(got, old) {
				t.Fatal("collision damaged target", err)
			}
			if n, err := s.GetWithOptions(ctx, "/inside-marker", path, TransferOptions{Overwrite: true}); err != nil || n != int64(len(want)) {
				t.Fatalf("explicit replacement: %d %v", n, err)
			}
			got, err = os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("replacement bytes", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "download-published" {
				t.Fatal("publication left temporary artifacts", err)
			}
		})
	}
}
