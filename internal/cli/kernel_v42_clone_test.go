package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func TestKernelV42Clone(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	if os.Getenv("NFS_VIEWER_REFLINK") != "1" {
		t.Skip("requires isolated Btrfs/XFS export")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: "4.2", Timeout: 15 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := session.New(c, host, false, false, nil)
	if err := s.Use(ctx, "/data"); err != nil {
		t.Fatal(err)
	}
	for _, locked := range []bool{false, true} {
		t.Run(fmt.Sprint(locked), func(t *testing.T) {
			dir := t.TempDir()
			src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
			if err := os.WriteFile(src, copySource(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, bytes.Repeat([]byte{'D'}, 262144), 0600); err != nil {
				t.Fatal(err)
			}
			name := fmt.Sprintf("clone-api-%s-%t-%d", runtime.GOOS, locked, time.Now().UnixNano())
			for _, p := range [][2]string{{src, name + "-src"}, {dst, name + "-dst"}, {dst, name + "-part"}} {
				if _, err := s.Put(ctx, p[0], p[1]); err != nil {
					t.Fatal(err)
				}
			}
			var locks []uint64
			if locked {
				for _, p := range []struct {
					name  string
					write bool
				}{{name + "-src", false}, {name + "-dst", true}, {name + "-part", true}} {
					id, err := s.Lock(ctx, p.name, p.write)
					if err != nil {
						t.Fatal(err)
					}
					locks = append(locks, id)
				}
			}
			for _, r := range []struct {
				dst                          string
				srcOffset, dstOffset, length uint64
			}{{name + "-dst", 0, 0, 262144}, {name + "-part", 65536, 131072, 65536}} {
				if n, err := s.CopyRange(ctx, name+"-src", r.dst, r.srcOffset, r.dstOffset, r.length, true); err != nil || n != r.length {
					t.Fatal("server CLONE", n, err)
				}
			}
			for _, id := range locks {
				if err := c.Unlock(ctx, id); err != nil {
					t.Fatal(err)
				}
			}
			// Modify the source after cloning and prove copy-on-write isolation.
			node, _, err := s.Resolve(ctx, name+"-src", false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.WriteFrom(ctx, node.Handle, bytes.NewReader([]byte("changed"))); err != nil {
				t.Fatal(err)
			}
			partial := bytes.Repeat([]byte{'D'}, 262144)
			copy(partial[131072:196608], copySource()[65536:131072])
			changed := copySource()
			copy(changed, []byte("changed"))
			for _, p := range []struct {
				role string
				want []byte
			}{{"src", changed}, {"dst", copySource()}, {"part", partial}} {
				var b bytes.Buffer
				// Verify CLONE bytes directly. XFS may advance change without
				// mtime/ctime changes during read; guarded download publication
				// conservatively refuses that profile (retained separate evidence).
				if _, err := s.Cat(ctx, name+"-"+p.role, &b); err != nil || !bytes.Equal(b.Bytes(), p.want) {
					t.Fatal("clone COW bytes", p.role, err)
				}
			}
			t.Logf("V42_CLONE platform=%s locked=%t whole_and_range_clone_COW_bytes_verified", runtime.GOOS, locked)
		})
	}
}

func TestKernelV42CloneCLI(t *testing.T) {
	host, ca := kernelTLSFixture(t)
	if os.Getenv("NFS_VIEWER_REFLINK") != "1" {
		t.Skip("requires isolated Btrfs/XFS export")
	}
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	if err := os.WriteFile(src, copySource(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, nil, 0600); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("clone-cli-%s-%d", runtime.GOOS, time.Now().UnixNano())
	args := []string{host, "--nfs-version", "4.2", "--export", "/data", "--auto-uid=false", "--auto-escape=false", "--uid", "25001", "--gid", "25000", "--tls", "--tls-ca", ca, "--no-banner", "--progress", "never", "--color", "never", "--timeout", "15s"}
	for _, cmd := range []string{"put " + strconv.Quote(src) + " " + name + "-src", "put " + strconv.Quote(dst) + " " + name + "-dst", "clonerange " + name + "-src " + name + "-dst 0 0 262144"} {
		args = append(args, "-c", cmd)
	}
	if output, err := runKerberosCLI(t, args); err != nil {
		t.Fatal(err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := nfs.Connect(ctx, nfs.Config{Host: host, Version: "4.2", Timeout: 15 * time.Second, Auth: nfs.Auth{UID: 25001, GID: 25000}, TLS: nfs.TLSConfig{Enabled: true, CAFile: ca}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := session.New(c, host, false, false, nil)
	if err := s.Use(ctx, "/data"); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := s.Cat(ctx, name+"-dst", &b); err != nil || !bytes.Equal(b.Bytes(), copySource()) {
		t.Fatal("CLI clone bytes", err)
	}
	t.Logf("V42_CLONE_CLI platform=%s whole_clone_extension_bytes_verified", runtime.GOOS)
}
