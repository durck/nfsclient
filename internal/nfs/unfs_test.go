package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Relay real NFS replies unchanged, inserting a rename between directory pages.
// UNFS3 invalidates its global cookie generation even for another directory.
func TestUNFSDirectoryRestart(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, persistent := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/persistent=%t", transport, persistent), func(t *testing.T) {
				cfg := unfsConfig(t, transport)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				peer, err := Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				root, err := peer.Mount(ctx, "/data")
				if err != nil {
					t.Fatal(err)
				}
				wide, err := peer.Lookup(ctx, root.Handle, "wide")
				if err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("restart-%d", time.Now().UnixNano())
				if _, err := peer.Create(ctx, root.Handle, name, 0600, false); err != nil {
					t.Fatal(err)
				}
				starts, mutations := 0, 0
				relay := scriptedClient(t, func(prog, proc uint32, d *decoder) (encoder, error) {
					if proc == 16 {
						args := &decoder{b: d.b}
						args.opaque(64)
						cookie := args.u64()
						if cookie == 0 {
							starts++
						} else if mutations == 0 || persistent {
							next := name + "x"
							if err := peer.Rename(ctx, root.Handle, name, root.Handle, next); err != nil {
								return nil, err
							}
							name = next
							mutations++
						}
					}
					r, err := peer.nfs.call(ctx, prog, 3, proc, &cfg.Auth, encoder(d.b))
					if err != nil {
						return nil, err
					}
					return encoder(r.b), nil
				})
				relay.basicReadDir = true
				entries, err := relay.ReadDir(ctx, wide.Handle)
				if starts != 2 {
					t.Fatalf("missing/bounded restart: starts=%d, error=%v", starts, err)
				}
				if persistent {
					if mutations != 2 || entries != nil || err == nil || !strings.Contains(err.Error(), "directory changed") {
						t.Fatalf("unstable listing: %d entries, %d mutations, %v", len(entries), mutations, err)
					}
				} else {
					if mutations != 1 || err != nil || len(entries) != 300 {
						t.Fatalf("restarted listing: %d entries, %d mutations, %v", len(entries), mutations, err)
					}
					for i, entry := range entries {
						if entry.Name != fmt.Sprintf("entry-%03d.txt", i) {
							t.Fatalf("mixed listing at %d: %s", i, entry.Name)
						}
					}
				}
			})
		}
	}
}

// The opt-in fixture exports only disposable container tmpfs filesystems.
func TestUNFSCompatibility(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			cfg := unfsConfig(t, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			connect := func(config Config, export string) (*Client, Node) {
				t.Helper()
				c, err := Connect(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				r, err := c.Mount(ctx, export)
				if err != nil {
					t.Fatal(err)
				}
				return c, r
			}
			alice, root := connect(cfg, "/data")
			bobConfig := cfg
			bobConfig.Auth = Auth{UID: 20002, GID: 20002}
			bob, bobRoot := connect(bobConfig, "/data")
			lookup := func(c *Client, parent Node, name string) Node {
				t.Helper()
				n, err := c.Lookup(ctx, parent.Handle, name)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			create := func(c *Client, parent Node, name string, mode uint32, directory bool) Node {
				t.Helper()
				n, err := c.Create(ctx, parent.Handle, name, mode, directory)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			denied := func(err error) {
				t.Helper()
				if !errors.Is(err, Status(13)) && !errors.Is(err, Status(1)) {
					t.Fatalf("expected permission denial: %v", err)
				}
			}
			read := func(c *Client, file Node, want []byte) {
				t.Helper()
				var out bytes.Buffer
				if n, err := c.ReadTo(ctx, file.Handle, &out); err != nil || n != int64(len(want)) || !bytes.Equal(out.Bytes(), want) {
					t.Fatalf("read differs: %d %v", n, err)
				}
			}
			name := func() string {
				t.Helper()
				var token [12]byte
				if _, err := rand.Read(token[:]); err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("unfs-%x", token)
			}
			exports, err := alice.Exports(ctx)
			if err != nil || len(exports) != 4 {
				t.Fatalf("exports: %+v %v", exports, err)
			}
			wide := lookup(alice, root, "wide")
			if _, err := alice.readDir(ctx, wide.Handle, true); !unsupported(err) {
				t.Fatalf("fixture must reject READDIRPLUS: %v", err)
			}
			for i := 0; i < 2; i++ {
				entries, err := alice.ReadDir(ctx, wide.Handle)
				if err != nil || len(entries) != 300 {
					t.Fatalf("paged READDIR: %d %v", len(entries), err)
				}
				for j, e := range entries {
					if e.Name != fmt.Sprintf("entry-%03d.txt", j) || e.Attr.Type != 1 || e.Attr.Size != 12 || len(e.Handle) == 0 {
						t.Fatalf("entry %d: %+v", j, e)
					}
				}
			}
			for _, linkName := range []string{"link.txt", "dangling"} {
				link := lookup(alice, root, linkName)
				want := "read.txt"
				if linkName == "dangling" {
					want = "missing"
				}
				if target, err := alice.Readlink(ctx, link.Handle); err != nil || target != want || link.Attr.Type != 5 {
					t.Fatalf("symlink: %q %v", target, err)
				}
			}
			dirName := name()
			dir := create(alice, root, dirName, 0755, true)
			bobDir := lookup(bob, bobRoot, dirName)
			file := create(alice, dir, "file", 0600, false)
			payload := bytes.Repeat([]byte{0, 255, 27, 'N', 'F', 'S'}, 17000)
			if n, err := alice.WriteFrom(ctx, file.Handle, bytes.NewReader(payload)); err != nil || n != int64(len(payload)) {
				t.Fatalf("write: %d %v", n, err)
			}
			read(alice, file, payload)
			if _, err := alice.Create(ctx, dir.Handle, "file", 0644, false); !errors.Is(err, Status(17)) {
				t.Fatalf("guarded collision: %v", err)
			}
			var exposed bytes.Buffer
			if n, err := bob.ReadTo(ctx, file.Handle, &exposed); n != 0 || exposed.Len() != 0 {
				t.Fatal("denied read exposed bytes")
			} else {
				denied(err)
			}
			if n, err := bob.WriteFrom(ctx, file.Handle, bytes.NewReader([]byte("forbidden"))); n != 0 {
				t.Fatal("denied write sent bytes")
			} else {
				denied(err)
			}
			denied(bob.Chmod(ctx, file.Handle, 0777))
			for _, directory := range []bool{false, true} {
				_, err := bob.Create(ctx, bobDir.Handle, "forbidden", 0600, directory)
				denied(err)
			}
			denied(bob.Remove(ctx, bobDir.Handle, "file"))
			denied(bob.Rename(ctx, bobDir.Handle, "file", bobRoot.Handle, name()))
			entries, err := alice.ReadDir(ctx, dir.Handle)
			if err != nil || len(entries) != 1 || entries[0].Name != "file" {
				t.Fatalf("denial changed namespace: %+v %v", entries, err)
			}
			read(alice, file, payload)
			if err := alice.Chmod(ctx, file.Handle, 0644); err != nil {
				t.Fatal(err)
			}
			read(bob, file, payload)
			replacement := create(alice, dir, "temporary", 0600, false)
			if _, err := alice.WriteFrom(ctx, replacement.Handle, bytes.NewReader([]byte("replacement"))); err != nil {
				t.Fatal(err)
			}
			if err := alice.Rename(ctx, dir.Handle, "temporary", dir.Handle, "file"); err != nil {
				t.Fatal(err)
			}
			read(alice, lookup(alice, dir, "file"), []byte("replacement"))
			if err := alice.Remove(ctx, dir.Handle, "file"); err != nil {
				t.Fatal(err)
			}
			if _, err := alice.Lookup(ctx, dir.Handle, "file"); !errors.Is(err, Status(2)) {
				t.Fatalf("remove: %v", err)
			}
			shared := lookup(alice, root, "shared")
			sharedFile := create(alice, shared, name(), 0600, false)
			if attr, err := alice.GetAttr(ctx, sharedFile.Handle); err != nil || attr.UID != 20001 || attr.GID != 20003 {
				t.Fatalf("setgid owner: %+v %v", attr, err)
			}
			noGroupCfg := cfg
			noGroupCfg.Auth.Groups = nil
			noGroup, _ := connect(noGroupCfg, "/data")
			_, err = noGroup.Create(ctx, shared.Handle, name(), 0600, false)
			denied(err)
			sticky := lookup(alice, root, "sticky")
			stickyName := name()
			create(alice, sticky, stickyName, 0644, false)
			denied(bob.Remove(ctx, sticky.Handle, stickyName))
			if err := alice.Remove(ctx, sticky.Handle, stickyName); err != nil {
				t.Fatal(err)
			}
			aclParent := lookup(alice, root, "acl-inherit")
			aclDir := create(alice, aclParent, name(), 0770, true)
			aclFile := create(alice, aclDir, "inherited", 0660, false)
			if _, err := alice.WriteFrom(ctx, aclFile.Handle, bytes.NewReader([]byte("ACL"))); err != nil {
				t.Fatal(err)
			}
			read(bob, aclFile, []byte("ACL"))
			if err := alice.Chmod(ctx, aclFile.Handle, 0600); err != nil {
				t.Fatal(err)
			}
			exposed.Reset()
			if n, err := bob.ReadTo(ctx, aclFile.Handle, &exposed); n != 0 || exposed.Len() != 0 {
				t.Fatal("masked ACL exposed bytes")
			} else {
				denied(err)
			}
			if err := alice.Chmod(ctx, aclFile.Handle, 0640); err != nil {
				t.Fatal(err)
			}
			read(bob, aclFile, []byte("ACL"))
			rootCfg := cfg
			rootCfg.Auth = Auth{}
			squashed, squashedRoot := connect(rootCfg, "/squashed")
			private := lookup(squashed, squashedRoot, "private")
			_, err = squashed.Lookup(ctx, private.Handle, "file")
			denied(err)
			anon := create(squashed, squashedRoot, name(), 0600, false)
			if attr, err := squashed.GetAttr(ctx, anon.Handle); err != nil || attr.UID != 65534 || attr.GID != 65534 {
				t.Fatalf("root squash: %+v %v", attr, err)
			}
			ro, roRoot := connect(cfg, "/readonly")
			read(ro, lookup(ro, roRoot, "read.txt"), []byte("read-only export\n"))
			if _, err := ro.Create(ctx, roRoot.Handle, name(), 0600, false); !errors.Is(err, Status(30)) {
				t.Fatalf("read-only export: %v", err)
			}
			if _, err := alice.Mount(ctx, "/secure"); !errors.Is(err, Status(13)) {
				t.Fatalf("unreserved MOUNT accepted: %v", err)
			}
			if os.Getenv("NFS_VIEWER_UNFS_RESERVED") == "1" {
				if runtime.GOOS != "linux" {
					t.Fatal("reserved-port evidence requires direct Linux fixture network, without Docker host forwarding")
				}
				reservedCfg := cfg
				reservedCfg.ReservedPort = true
				reserved, secureRoot := connect(reservedCfg, "/secure")
				create(reserved, secureRoot, name(), 0600, false)
			}
		})
	}
}

func unfsConfig(t *testing.T, transport string) Config {
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
	return Config{Host: "127.0.0.1", Version: "3", Transport: transport, NFSPort: port("PORT"), MountPort: port("MOUNT_PORT"), Timeout: 3 * time.Second, Auth: Auth{UID: 20001, GID: 20001, Groups: []uint32{20003}}}
}
