package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func nfs2ServerConfig(t *testing.T, transport string) Config {
	t.Helper()
	if os.Getenv("NFS_VIEWER_NFS2_SERVER") != "1" {
		t.Skip("requires isolated tests/nfsv2 fixture")
	}
	port := func(key, fallback string) int {
		value := os.Getenv("NFS_VIEWER_NFS2_" + key)
		if value == "" {
			value = fallback
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid fixture port %s", key)
		}
		return n
	}
	return Config{Host: "127.0.0.1", Version: "2", Transport: transport, NFSPort: port("PORT", "19049"), MountPort: port("MOUNT_PORT", "19048"), Timeout: 3 * time.Second, Auth: Auth{UID: 20001, GID: 20001, Groups: []uint32{20003}}}
}

func TestNFS2Server(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, version := range []string{"2", "auto"} {
			t.Run(transport+"/"+version, func(t *testing.T) {
				cfg := nfs2ServerConfig(t, transport)
				cfg.Version = version
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				connect := func(t *testing.T, config Config, export string) (*Client, Node) {
					t.Helper()
					c, err := Connect(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(c.Close)
					if c.Version() != "2" {
						t.Fatal("wrong protocol", c.Version())
					}
					root, err := c.Mount(ctx, export)
					if err != nil {
						t.Fatal(err)
					}
					if err := c.Tune(ctx, root.Handle); err != nil {
						t.Fatal(err)
					}
					return c, root
				}
				alice, root := connect(t, cfg, "/data")
				bobConfig := cfg
				bobConfig.Auth = Auth{UID: 20002, GID: 20002}
				bob, bobRoot := connect(t, bobConfig, "/data")
				lookup := func(t *testing.T, c *Client, parent Node, name string) Node {
					t.Helper()
					n, err := c.Lookup(ctx, parent.Handle, name)
					if err != nil {
						t.Fatal(err)
					}
					return n
				}
				read := func(t *testing.T, c *Client, file Node, want []byte) {
					t.Helper()
					var got bytes.Buffer
					if n, err := c.ReadTo(ctx, file.Handle, &got); err != nil || n != int64(len(want)) || !bytes.Equal(got.Bytes(), want) {
						t.Fatalf("read %d bytes: %v", n, err)
					}
				}
				name := "v2-" + runtime.GOOS + "-" + version + "-" + transport
				var workspace Node
				t.Run("namespace", func(t *testing.T) {
					exports, err := alice.Exports(ctx)
					if err != nil || len(exports) != 3 {
						t.Fatal("export policies", exports, err)
					}
					entries, err := alice.ReadDir(ctx, lookup(t, alice, root, "wide").Handle)
					if err != nil || len(entries) != 300 {
						t.Fatalf("directory pages: %d %v", len(entries), err)
					}
					for i, e := range entries {
						if e.Name != fmt.Sprintf("entry-%03d", i) || e.Attr.Type != 1 {
							t.Fatal("directory mixed")
						}
					}
					for name, want := range map[string]string{"link.txt": "public.txt", "dangling.txt": "missing"} {
						got, err := alice.Readlink(ctx, lookup(t, alice, root, name).Handle)
						if err != nil || got != want {
							t.Fatal("symlink", got, err)
						}
					}
				})
				t.Run("authorization", func(t *testing.T) {
					read(t, alice, lookup(t, alice, root, "private.txt"), []byte("private-alice\n"))
					read(t, alice, lookup(t, alice, root, "group.txt"), []byte("shared-group\n"))
					for _, file := range []string{"private.txt", "group.txt"} {
						var exposed bytes.Buffer
						n, err := bob.ReadTo(ctx, lookup(t, bob, bobRoot, file).Handle, &exposed)
						if !errors.Is(err, Status(13)) || n != 0 || exposed.Len() != 0 {
							t.Fatal("unauthorized data", err)
						}
					}
				})
				var err error
				workspace, err = alice.Create(ctx, root.Handle, name, 0755, true)
				if err != nil {
					t.Fatal("fresh fixture workspace required", err)
				}
				payload := bytes.Repeat([]byte("independent-v2\x00"), 32768)
				if !t.Run("staged_roundtrip", func(t *testing.T) {
					for _, item := range []struct {
						name string
						data []byte
					}{{"binary", payload}, {"empty", nil}} {
						filename, data := item.name, item.data
						n, err := alice.UploadV2(ctx, workspace.Handle, filename, 0640, bytes.NewReader(data), int64(len(data)), false, nil)
						if err != nil || n != int64(len(data)) {
							t.Fatal("staged upload", n, err)
						}
						file := lookup(t, alice, workspace, filename)
						if file.Attr.UID != 20001 || file.Attr.GID != 20001 || file.Attr.Mode&0777 != 0640 {
							t.Fatal("numeric ownership/mode", file.Attr)
						}
						read(t, alice, file, data)
					}
				}) {
					return
				}
				t.Run("overwrite_refusal", func(t *testing.T) {
					for _, overwrite := range []bool{false, true} {
						progressed := false
						n, err := alice.UploadV2(ctx, workspace.Handle, "binary", 0600, bytes.NewBufferString("replacement"), 11, overwrite, func(uint64) { progressed = true })
						want := error(Status(17))
						if overwrite {
							want = ErrLegacyReplacementUnsupported
						}
						if !errors.Is(err, want) || n != 0 || progressed {
							t.Fatal("overwrite contract", n, err)
						}
					}
					read(t, alice, lookup(t, alice, workspace, "binary"), payload)
				})
				t.Run("publication_race", func(t *testing.T) {
					peer, peerRoot := connect(t, cfg, "/data")
					peerDir := lookup(t, peer, peerRoot, name)
					competed := false
					_, err := alice.UploadV2(ctx, workspace.Handle, "race", 0640, bytes.NewReader(payload), int64(len(payload)), false, func(uint64) {
						if competed {
							return
						}
						competed = true
						if _, err := peer.UploadV2(ctx, peerDir.Handle, "race", 0640, bytes.NewBufferString("winner"), 6, false, nil); err != nil {
							t.Fatal(err)
						}
					})
					if !errors.Is(err, Status(17)) || !competed {
						t.Fatal("LINK no-replace publication", err)
					}
					read(t, alice, lookup(t, alice, workspace, "race"), []byte("winner"))
				})
				t.Run("incomplete_source", func(t *testing.T) {
					_, err := alice.UploadV2(ctx, workspace.Handle, "incomplete", 0640, bytes.NewReader(payload), int64(len(payload)+1), false, nil)
					if err == nil {
						t.Fatal("short source published")
					}
					if _, err := alice.Lookup(ctx, workspace.Handle, "incomplete"); !errors.Is(err, Status(2)) {
						t.Fatal("partial publication", err)
					}
				})
				t.Run("size_boundary", func(t *testing.T) {
					_, err := alice.UploadV2(ctx, workspace.Handle, "oversize", 0640, bytes.NewReader(nil), maxV2File+1, false, nil)
					if err == nil {
						t.Fatal("oversized upload accepted")
					}
					file := lookup(t, alice, root, "boundary.bin")
					if file.Attr.Size != maxV2File {
						t.Fatal("boundary size wrapped", file.Attr.Size)
					}
					count := min(alice.ReadSize, uint32(8192))
					e, _ := handle2(file.Handle)
					e.u32(maxV2File - count)
					e.u32(count)
					e.u32(0)
					d, err := alice.call(ctx, 6, e)
					if err != nil {
						t.Fatal(err)
					}
					a := attr2(d)
					tail := d.opaque(count)
					if d.err != nil || a.Size != maxV2File || len(tail) != int(count) || !bytes.Equal(tail[len(tail)-6:], []byte("V2-END")) || !bytes.Equal(tail[:len(tail)-6], make([]byte, len(tail)-6)) {
						t.Fatal("real boundary READ", a.Size, d.err)
					}
					var exposed bytes.Buffer
					n, err := alice.ReadTo(ctx, lookup(t, alice, root, "too-large.bin").Handle, &exposed)
					if err == nil || n != 0 || exposed.Len() != 0 {
						t.Fatal("oversized download exposed bytes", n, err)
					}
				})
				t.Run("root_squash", func(t *testing.T) {
					rootCfg := cfg
					rootCfg.Auth = Auth{}
					c, r := connect(t, rootCfg, "/squashed")
					if _, err := c.UploadV2(ctx, r.Handle, name, 0600, bytes.NewBufferString("squashed"), 8, false, nil); err != nil {
						t.Fatal(err)
					}
					if file := lookup(t, c, r, name); file.Attr.UID != 65534 || file.Attr.GID != 65534 {
						t.Fatal("root not squashed", file.Attr)
					}
				})
				t.Run("read_only", func(t *testing.T) {
					c, r := connect(t, cfg, "/readonly")
					read(t, c, lookup(t, c, r, "seed"), []byte("read-only-seed\n"))
					if _, err := c.UploadV2(ctx, r.Handle, name, 0600, bytes.NewBufferString("denied"), 6, false, nil); !errors.Is(err, Status(30)) {
						t.Fatal("read-only write", err)
					}
				})
				t.Run("metadata_mutations", func(t *testing.T) {
					file := lookup(t, alice, workspace, "binary")
					if err := alice.Chmod(ctx, file.Handle, 0600); err != nil {
						t.Fatal(err)
					}
					if a, err := alice.GetAttr(ctx, file.Handle); err != nil || a.Mode&0777 != 0600 {
						t.Fatal("chmod", err)
					}
					if err := alice.Rename(ctx, workspace.Handle, "empty", workspace.Handle, "renamed"); err != nil {
						t.Fatal(err)
					}
					if err := alice.Remove(ctx, workspace.Handle, "renamed"); err != nil {
						t.Fatal(err)
					}
					entries, err := alice.ReadDir(ctx, workspace.Handle)
					if err != nil || len(entries) != 2 || entries[0].Name != "binary" || entries[1].Name != "race" {
						t.Fatal("stage cleanup/namespace", entries, err)
					}
				})
				if !t.Failed() {
					t.Logf("NFS2_SERVER platform=%s transport=%s selection=%s real_protocol=2 policy_checks boundary=%d sha256=%x", runtime.GOOS, transport, version, maxV2File, sha256.Sum256(payload))
				}
			})
		}
	}
}

func TestNFS2ServerDiscovery(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NFS2_DISCOVERY") != "1" {
		t.Skip("direct Linux fixture namespace only")
	}
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			cfg := nfs2ServerConfig(t, transport)
			cfg.NFSPort = 0
			cfg.MountPort = 0
			cfg.PortmapPort = 111
			c, err := Connect(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Mount(context.Background(), "/data"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNFS2ServerLarge(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NFS2_LARGE") != "1" {
		t.Skip("opt-in real 32 MiB transfer")
	}
	const size = 32<<20 + 17
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			cfg := nfs2ServerConfig(t, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			c, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			root, err := c.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Tune(ctx, root.Handle); err != nil {
				t.Fatal(err)
			}
			name := "large-" + runtime.GOOS + "-" + transport
			// A bounded reader supplies an independently predictable repeated pattern.
			r := io.LimitReader(&nfs2PatternReader{}, size)
			expected := sha256.New()
			written, err := c.UploadV2(ctx, root.Handle, name, 0600, io.TeeReader(r, expected), size, false, nil)
			if err != nil || written != size {
				t.Fatal("large upload", written, err)
			}
			file, err := c.Lookup(ctx, root.Handle, name)
			if err != nil {
				t.Fatal(err)
			}
			actual := sha256.New()
			read, err := c.ReadTo(ctx, file.Handle, actual)
			if err != nil || read != size || !bytes.Equal(actual.Sum(nil), expected.Sum(nil)) {
				t.Fatal("large read", read, err)
			}
			if err := c.Remove(ctx, root.Handle, name); err != nil {
				t.Fatal(err)
			}
			t.Logf("NFS2_LARGE platform=%s transport=%s bytes=%d sha256=%x", runtime.GOOS, transport, size, actual.Sum(nil))
		})
	}
}

type nfs2PatternReader struct{ offset uint64 }

// Explicit resource opt-in: the dedicated tmpfs fixture must have >8 GiB free
// for all four retained Windows/Linux TCP/UDP files. Never run on a user export.
func TestNFS2ServerFullBoundary(t *testing.T) {
	if os.Getenv("NFS_VIEWER_NFS2_BOUNDARY") != "1" {
		t.Skip("opt-in complete 2 GiB minus one transfer")
	}
	const size int64 = 1<<31 - 1
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			cfg := nfs2ServerConfig(t, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
			defer cancel()
			c, err := Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			root, err := c.Mount(ctx, "/data")
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Tune(ctx, root.Handle); err != nil {
				t.Fatal(err)
			}
			name := "boundary-full-" + runtime.GOOS + "-" + transport
			expected := sha256.New()
			r := io.TeeReader(io.LimitReader(&nfs2PatternReader{}, size), expected)
			written, err := c.UploadV2(ctx, root.Handle, name, 0600, r, size, false, nil)
			if err != nil || written != size {
				t.Fatal("full boundary upload", written, err)
			}
			file, err := c.Lookup(ctx, root.Handle, name)
			if err != nil {
				t.Fatal(err)
			}
			if file.Attr.Size != uint64(size) {
				t.Fatal("boundary size", file.Attr.Size)
			}
			actual := sha256.New()
			read, err := c.ReadTo(ctx, file.Handle, actual)
			if err != nil || read != size || !bytes.Equal(actual.Sum(nil), expected.Sum(nil)) {
				t.Fatal("full boundary read", read, err)
			}
			t.Logf("NFS2_FULL_BOUNDARY platform=%s transport=%s bytes=%d sha256=%x retained_for_native_oracle", runtime.GOOS, transport, size, actual.Sum(nil))
		})
	}
}

func (r *nfs2PatternReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte((r.offset + uint64(i)) % 251)
	}
	r.offset += uint64(len(p))
	return len(p), nil
}
