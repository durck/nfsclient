package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Only the disposable tests/vfs configuration is supported. Do not substitute
// production exports: these cases create, rename, chmod and remove test data.
func TestVFSAuthorization(t *testing.T) {
	if os.Getenv("NFS_VIEWER_VFS") != "1" {
		t.Skip("requires disposable tests/vfs fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"sys", "krb5", "krb5i", "krb5p"} {
			for _, credential := range []string{"keytab", "ccache"} {
				if security == "sys" && credential == "ccache" || version == "3-udp" && security != "sys" && security != "krb5" {
					continue
				}
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					t.Parallel()
					cfg, realm := vfsFixtureConfig(t, version, security, credential, "alice")
					bobCfg, _ := vfsFixtureConfig(t, version, security, "keytab", "bob")
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					connect := func(t *testing.T, config Config, export string) (*Client, Node) {
						t.Helper()
						c, err := Connect(ctx, config)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(c.Close)
						n, err := c.Mount(ctx, export)
						if err != nil {
							t.Fatal(err)
						}
						return c, n
					}
					alice, root := connect(t, cfg, "/data")
					bob, bobRoot := connect(t, bobCfg, "/data")
					lookup := func(t *testing.T, c *Client, parent Node, name string) Node {
						t.Helper()
						n, err := c.Lookup(ctx, parent.Handle, name)
						if err != nil {
							t.Fatal(err)
						}
						return n
					}
					create := func(t *testing.T, c *Client, parent Node, name string, mode uint32, dir bool) Node {
						t.Helper()
						n, err := c.Create(ctx, parent.Handle, name, mode, dir)
						if err != nil {
							t.Fatal(err)
						}
						return n
					}
					denied := func(t *testing.T, err error) {
						t.Helper()
						if !errors.Is(err, Status(13)) && !errors.Is(err, Status(1)) {
							t.Fatalf("expected permission denial: %v", err)
						}
					}
					absent := func(t *testing.T, c *Client, parent Node, name string) {
						t.Helper()
						if _, err := c.Lookup(ctx, parent.Handle, name); !errors.Is(err, Status(2)) {
							t.Fatalf("unexpected remote entry %s: %v", name, err)
						}
					}
					unchanged := func(t *testing.T, c *Client, file Node, want []byte) {
						t.Helper()
						var b bytes.Buffer
						if _, err := c.ReadTo(ctx, file.Handle, &b); err != nil || !bytes.Equal(b.Bytes(), want) {
							t.Fatalf("remote content changed: %v", err)
						}
					}
					name := func(t *testing.T) string {
						t.Helper()
						var b [12]byte
						if _, err := rand.Read(b[:]); err != nil {
							t.Fatal(err)
						}
						return fmt.Sprintf("vfs-%x", b)
					}
					owner := func(t *testing.T, c *Client, n Node, uid, gid uint32, user, group string) {
						t.Helper()
						a, err := c.GetAttr(ctx, n.Handle)
						if err != nil {
							t.Fatal(err)
						}
						if c.Version() == "3" {
							if a.UID != uid || a.GID != gid {
								t.Fatalf("owner=%d:%d want=%d:%d", a.UID, a.GID, uid, gid)
							}
						} else if a.Owner != user+"@"+strings.ToLower(realm) || a.Group != group+"@"+strings.ToLower(realm) {
							t.Fatalf("owner=%s:%s want=%s:%s", a.Owner, a.Group, user, group)
						}
					}
					t.Run("namespace", func(t *testing.T) {
						dirName := name(t)
						dir := create(t, alice, root, dirName, 0755, true)
						bobDir := lookup(t, bob, bobRoot, dirName)
						file := create(t, alice, dir, "original", 0600, false)
						data := []byte("private namespace fixture")
						if _, err := alice.WriteFrom(ctx, file.Handle, bytes.NewReader(data)); err != nil {
							t.Fatal(err)
						}
						for _, directory := range []bool{false, true} {
							_, err := bob.Create(ctx, bobDir.Handle, "forbidden", 0600, directory)
							denied(t, err)
							absent(t, alice, dir, "forbidden")
						}
						denied(t, bob.Remove(ctx, bobDir.Handle, "original"))
						denied(t, bob.Rename(ctx, bobDir.Handle, "original", bobRoot.Handle, name(t)))
						sourceName := name(t)
						create(t, bob, bobRoot, sourceName, 0600, false)
						denied(t, bob.Rename(ctx, bobRoot.Handle, sourceName, bobDir.Handle, "replacement"))
						absent(t, alice, dir, "replacement")
						lookup(t, bob, bobRoot, sourceName)
						lookup(t, alice, dir, "original")
						unchanged(t, alice, file, data)
						// Permission failure leaves the same authenticated connection usable.
						if err := bob.Remove(ctx, bobRoot.Handle, sourceName); err != nil {
							t.Fatal(err)
						}
						if err := alice.Remove(ctx, dir.Handle, "original"); err != nil {
							t.Fatal(err)
						}
					})
					t.Run("sticky", func(t *testing.T) {
						dir := lookup(t, alice, root, "sticky")
						bobDir := lookup(t, bob, bobRoot, "sticky")
						fileName := name(t)
						create(t, alice, dir, fileName, 0644, false)
						denied(t, bob.Remove(ctx, bobDir.Handle, fileName))
						denied(t, bob.Rename(ctx, bobDir.Handle, fileName, bobDir.Handle, name(t)))
						lookup(t, alice, dir, fileName)
						if err := alice.Remove(ctx, dir.Handle, fileName); err != nil {
							t.Fatal(err)
						}
					})
					t.Run("supplementary-group", func(t *testing.T) {
						dir := lookup(t, alice, root, "shared")
						file := create(t, alice, dir, name(t), 0600, false)
						owner(t, alice, file, 20001, 20003, "alice", "shared")
						bobDir := lookup(t, bob, bobRoot, "shared")
						_, err := bob.Create(ctx, bobDir.Handle, name(t), 0600, false)
						denied(t, err)
						if security == "sys" {
							without := cfg
							without.Auth.Groups = nil
							plain, plainRoot := connect(t, without, "/data")
							plainDir := lookup(t, plain, plainRoot, "shared")
							_, err := plain.Create(ctx, plainDir.Handle, name(t), 0600, false)
							denied(t, err)
						}
					})
					t.Run("posix-acl", func(t *testing.T) {
						if os.Getenv("NFS_VIEWER_VFS_POSIX_ACL") != "1" && os.Getenv("NFS_VIEWER_VFS_POSIX_ACL_DIAGNOSTIC") != "1" {
						t.Skip("Ganesha 4.3 Ubuntu VFS rejects a locally valid POSIX ACL grant in this fixture")
						}
						dir := lookup(t, bob, bobRoot, "acl")
						file := lookup(t, bob, dir, "read.txt")
						unchanged(t, bob, file, []byte("ACL fixture data\n"))
						var out bytes.Buffer
						aliceDir := lookup(t, alice, root, "acl")
						_, err := alice.Lookup(ctx, aliceDir.Handle, "read.txt")
						denied(t, err)
						n, err := bob.WriteFrom(ctx, file.Handle, bytes.NewReader([]byte("forbidden")))
						denied(t, err)
						if n != 0 {
							t.Fatal("denied write reported bytes")
						}
						denied(t, bob.Remove(ctx, dir.Handle, "read.txt"))
						_, err = bob.ReadTo(ctx, file.Handle, &out)
						if err != nil || out.String() != "ACL fixture data\n" {
							t.Fatalf("ACL read failed after denials: %v", err)
						}
					})
					t.Run("acl-inheritance-mask", func(t *testing.T) {
						if os.Getenv("NFS_VIEWER_VFS_POSIX_ACL") != "1" {
							t.Skip("requires the ACL-enabled tests/vfs build")
						}
						parent := lookup(t, alice, root, "acl-inherit")
						bobParent := lookup(t, bob, bobRoot, "acl-inherit")
						dirName := name(t)
						dir := create(t, alice, parent, dirName, 0770, true)
						bobDir := lookup(t, bob, bobParent, dirName)
						file := create(t, alice, dir, "inherited", 0660, false)
						payload := []byte("inherited ACL fixture")
						if _, err := alice.WriteFrom(ctx, file.Handle, bytes.NewReader(payload)); err != nil {
							t.Fatal(err)
						}
						bobFile := lookup(t, bob, bobDir, "inherited")
						unchanged(t, bob, bobFile, payload)
						chmod := func(mode uint32) {
							t.Helper()
							if err := alice.Chmod(ctx, file.Handle, mode); err != nil {
								t.Fatal(err)
							}
							attr, err := alice.GetAttr(ctx, file.Handle)
							if err != nil || attr.Mode&0777 != mode {
								t.Fatalf("ACL mask/mode mismatch: %#o, %v", attr.Mode, err)
							}
						}
						chmod(0600)
						var out bytes.Buffer
						n, err := bob.ReadTo(ctx, bobFile.Handle, &out)
						denied(t, err)
						if n != 0 || out.Len() != 0 {
							t.Fatal("masked ACL read exposed bytes")
						}
						chmod(0640)
						unchanged(t, bob, bobFile, payload)
						// Expanding the mask cannot add write permission missing from
						// Bob's named entry, even though group mode bits now show rw.
						chmod(0660)
						n, err = bob.WriteFrom(ctx, bobFile.Handle, bytes.NewReader([]byte("forbidden")))
						denied(t, err)
						if n != 0 {
							t.Fatal("read-only inherited ACL wrote bytes")
						}
						denied(t, bob.Remove(ctx, bobDir.Handle, "inherited"))
						unchanged(t, alice, file, payload)
						// A child directory must propagate its default ACL again. A
						// restrictive creation mode masks, rather than removes, Bob.
						child := create(t, alice, dir, "nested", 0770, true)
						private := create(t, alice, child, "private", 0600, false)
						if _, err := alice.WriteFrom(ctx, private.Handle, bytes.NewReader(payload)); err != nil {
							t.Fatal(err)
						}
						bobChild := lookup(t, bob, bobDir, "nested")
						bobPrivate := lookup(t, bob, bobChild, "private")
						out.Reset()
						n, err = bob.ReadTo(ctx, bobPrivate.Handle, &out)
						denied(t, err)
						if n != 0 || out.Len() != 0 {
							t.Fatal("restrictive creation exposed bytes")
						}
						if err := alice.Chmod(ctx, private.Handle, 0640); err != nil {
							t.Fatal(err)
						}
						unchanged(t, bob, bobPrivate, payload)
					})
					if security != "sys" && alice.Identity() != "alice@"+realm+" ("+security+")" {
						t.Fatal("identity changed after denials")
					}
				})
			}
		}
	}
}

func vfsFixtureConfig(t *testing.T, version, security, credential, user string) (Config, string) {
	t.Helper()
	prefix, realm, spn := "NFS_VIEWER_KRB5_", "NFS.TEST", "nfs/server.nfs.test"
	if os.Getenv("NFS_VIEWER_VFS_AD") == "1" {
		prefix, realm, spn = "NFS_VIEWER_AD_", "AD.NFS.TEST", "nfs/server.ad.nfs.test"
	}
	port := func(s string) int {
		t.Helper()
		n, err := strconv.Atoi(os.Getenv(prefix + s))
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid fixture port %s", prefix+s)
		}
		return n
	}
	cfg := Config{Host: "127.0.0.1", Version: version, Security: security, Timeout: 3 * time.Second, Transport: "tcp", NFSPort: port("PORT"), MountPort: port("MOUNT_PORT")}
	if version == "3-udp" {
		cfg.Version = "3"
		cfg.Transport = "udp"
		cfg.NFSPort = port("UDP_PORT")
		cfg.MountPort = port("UDP_MOUNT_PORT")
	}
	if security == "sys" {
		switch user {
		case "alice":
			cfg.Auth = Auth{UID: 20001, GID: 20001, Groups: []uint32{20003}}
		case "bob":
			cfg.Auth = Auth{UID: 20002, GID: 20002}
		}
		return cfg, realm
	}
	cfg.Kerberos = KerberosConfig{ConfigFile: os.Getenv(prefix + "CONFIG"), Principal: user + "@" + realm, SPN: spn}
	field := strings.ToUpper(user) + "_"
	if realm == "AD.NFS.TEST" && user == "alice" || user == "root" {
		field = ""
	}
	if credential == "ccache" {
		cfg.Kerberos.CCache = os.Getenv(prefix + field + "CCACHE")
	} else {
		cfg.Kerberos.Keytab = os.Getenv(prefix + field + "KEYTAB")
	}
	if cfg.Kerberos.Keytab == "" && cfg.Kerberos.CCache == "" {
		t.Fatal("missing explicit fixture credential")
	}
	return cfg, realm
}

func TestVFSRootSquash(t *testing.T) {
	if os.Getenv("NFS_VIEWER_VFS") != "1" {
		t.Skip("requires disposable tests/vfs fixture")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"sys", "krb5", "krb5i", "krb5p"} {
			if security != "sys" && os.Getenv("NFS_VIEWER_VFS_AD") == "1" || version == "3-udp" && security != "sys" && security != "krb5" {
				continue
			}
			t.Run(version+"/"+security, func(t *testing.T) {
				t.Parallel()
				cfg, realm := vfsFixtureConfig(t, version, security, "keytab", "root")
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				c, err := Connect(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				root, err := c.Mount(ctx, "/squashed")
				if err != nil {
					t.Fatal(err)
				}
				private, err := c.Lookup(ctx, root.Handle, "root-only")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = c.Lookup(ctx, private.Handle, "private.txt"); !errors.Is(err, Status(13)) {
					t.Fatalf("squashed root accessed private file: %v", err)
				}
				var nonce [12]byte
				if _, err = rand.Read(nonce[:]); err != nil {
					t.Fatal(err)
				}
				file, err := c.Create(ctx, root.Handle, fmt.Sprintf("squashed-%x", nonce), 0600, false)
				if err != nil {
					t.Fatal(err)
				}
				attr, err := c.GetAttr(ctx, file.Handle)
				if err != nil {
					t.Fatal(err)
				}
				if c.Version() == "3" {
					if attr.UID != 65534 || attr.GID != 65534 {
						t.Fatalf("root not mapped: %d:%d", attr.UID, attr.GID)
					}
				} else if attr.Owner != "nobody@"+strings.ToLower(realm) || attr.Group != "nogroup@"+strings.ToLower(realm) {
					t.Fatalf("root not mapped: %s:%s", attr.Owner, attr.Group)
				}
			})
		}
	}
}
