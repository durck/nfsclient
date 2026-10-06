package nfs

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// The fixture maps two real Kerberos principals to distinct, non-root local
// accounts. Root creates only the test workspace; user operations stay GSS.
func TestKerberosUserPermissions(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KRB5_ALICE_KEYTAB") == "" {
		t.Skip("requires tests/kerberos ordinary-user credentials")
	}
	for _, version := range []string{"3", "4.0", "4.1", "4.2", "3-udp"} {
		for _, security := range []string{"krb5", "krb5i", "krb5p"} {
			if version == "3-udp" && security != "krb5" {
				continue
			}
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(version+"/"+security+"/"+credential, func(t *testing.T) {
					if credential == "ccache" && os.Getenv("NFS_VIEWER_KRB5_ALICE_CCACHE") == "" {
						t.Skip("requires explicit Alice FILE cache")
					}
					testKerberosUserPermissions(t, version, security, credential)
				})
			}
		}
	}
}

func testKerberosUserPermissions(t *testing.T, version, security, credential string) {
	port := func(variable string) int {
		t.Helper()
		n, err := strconv.Atoi(os.Getenv(variable))
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid fixture port %s", variable)
		}
		return n
	}
	cfg := Config{Host: "127.0.0.1", Version: version, Transport: "tcp", Security: security, Timeout: 3 * time.Second,
		NFSPort: port("NFS_VIEWER_KRB5_PORT"), MountPort: port("NFS_VIEWER_KRB5_MOUNT_PORT")}
	if version == "3-udp" {
		cfg.Version, cfg.Transport = "3", "udp"
		cfg.NFSPort, cfg.MountPort = port("NFS_VIEWER_KRB5_UDP_PORT"), port("NFS_VIEWER_KRB5_UDP_MOUNT_PORT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func(principal, keytab, cache string) (*Client, Node) {
		t.Helper()
		c := cfg
		c.Kerberos = KerberosConfig{ConfigFile: os.Getenv("NFS_VIEWER_KRB5_CONFIG"), Keytab: keytab, CCache: cache,
			Principal: principal + "@NFS.TEST", SPN: "nfs/server.nfs.test"}
		client, err := Connect(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		root, err := client.Mount(ctx, "/data")
		if err != nil {
			t.Fatal(err)
		}
		if client.Identity() != principal+"@NFS.TEST ("+security+")" {
			t.Fatal("principal/security changed")
		}
		return client, root
	}
	admin, export := connect("root", os.Getenv("NFS_VIEWER_KRB5_KEYTAB"), "")
	aliceKeytab, aliceCache := os.Getenv("NFS_VIEWER_KRB5_ALICE_KEYTAB"), ""
	if credential == "ccache" {
		aliceKeytab, aliceCache = "", os.Getenv("NFS_VIEWER_KRB5_ALICE_CCACHE")
	}
	alice, aliceExport := connect("alice", aliceKeytab, aliceCache)
	bob, bobExport := connect("bob", os.Getenv("NFS_VIEWER_KRB5_BOB_KEYTAB"), "")
	create := func(c *Client, dir Node, name string, mode uint32, directory bool) Node {
		t.Helper()
		n, err := c.Create(ctx, dir.Handle, name, mode, directory)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return n
	}
	lookup := func(c *Client, dir Node, name string) Node {
		t.Helper()
		n, err := c.Lookup(ctx, dir.Handle, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		return n
	}
	chmod := func(c *Client, n Node, mode uint32) {
		t.Helper()
		if err := c.Chmod(ctx, n.Handle, mode); err != nil {
			t.Fatal(err)
		}
	}
	denied := func(err error) {
		t.Helper()
		if !errors.Is(err, Status(13)) && !errors.Is(err, Status(1)) {
			t.Fatalf("expected NFS access/permission denial, got %v", err)
		}
	}
	owner := func(c *Client, n Node, name string, id uint32) {
		t.Helper()
		a, err := c.GetAttr(ctx, n.Handle)
		if err != nil {
			t.Fatal(err)
		}
		if c.Version() == "3" {
			if a.UID != id || a.GID != id {
				t.Fatalf("unexpected %s numeric owner: %d:%d", name, a.UID, a.GID)
			}
		} else if a.Owner != name+"@nfs.test" || a.Group != name+"@nfs.test" {
			t.Fatalf("unexpected %s named owner: %q:%q", name, a.Owner, a.Group)
		}
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("users-%x", nonce)
	workspace := create(admin, export, name, 0777, true)
	// Explicit mode avoids depending on a server's creation-mask policy.
	chmod(admin, workspace, 0777)
	aliceWorkspace := lookup(alice, aliceExport, name)
	bobWorkspace := lookup(bob, bobExport, name)
	aliceDir := create(alice, aliceWorkspace, "alice", 0755, true)
	owner(alice, aliceDir, "alice", 20001)
	directoryAttr, err := alice.GetAttr(ctx, aliceDir.Handle)
	if err != nil || directoryAttr.Mode&0777 != 0755 {
		t.Fatalf("Alice directory mode: %o, %v", directoryAttr.Mode, err)
	}
	file := create(alice, aliceDir, "private.bin", 0600, false)
	owner(alice, file, "alice", 20001)
	payload := bytes.Repeat([]byte{0, 255, 27, 'a', 'l', 'i', 'c', 'e'}, 2100)
	if n, err := alice.WriteFrom(ctx, file.Handle, bytes.NewReader(payload)); err != nil || n != int64(len(payload)) {
		t.Fatalf("Alice write: %d, %v", n, err)
	}
	bobDir := lookup(bob, bobWorkspace, "alice")
	bobFile := lookup(bob, bobDir, "private.bin")
	var received bytes.Buffer
	n, err := bob.ReadTo(ctx, bobFile.Handle, &received)
	denied(err)
	if n != 0 || received.Len() != 0 {
		t.Fatal("denied read exposed file bytes")
	}
	n, err = bob.WriteFrom(ctx, bobFile.Handle, bytes.NewReader([]byte("must not replace Alice's data")))
	denied(err)
	if n != 0 {
		t.Fatal("denied write reported transferred bytes")
	}
	denied(bob.Chmod(ctx, bobFile.Handle, 0666))
	// MEM retains a separately enabled failing diagnostic. The VFS fixture
	// requires these checks as part of ordinary permission validation.
	if os.Getenv("NFS_VIEWER_VFS") == "1" || os.Getenv("NFS_VIEWER_KRB5_MEM_NAMESPACE_DIAGNOSTIC") == "1" {
		create(alice, aliceDir, "unlink-test", 0600, false)
		t.Run("remove-denied", func(t *testing.T) {
			if err := bob.Remove(ctx, bobDir.Handle, "unlink-test"); !errors.Is(err, Status(13)) && !errors.Is(err, Status(1)) {
				t.Fatalf("REMOVE authorization: expected denial, got %v", err)
			}
		})
		t.Run("create-denied", func(t *testing.T) {
			_, err := bob.Create(ctx, bobDir.Handle, "forbidden", 0600, false)
			if !errors.Is(err, Status(13)) && !errors.Is(err, Status(1)) {
				t.Fatalf("CREATE authorization: expected denial, got %v", err)
			}
		})
	}
	unchanged, err := alice.GetAttr(ctx, file.Handle)
	if err != nil || unchanged.Mode&0777 != 0600 || unchanged.Size != uint64(len(payload)) {
		t.Fatalf("denied operations changed metadata: %+v, %v", unchanged, err)
	}
	received.Reset()
	if _, err := alice.ReadTo(ctx, file.Handle, &received); err != nil || !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("denied operations changed file content: %v", err)
	}
	chmod(alice, aliceDir, 0700)
	_, err = bob.Lookup(ctx, bobDir.Handle, "private.bin")
	denied(err)
	chmod(alice, aliceDir, 0755)
	chmod(alice, file, 0644)
	received.Reset()
	if _, err := bob.ReadTo(ctx, bobFile.Handle, &received); err != nil || !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("same session failed after permissions granted: %v", err)
	}
	// Bob can still create and transfer his own file after all denied operations.
	bobOwn := create(bob, bobWorkspace, "bob.bin", 0600, false)
	owner(bob, bobOwn, "bob", 20002)
	if _, err := bob.WriteFrom(ctx, bobOwn.Handle, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	received.Reset()
	if _, err := bob.ReadTo(ctx, bobOwn.Handle, &received); err != nil || !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("Bob transfer after permission failures: %v", err)
	}
	if bob.Identity() != "bob@NFS.TEST ("+security+")" || alice.Identity() != "alice@NFS.TEST ("+security+")" {
		t.Fatal("permission handling changed identity or security")
	}
}
