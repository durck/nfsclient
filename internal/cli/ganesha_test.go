package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// Opt-in tests against tests/ganesha's disposable loopback-only MEM export.
// No production hosts or OS mounts are used. The fixture is not a filesystem
// or server-product certification beyond the exact tested configuration.
func TestGaneshaVersions(t *testing.T) {
	portText := os.Getenv("NFS_VIEWER_TEST_PORT")
	if portText == "" {
		t.Skip("start tests/ganesha and set NFS_VIEWER_TEST_PORT")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	mountPort, _ := strconv.Atoi(os.Getenv("NFS_VIEWER_TEST_MOUNT_PORT"))
	for _, selected := range []string{"4.0", "4.1", "4.2", "auto", "3", "3-udp", "auto-udp"} {
		t.Run(selected, func(t *testing.T) {
			version, transport, nfsPort, mntPort := selected, "tcp", port, mountPort
			if selected == "3-udp" || selected == "auto-udp" {
				version, transport = "3", "udp"
				if selected == "auto-udp" {
					version = "auto"
				}
				nfsPort, _ = strconv.Atoi(os.Getenv("NFS_VIEWER_TEST_UDP_PORT"))
				mntPort, _ = strconv.Atoi(os.Getenv("NFS_VIEWER_TEST_UDP_MOUNT_PORT"))
				if nfsPort == 0 || mntPort == 0 {
					t.Skip("set UDP fixture ports")
				}
			}
			if version == "3" && mntPort == 0 {
				t.Skip("set NFS_VIEWER_TEST_MOUNT_PORT for NFSv3")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			client, err := nfs.Connect(ctx, nfs.Config{Host: "127.0.0.1", Version: version, Transport: transport, NFSPort: nfsPort, MountPort: mntPort, Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			want := "4.2"
			if transport == "udp" {
				want = "3"
			}
			if version == "auto" && client.Version() != want {
				t.Fatalf("auto selected %s", client.Version())
			}
			version = client.Version()
			if transport == "udp" && (client.Transport() != "udp" || client.ReadSize > 4096) {
				t.Fatal("wrong UDP state")
			}
			sess := session.New(client, "127.0.0.1", false, false, nil)
			if err := sess.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			if transport == "udp" && (client.ReadSize > 4096 || client.WriteSize > 4096) {
				t.Fatal("FSINFO exceeded UDP transfer cap")
			}
			if version != "3" && os.Getenv("NFS_VIEWER_TEST_IDLE") == "1" {
				// The committed fixture uses a six-second lease. Remain idle
				// longer than that, then exercise OPEN and all transfer operations.
				select {
				case <-time.After(8 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			name := fmt.Sprintf("test-%s-%d", version, time.Now().UnixNano())
			if _, err := client.Create(ctx, sess.Root.Handle, name, 0755, true); err != nil {
				t.Fatal(err)
			}
			if err := sess.CD(ctx, name); err != nil {
				t.Fatal(err)
			}
			if version != "3" {
				child, _, err := sess.Resolve(ctx, ".", true)
				if err != nil {
					t.Fatal(err)
				}
				parent, err := client.Lookup(ctx, child.Handle, "..")
				if err != nil || session.RootObjectID(parent) != session.RootObjectID(sess.Root) {
					t.Fatalf("LOOKUPP: %+v %v", parent, err)
				}
			}
			if report, err := sess.VerifyRoot(ctx); err != nil || report == nil || len(report.Checks) != 4 || sess.CWD != "/"+name {
				t.Fatalf("root verification: %+v %v, cwd %q", report, err, sess.CWD)
			}
			if err := sess.SelectRoot(ctx, false); err != nil || sess.CWD != "/" || sess.RootVerification != nil {
				t.Fatalf("root reset: %v", err)
			}
			if err := sess.CD(ctx, name); err != nil {
				t.Fatal(err)
			}
			local := filepath.Join(t.TempDir(), "source")
			download := local + ".get"
			payload := bytes.Repeat([]byte("binary\x00\xff\x1b[31m\n"), 3000)
			if err := os.WriteFile(local, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if n, err := sess.Put(ctx, local, "payload.bin"); err != nil || n != int64(len(payload)) {
				t.Fatalf("put: %d %v", n, err)
			}
			if _, err := sess.Put(ctx, local, "payload.bin"); err == nil {
				t.Fatal("upload collision accepted")
			}
			if n, err := sess.Get(ctx, "payload.bin", download); err != nil || n != int64(len(payload)) {
				t.Fatalf("get: %d %v", n, err)
			}
			data, err := os.ReadFile(download)
			if err != nil || !bytes.Equal(data, payload) {
				t.Fatalf("round trip changed bytes (%d): %v", len(data), err)
			}
			if err := os.WriteFile(local, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			var contents bytes.Buffer
			if version != "3" {
				// FSAL_MEM exposes no ACL; replacement must refuse without changing bytes.
				const refusal = "NFSv4 ACL-preserving replacement refused: server does not expose required attribute 12"
				if n, err := sess.PutWithOptions(ctx, local, "payload.bin", session.TransferOptions{Overwrite: true}); n != 0 || err == nil || err.Error() != refusal {
					t.Fatalf("MEM ACL refusal: %d %v", n, err)
				}
			} else {
				if n, err := sess.PutWithOptions(ctx, local, "payload.bin", session.TransferOptions{Overwrite: true}); n != 0 || !errors.Is(err, nfs.ErrLegacyReplacementUnsupported) {
					t.Fatalf("legacy ACL refusal: %d %v", n, err)
				}
			}
			if _, err := sess.Cat(ctx, "payload.bin", &contents); err != nil || !bytes.Equal(contents.Bytes(), payload) {
				t.Fatalf("ACL refusal changed original: %v", err)
			}
			n, _, err := sess.Resolve(ctx, "payload.bin", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Chmod(ctx, n.Handle, 0640); err != nil {
				t.Fatal(err)
			}
			entries, err := sess.LS(ctx, ".")
			if err != nil || len(entries) != 1 || entries[0].Attr.Mode&0777 != 0640 {
				t.Fatalf("ls/chmod: %+v %v", entries, err)
			}
			if err := os.WriteFile(local, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := sess.Put(ctx, local, "empty"); err != nil {
				t.Fatal(err)
			}
			contents.Reset()
			if _, err := sess.Cat(ctx, "empty", &contents); err != nil || contents.Len() != 0 {
				t.Fatalf("empty read: %v", err)
			}
		})
	}
}
