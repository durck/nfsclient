package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

// These groups come from server-local NSS, not a PAC or client-supplied IDs.
func TestKernelNFSGSSGroups(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KERNEL_GSS_GROUPS") != "1" {
		t.Skip("requires explicit kernel GSS supplementary-group fixture")
	}
	kernelKerberosProfiles(t, func(t *testing.T, cfg nfs.Config) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		connect := func(uid uint32) *session.Session {
			config := kernelACLIdentity(t, cfg, uid)
			c, err := nfs.Connect(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			s := session.New(c, config.Host, false, false, nil)
			if err := s.Use(ctx, "/data"); err != nil {
				t.Fatal(err)
			}
			return s
		}
		alice, bob, stranger := connect(20001), connect(20002), connect(20004)
		denied := func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nfs.Status(13)) && !errors.Is(err, nfs.Status(1)) {
				t.Fatalf("expected server permission denial, got %v", err)
			}
		}
		const payload = "gss supplementary fixture\n"
		const directory = "gss-groups"
		const remote = directory + "/read.txt"
		t.Run("api-group-policy", func(t *testing.T) {
			parent, _, err := alice.Resolve(ctx, directory, true)
			if err != nil || parent.Attr.Owner != "root@nfs.test" || parent.Attr.Group != "nfsshared@nfs.test" || parent.Attr.Mode&07777 != 0770 {
				t.Fatalf("group directory policy: %+v %v", parent.Attr, err)
			}
			file, _, err := alice.Resolve(ctx, remote, true)
			if err != nil || file.Attr.Owner != "root@nfs.test" || file.Attr.Group != "nfsshared@nfs.test" || file.Attr.Mode&0777 != 0640 {
				t.Fatalf("group file policy: %+v %v", file.Attr, err)
			}
			var out bytes.Buffer
			if _, err := alice.Cat(ctx, remote, &out); err != nil || out.String() != payload {
				t.Fatalf("supplementary group grant: %q %v", out.String(), err)
			}
			const readAccess, writeAccess = uint32(1), uint32(4 | 8)
			access, err := alice.Client.Access(ctx, file.Handle)
			if err != nil || access&readAccess == 0 || access&writeAccess != 0 {
				t.Fatalf("supplementary group ACCESS grant: %#x %v", access, err)
			}
			_, err = alice.Client.WriteFrom(ctx, file.Handle, strings.NewReader("forbidden"))
			denied(t, err)
			denied(t, alice.Chmod(ctx, remote, 0666))
			name := fmt.Sprintf("gss-group-alice-%d", time.Now().UnixNano())
			created, err := alice.Client.Create(ctx, parent.Handle, name, 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			attr, err := alice.Client.GetAttr(ctx, created.Handle)
			if err != nil || attr.Owner != "alice@nfs.test" || attr.Group != "alice@nfs.test" || attr.Mode&0777 != 0600 || attr.Size != 0 {
				t.Fatalf("supplementary group must not replace primary identity: %+v %v", attr, err)
			}
			t.Logf("GSS_GROUP_FILE path=%s/%s owner=%s group=%s", directory, name, attr.Owner, attr.Group)
			for i, other := range []*session.Session{bob, stranger} {
				out.Reset()
				_, err := other.Cat(ctx, remote, &out)
				denied(t, err)
				if out.Len() != 0 {
					t.Fatal("denied path read exposed bytes")
				}
				// ACCESS and SETATTR accept a known handle without this client's
				// parent/name cache. ReadTo/WriteFrom require that cache for OPEN.
				// Linux subtree_check rejects a file whose ancestor cannot be
				// searched as ESTALE during handle decoding, before either op.
				// Keep this exact fixture result separate from permission errors.
				unusable := func(operation string, err error) {
					t.Helper()
					if !errors.Is(err, nfs.Status(70)) {
						t.Fatalf("expected subtree handle rejection for %s, got %v", operation, err)
					}
					t.Logf("GSS_GROUP_HANDLE operation=%s principal=%s status=70", operation, other.Client.Identity())
				}
				_, err = other.Client.Access(ctx, file.Handle)
				unusable("ACCESS", err)
				unusable("SETATTR", other.Client.Chmod(ctx, file.Handle, 0666))
				_, err = other.Client.Create(ctx, parent.Handle, fmt.Sprintf("denied-%s-%d", name, i), 0600, false)
				denied(t, err)
				denied(t, other.Client.Remove(ctx, parent.Handle, "read.txt"))
			}
			// The same handle must remain valid to the authorized identity:
			// ESTALE above must not be explained by an actually removed file.
			after, err := alice.Client.GetAttr(ctx, file.Handle)
			if err != nil || after.FileID != file.Attr.FileID || after.Owner != file.Attr.Owner || after.Group != file.Attr.Group || after.Mode != file.Attr.Mode || after.Size != file.Attr.Size {
				t.Fatalf("borrowed-handle probes changed the original: %+v %v", after, err)
			}
			out.Reset()
			if _, err := alice.Cat(ctx, remote, &out); err != nil || out.String() != payload {
				t.Fatalf("denials changed source: %q %v", out.String(), err)
			}
		})
		t.Run("cli-group-publication", func(t *testing.T) {
			run := func(uid uint32, commands ...string) (string, error) {
				args := []string{"127.0.0.1", "--nfs-version", cfg.Version, "--transport", "tcp",
					"--nfs-port", strconv.Itoa(cfg.NFSPort), "--mount-port", strconv.Itoa(cfg.MountPort),
					"--export", "/data", "--auto-uid=false", "--auto-escape=false", "--color", "never",
					"--progress", "never", "--no-banner"}
				args = append(args, kernelKerberosArgs(kernelACLIdentity(t, cfg, uid))...)
				for _, command := range commands {
					args = append(args, "-c", command)
				}
				return runKerberosCLI(t, args)
			}
			local := t.TempDir()
			download := filepath.Join(local, "download")
			out, err := run(20001, "get "+remote+" "+strconv.Quote(download), "id")
			if err != nil || !strings.Contains(out, "alice@NFS.TEST ("+cfg.Security+")") || strings.Contains(out, "AUTH_SYS") {
				t.Fatalf("CLI group read/identity: %v %s", err, out)
			}
			got, err := os.ReadFile(download)
			if err != nil || string(got) != payload {
				t.Fatalf("CLI group bytes: %q %v", got, err)
			}
			upload := fmt.Sprintf("%s/gss-cli-alice-%d", directory, time.Now().UnixNano())
			out, err = run(20001, "put "+strconv.Quote(download)+" "+upload)
			if err != nil {
				t.Fatalf("CLI group create: %v %s", err, out)
			}
			var content bytes.Buffer
			if _, err := alice.Cat(ctx, upload, &content); err != nil || content.String() != payload {
				t.Fatalf("CLI upload bytes: %q %v", content.String(), err)
			}
			blocked := t.TempDir()
			out, err = run(20002, "get "+remote+" "+strconv.Quote(filepath.Join(blocked, "download")))
			if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
				t.Fatalf("CLI denied group read: %v %s", err, out)
			}
			entries, err := os.ReadDir(blocked)
			if err != nil || len(entries) != 0 {
				t.Fatalf("denied group read left local entries: %v %v", entries, err)
			}
			out, err = run(20002, "put "+strconv.Quote(download)+" "+upload+"-denied")
			if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
				t.Fatalf("CLI denied group create: %v %s", err, out)
			}
			remoteEntries, err := alice.LS(ctx, directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range remoteEntries {
				if strings.HasPrefix(entry.Name, ".nfs-upload-") || strings.Contains(entry.Name, "-denied") || strings.HasPrefix(entry.Name, "denied-") {
					t.Fatalf("denied group operation left remote entry: %s", entry.Name)
				}
			}
		})
		for i, s := range []*session.Session{alice, bob, stranger} {
			principal := []string{"alice", "bob", "stranger"}[i] + "@NFS.TEST"
			if s.Client.Security() != cfg.Security || s.Client.Identity() != principal+" ("+cfg.Security+")" {
				t.Fatal("group operation changed GSS identity/protection")
			}
		}
	})
}
