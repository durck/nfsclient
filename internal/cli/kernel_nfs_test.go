package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// This opt-in suite is transferred into the disposable Linux VM. It never
// reaches a user-supplied host or mounts NFS with the operating system.
func kernelConfig(t *testing.T, version, transport string) nfs.Config {
	t.Helper()
	if os.Getenv("NFS_VIEWER_KERNEL") != "1" {
		t.Skip("requires isolated tests/microsoft-ad kernel-NFS fixture")
	}
	port := func(key string) int {
		n, err := strconv.Atoi(os.Getenv("NFS_VIEWER_KERNEL_" + key))
		if err != nil || n < 1 || n > 65535 {
			t.Fatalf("invalid kernel fixture port %s", key)
		}
		return n
	}
	return nfs.Config{Host: "127.0.0.1", Version: version, Transport: transport,
		NFSPort: port("PORT"), MountPort: port("MOUNT_PORT"), Timeout: 4 * time.Second,
		Auth: nfs.Auth{UID: 20001, GID: 20001, Groups: []uint32{20003}}}
}

func kernelExport(version, name string) string {
	if version == "3" {
		return "/srv/nfs-viewer-kernel/" + name
	}
	return "/" + name
}

func kernelProfiles(t *testing.T, run func(*testing.T, nfs.Config)) {
	for _, profile := range [][2]string{{"3", "tcp"}, {"3", "udp"}, {"4.0", "tcp"}, {"4.1", "tcp"}, {"4.2", "tcp"}} {
		t.Run(profile[0]+"/"+profile[1], func(t *testing.T) { run(t, kernelConfig(t, profile[0], profile[1])) })
	}
}

// A refused legacy replacement must leave both the object and its parent
// unchanged. The initial zero-byte progress notification is allowed.
func kernelLegacyReplacementRefusal(t *testing.T, ctx context.Context, s *session.Session, source, remote string) {
	t.Helper()
	var beforeData bytes.Buffer
	if n, err := s.Cat(ctx, remote, &beforeData); err != nil || n != int64(beforeData.Len()) {
		t.Fatalf("read before replacement refusal: %d %v", n, err)
	}
	before, _, err := s.Resolve(ctx, remote, true)
	if err != nil {
		t.Fatal(err)
	}
	parentPath := path.Dir(remote)
	parent, _, err := s.Resolve(ctx, parentPath, true)
	if err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := s.LS(ctx, parentPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeParent, err := s.Client.GetAttr(ctx, parent.Handle)
	if err != nil {
		t.Fatal(err)
	}
	var progressed uint64
	written, err := s.PutWithOptions(ctx, source, remote, session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
		if done > progressed {
			progressed = done
		}
	}})
	if written != 0 || progressed != 0 || !errors.Is(err, nfs.ErrLegacyReplacementUnsupported) || !strings.HasPrefix(err.Error(), "NFSv2/v3 ACL-preserving replacement refused") {
		t.Fatalf("legacy replacement refusal: written=%d progress=%d error=%v", written, progressed, err)
	}
	after, _, err := s.Resolve(ctx, remote, true)
	if err != nil || !bytes.Equal(before.Handle, after.Handle) || !reflect.DeepEqual(before.Attr, after.Attr) {
		t.Fatalf("refused replacement changed object: before=%+v after=%+v handle_equal=%t error=%v", before.Attr, after.Attr, bytes.Equal(before.Handle, after.Handle), err)
	}
	afterParent, err := s.Client.GetAttr(ctx, parent.Handle)
	if err != nil || !reflect.DeepEqual(beforeParent, afterParent) {
		t.Fatalf("refused replacement changed parent metadata: before=%+v after=%+v error=%v", beforeParent, afterParent, err)
	}
	afterEntries, err := s.LS(ctx, parentPath)
	if err != nil || !reflect.DeepEqual(beforeEntries, afterEntries) {
		t.Fatalf("refused replacement changed namespace: before=%v after=%v error=%v", beforeEntries, afterEntries, err)
	}
	for _, entry := range afterEntries {
		if strings.HasPrefix(entry.Name, ".nfs-upload-") {
			t.Fatalf("refused replacement left staging: %s", entry.Name)
		}
	}
	var afterData bytes.Buffer
	if n, err := s.Cat(ctx, remote, &afterData); err != nil || n != int64(beforeData.Len()) || !bytes.Equal(beforeData.Bytes(), afterData.Bytes()) {
		t.Fatalf("refused replacement changed bytes: %d %v", n, err)
	}
}

func kernelNewDestinationOverwriteIntent(t *testing.T, ctx context.Context, s *session.Session, source, remote string) {
	t.Helper()
	want, err := os.ReadFile(source)
	if err != nil || len(want) == 0 {
		t.Fatalf("new-destination fixture needs nonempty bytes: %v", err)
	}
	observed := false
	written, err := s.PutWithOptions(ctx, source, remote, session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
		if done == 0 || observed {
			return
		}
		entries, err := s.LS(ctx, path.Dir(remote))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name, ".nfs-upload-") {
				t.Fatalf("new destination used replacement staging: %s", entry.Name)
			}
			if entry.Name == path.Base(remote) && entry.Attr.Type == 1 {
				observed = true
			}
		}
		if !observed {
			t.Fatal("new destination was not created under its requested name before progress")
		}
	}})
	if err != nil || written != int64(len(want)) || !observed {
		t.Fatalf("overwrite intent for new destination: written=%d observed=%t error=%v", written, observed, err)
	}
	var got bytes.Buffer
	if n, err := s.Cat(ctx, remote, &got); err != nil || n != int64(len(want)) || !bytes.Equal(want, got.Bytes()) {
		t.Fatalf("new destination bytes: %d %v", n, err)
	}
}

func TestKernelNFSBehavior(t *testing.T) {
	kernelProfiles(t, func(t *testing.T, cfg nfs.Config) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		connect := func(t *testing.T, config nfs.Config, export string) *session.Session {
			t.Helper()
			c, err := nfs.Connect(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			s := session.New(c, config.Host, false, false, nil)
			if err := s.Use(ctx, kernelExport(cfg.Version, export)); err != nil {
				t.Fatal(err)
			}
			return s
		}
		alice := connect(t, cfg, "data")
		bobCfg := cfg
		bobCfg.Auth = nfs.Auth{UID: 20002, GID: 20002}
		bob := connect(t, bobCfg, "data")
		denied := func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, nfs.Status(13)) && !errors.Is(err, nfs.Status(1)) {
				t.Fatalf("expected server permission denial, got %v", err)
			}
		}
		read := func(t *testing.T, s *session.Session, path string, want []byte) {
			t.Helper()
			var b bytes.Buffer
			if n, err := s.Cat(ctx, path, &b); err != nil || n != int64(len(want)) || !bytes.Equal(b.Bytes(), want) {
				t.Fatalf("read %s: %d %v", path, n, err)
			}
		}
		name := fmt.Sprintf("kernel-%d", time.Now().UnixNano())
		local := t.TempDir()
		src, dst := filepath.Join(local, "source"), filepath.Join(local, "download")
		payload := bytes.Repeat([]byte{0, 255, 27, 'N', 'F', 'S'}, 30000)
		if err := os.WriteFile(src, payload, 0600); err != nil {
			t.Fatal(err)
		}
		t.Run("listing-and-links", func(t *testing.T) {
			entries, err := alice.LS(ctx, "wide")
			if err != nil || len(entries) != 300 {
				t.Fatalf("paged listing: %d %v", len(entries), err)
			}
			for i, e := range entries {
				if e.Name != fmt.Sprintf("entry-%03d.txt", i) || e.Attr.Type != 1 || e.Attr.Size != 12 {
					t.Fatalf("entry %d: %+v", i, e)
				}
			}
			read(t, alice, "link.txt", []byte("kernel fixture\n"))
			if _, _, err := alice.Resolve(ctx, "dangling", true); !errors.Is(err, nfs.Status(2)) {
				t.Fatalf("dangling link: %v", err)
			}
		})
		if err := alice.Mkdir(ctx, name); err != nil {
			t.Fatal(err)
		}
		file := name + "/file"
		if _, err := alice.Put(ctx, src, file); err != nil {
			t.Fatal(err)
		}
		if err := alice.Chmod(ctx, file, 0600); err != nil {
			t.Fatal(err)
		}
		t.Run("transfer-and-server-denials", func(t *testing.T) {
			if n, err := alice.Get(ctx, file, dst); err != nil || n != int64(len(payload)) {
				t.Fatalf("get: %d %v", n, err)
			}
			if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("download differs: %v", err)
			}
			if _, err := alice.Put(ctx, src, file); !errors.Is(err, session.ErrDestinationExists) {
				t.Fatalf("collision: %v", err)
			}
			denyDst := filepath.Join(t.TempDir(), "denied")
			_, err := bob.Get(ctx, file, denyDst)
			denied(t, err)
			if entries, err := os.ReadDir(filepath.Dir(denyDst)); err != nil || len(entries) != 0 {
				t.Fatalf("denied get left files: %v %v", entries, err)
			}
			_, err = bob.Put(ctx, src, name+"/forbidden")
			denied(t, err)
			denied(t, bob.Chmod(ctx, file, 0777))
			entries, err := alice.LS(ctx, name)
			if err != nil || len(entries) != 1 {
				t.Fatalf("denials changed namespace: %v %v", entries, err)
			}
			read(t, alice, file, payload)
			if err := alice.Chmod(ctx, file, 0644); err != nil {
				t.Fatal(err)
			}
			read(t, bob, file, payload)
		})
		t.Run("staged-replacement", func(t *testing.T) {
			if err := alice.Chmod(ctx, file, 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(src, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			if cfg.Version == "2" || cfg.Version == "3" {
				read(t, bob, file, payload)
				kernelLegacyReplacementRefusal(t, ctx, alice, src, file)
				read(t, bob, file, payload)
				if err := alice.Chmod(ctx, file, 0600); err != nil {
					t.Fatal(err)
				}
				denyRead := func() {
					var out bytes.Buffer
					n, err := bob.Cat(ctx, file, &out)
					denied(t, err)
					if n != 0 || out.Len() != 0 {
						t.Fatal("denied replacement read exposed bytes")
					}
				}
				denyRead()
				kernelLegacyReplacementRefusal(t, ctx, alice, src, file)
				denyRead()
				newFile := name + "/new-file"
				kernelNewDestinationOverwriteIntent(t, ctx, alice, src, newFile)
				read(t, alice, file, payload)
				return
			}
			cancelCtx, stop := context.WithCancel(ctx)
			_, err := alice.PutWithOptions(cancelCtx, src, file, session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
				if done > 0 {
					stop()
				}
			}})
			stop()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			read(t, alice, file, payload)
			if entries, err := alice.LS(ctx, name); err != nil || len(entries) != 1 {
				t.Fatalf("staging leaked: %v %v", entries, err)
			}
			if _, err := alice.PutWithOptions(ctx, src, file, session.TransferOptions{Overwrite: true}); err != nil {
				t.Fatal(err)
			}
			read(t, alice, file, []byte("replacement"))
			entries, err := alice.LS(ctx, name)
			if err != nil || len(entries) != 1 || entries[0].Attr.Mode&0777 != 0644 {
				t.Fatalf("replacement mode/namespace: %v %v", entries, err)
			}
			kernelNewDestinationOverwriteIntent(t, ctx, alice, src, name+"/new-file")
			read(t, alice, file, []byte("replacement"))
		})
		t.Run("supplementary-group", func(t *testing.T) {
			if _, err := alice.Put(ctx, src, "shared/"+name); err != nil {
				t.Fatal(err)
			}
			n, _, err := alice.Resolve(ctx, "shared/"+name, true)
			if err != nil || n.Attr.UID != 20001 || n.Attr.GID != 20003 {
				t.Fatalf("setgid owner: %+v %v", n.Attr, err)
			}
			noGroupCfg := cfg
			noGroupCfg.Auth.Groups = nil
			noGroup := connect(t, noGroupCfg, "data")
			_, err = noGroup.Put(ctx, src, "shared/denied-"+name)
			denied(t, err)
		})
		t.Run("root-squash", func(t *testing.T) {
			rootCfg := cfg
			rootCfg.Auth = nfs.Auth{}
			s := connect(t, rootCfg, "squashed")
			if _, _, err := s.Resolve(ctx, "private/file", true); err == nil {
				t.Fatal("root squash allowed private traversal")
			} else {
				denied(t, err)
			}
			if _, err := s.Put(ctx, src, name); err != nil {
				t.Fatal(err)
			}
			n, _, err := s.Resolve(ctx, name, true)
			if err != nil || n.Attr.UID != 65534 || n.Attr.GID != 65534 {
				t.Fatalf("squash ownership: %+v %v", n.Attr, err)
			}
		})
		t.Run("read-only-export", func(t *testing.T) {
			s := connect(t, cfg, "readonly")
			read(t, s, "read.txt", []byte("read-only export\n"))
			if _, err := s.Put(ctx, src, name); !errors.Is(err, nfs.Status(30)) {
				t.Fatalf("read-only create: %v", err)
			}
		})
		t.Run("reserved-source-port", func(t *testing.T) {
			c, err := nfs.Connect(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_, err = c.Mount(ctx, kernelExport(cfg.Version, "secure"))
			denied(t, err)
			reservedCfg := cfg
			reservedCfg.ReservedPort = true
			s := connect(t, reservedCfg, "secure")
			if _, err := s.Put(ctx, src, name); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("root-observations", func(t *testing.T) {
			if err := alice.CD(ctx, name); err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), alice.Root.Handle...)
			auth := alice.Client.Auth
			r, err := alice.VerifyRoot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if alice.CWD != "/"+name || !bytes.Equal(original, alice.Root.Handle) || !reflect.DeepEqual(auth, alice.Client.Auth) {
				t.Fatal("verification changed navigation or identity")
			}
			t.Logf("original=%s checks=%+v", session.RootObjectID(alice.Root), r.Checks)
			if cfg.Version == "3" {
				found, err := alice.Escape(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("probe found=%t attempts=%d selected=%s", found, alice.DiscoveryAttempts, session.RootObjectID(alice.Root))
				if found {
					discovered := append([]byte(nil), alice.Root.Handle...)
					if _, err := alice.VerifyRoot(ctx); err != nil {
						t.Fatal(err)
					}
					if err := alice.SelectRoot(ctx, false); err != nil {
						t.Fatal(err)
					}
					if err := alice.SelectRoot(ctx, true); err != nil || !bytes.Equal(discovered, alice.Root.Handle) {
						t.Fatalf("select saved: %v", err)
					}
				}
			}
			if err := alice.SelectRoot(ctx, false); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, alice.Root.Handle) || alice.CWD != "/" || alice.Escaped || !reflect.DeepEqual(auth, alice.Client.Auth) {
				t.Fatal("reset failed")
			}
		})
	})
}

func TestKernelNFSCLI(t *testing.T) {
	kernelProfiles(t, func(t *testing.T, cfg nfs.Config) {
		base := []string{"127.0.0.1", "--nfs-version", cfg.Version, "--transport", cfg.Transport, "--nfs-port", strconv.Itoa(cfg.NFSPort), "--mount-port", strconv.Itoa(cfg.MountPort), "--export", kernelExport(cfg.Version, "data"), "--auto-uid=false", "--auto-escape=false", "--uid", "20001", "--gid", "20001", "--groups", "20003", "--no-banner", "--color", "never", "--progress", "never", "--timeout", "4s"}
		run := func(commands ...string) (string, error) {
			args := append([]string(nil), base...)
			for _, c := range commands {
				args = append(args, "-c", c)
			}
			return runKerberosCLI(t, args)
		}
		dir := t.TempDir()
		src, dst, empty, emptyDst := filepath.Join(dir, "src"), filepath.Join(dir, "dst"), filepath.Join(dir, "empty"), filepath.Join(dir, "empty-dst")
		payload := bytes.Repeat([]byte{0, 255, 27, 'k'}, 25000)
		if err := os.WriteFile(src, payload, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(empty, nil, 0600); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("cli-kernel-%d", time.Now().UnixNano())
		out, err := run("mkdir "+name, "put "+strconv.Quote(src)+" "+name+"/file", "get "+name+"/file "+strconv.Quote(dst), "put "+strconv.Quote(empty)+" "+name+"/empty", "get "+name+"/empty "+strconv.Quote(emptyDst), "cat link.txt", "root verify", "root reset", "id")
		if err != nil || !strings.Contains(out, "kernel fixture") || !strings.Contains(out, "Unverified; requires independent server-side confirmation") {
			t.Fatalf("CLI flow: %v %s", err, out)
		}
		if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("download differs: %v", err)
		}
		if got, err := os.ReadFile(emptyDst); err != nil || len(got) != 0 {
			t.Fatalf("empty download: %v", err)
		}
	})
}
