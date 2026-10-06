package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// Real Linux POSIX ACL policy checks; numeric identities are deliberately not
// domain identities. The runner retains getfacl evidence independently.
func TestKernelNFSPOSIXACL(t *testing.T) {
	kernelProfiles(t, kernelACLBehavior)
}

func kernelACLBehavior(t *testing.T, cfg nfs.Config) {
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
		if err := s.Use(ctx, kernelExport(cfg.Version, "data")); err != nil {
			t.Fatal(err)
		}
		return s
	}
	alice, bob, stranger := connect(20001), connect(20002), connect(20004)
	if cfg.Security != "" && cfg.Security != "sys" {
		if !t.Run("kerberos-principal-mapping", func(t *testing.T) {
			for i, s := range []*session.Session{alice, bob, stranger} {
				user := []string{"alice", "bob", "stranger"}[i]
				root, _, err := s.Resolve(ctx, "/", true)
				if err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("gss-identity-%s-%d", user, time.Now().UnixNano())
				n, err := s.Client.Create(ctx, root.Handle, name, 0600, false)
				if err != nil {
					t.Fatalf("mapping proof create for %s: %v", user, err)
				}
				a, err := s.Client.GetAttr(ctx, n.Handle)
				if err != nil || a.Owner != user+"@nfs.test" || a.Group != user+"@nfs.test" || a.Mode&0777 != 0600 {
					t.Fatalf("mapping proof for %s: %+v %v", user, a, err)
				}
				// Retain these empty fixture files for independent numeric stat.
				t.Logf("GSS_IDENTITY path=%s principal=%s owner=%s group=%s", name, s.Client.Identity(), a.Owner, a.Group)
			}
		}) {
			return
		}
	}
	read := func(t *testing.T, s *session.Session, path string, want string) {
		t.Helper()
		var out bytes.Buffer
		if n, err := s.Cat(ctx, path, &out); err != nil || n != int64(len(want)) || out.String() != want {
			t.Fatalf("read %s: %d %v %q", path, n, err, out.String())
		}
	}
	denied := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, nfs.Status(13)) && !errors.Is(err, nfs.Status(1)) {
			t.Fatalf("expected server denial, got %v", err)
		}
	}
	denyRead := func(t *testing.T, s *session.Session, path string) {
		t.Helper()
		var out bytes.Buffer
		_, err := s.Cat(ctx, path, &out)
		denied(t, err)
		if out.Len() != 0 {
			t.Fatal("denied read exposed bytes")
		}
	}
	create := func(t *testing.T, parent, name string, mode uint32, dir bool) string {
		t.Helper()
		p, _, err := alice.Resolve(ctx, parent, true)
		if err != nil {
			t.Fatal(err)
		}
		n, err := alice.Client.Create(ctx, p.Handle, name, mode, dir)
		if err != nil {
			t.Fatal(err)
		}
		if !dir {
			if _, err := alice.Client.WriteFrom(ctx, n.Handle, strings.NewReader("ACL payload\n")); err != nil {
				t.Fatal(err)
			}
		}
		return parent + "/" + name
	}
	move := func(t *testing.T, from, to, name string) {
		t.Helper()
		src, _, err := alice.Resolve(ctx, from, true)
		if err != nil {
			t.Fatal(err)
		}
		dst, _, err := alice.Resolve(ctx, to, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := alice.Client.Rename(ctx, src.Handle, name, dst.Handle, name); err != nil {
			t.Fatal(err)
		}
	}
	name := fmt.Sprintf("acl-%s-%s-%d", cfg.Version, cfg.Transport, time.Now().UnixNano())
	t.Run("named-user-grant-and-denials", func(t *testing.T) {
		read(t, bob, "acl/grant/read.txt", "acl grant fixture\n")
		denyRead(t, stranger, "acl/grant/read.txt")
		denied(t, bob.Mkdir(ctx, "acl/grant/"+name))
		n, _, err := bob.Resolve(ctx, "acl/grant/read.txt", true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = bob.Client.WriteFrom(ctx, n.Handle, strings.NewReader("forbidden"))
		denied(t, err)
		denied(t, bob.Chmod(ctx, "acl/grant/read.txt", 0666))
		p, _, err := bob.Resolve(ctx, "acl/grant", true)
		if err != nil {
			t.Fatal(err)
		}
		denied(t, bob.Client.Remove(ctx, p.Handle, "read.txt"))
		read(t, alice, "acl/grant/read.txt", "acl grant fixture\n")
	})
	t.Run("nested-default-and-mask", func(t *testing.T) {
		parent := create(t, "acl/inherit", name+"-nested", 0750, true)
		child := create(t, parent, "child", 0750, true)
		file := create(t, child, "file", 0640, false)
		read(t, bob, file, "ACL payload\n")
		denyRead(t, stranger, file)
		denied(t, bob.Mkdir(ctx, child+"/forbidden"))
		for _, mode := range []uint32{0600, 0640} {
			if err := alice.Chmod(ctx, file, mode); err != nil {
				t.Fatal(err)
			}
			if mode == 0600 {
				denyRead(t, bob, file)
			} else {
				read(t, bob, file, "ACL payload\n")
			}
		}
		read(t, alice, file, "ACL payload\n")
	})
	t.Run("restrictive-create", func(t *testing.T) {
		file := create(t, "acl/inherit", name+"-private", 0600, false)
		denyRead(t, bob, file)
		if err := alice.Chmod(ctx, file, 0640); err != nil {
			t.Fatal(err)
		}
		read(t, bob, file, "ACL payload\n")
		// Retain a masked named entry for the independent server-side snapshot.
		if err := alice.Chmod(ctx, file, 0600); err != nil {
			t.Fatal(err)
		}
		denyRead(t, bob, file)
	})
	t.Run("replacement-acl-diagnostic", func(t *testing.T) {
		source := filepath.Join(t.TempDir(), "replacement")
		if err := os.WriteFile(source, []byte("replacement\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, inherited := range []bool{true, false} {
			from, to, suffix := "acl/inherit", "acl/replace", "-grant-loss"
			if !inherited {
				from, to, suffix = to, from, "-grant-gain"
			}
			base := name + suffix
			create(t, from, base, 0640, false)
			move(t, from, to, base)
			file := to + "/" + base
			if inherited {
				read(t, bob, file, "ACL payload\n")
			} else {
				denyRead(t, bob, file)
			}
			if cfg.Version == "2" || cfg.Version == "3" {
				kernelLegacyReplacementRefusal(t, ctx, alice, source, file)
				read(t, alice, file, "ACL payload\n")
				if inherited {
					read(t, bob, file, "ACL payload\n")
				} else {
					denyRead(t, bob, file)
				}
				denyRead(t, stranger, file)
				t.Logf("ACL_REPLACEMENT_REFUSED path=%s bob_before=%t bob_after=%t mode=0640 bytes=0 progress=0", file, inherited, inherited)
				continue
			}
			cancelCtx, stop := context.WithCancel(ctx)
			_, err := alice.PutWithOptions(cancelCtx, source, file, session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
				if done > 0 {
					if cfg.Version != "3" {
						entries, e := bob.LS(ctx, to)
						if e != nil {
							t.Fatal(e)
						}
						found := false
						for _, entry := range entries {
							if strings.HasPrefix(entry.Name, ".nfs-upload-") {
								found = true
								denyRead(t, bob, to+"/"+entry.Name)
							}
						}
						if !found {
							t.Fatal("private staging observation did not see upload")
						}
					}
					stop()
				}
			}})
			stop()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel replacement: %v", err)
			}
			read(t, alice, file, "ACL payload\n")
			if inherited {
				read(t, bob, file, "ACL payload\n")
			} else {
				denyRead(t, bob, file)
			}
			if _, err := alice.PutWithOptions(ctx, source, file, session.TransferOptions{Overwrite: true}); err != nil {
				t.Fatal(err)
			}
			read(t, alice, file, "replacement\n")
			denyRead(t, stranger, file)
			n, _, err := alice.Resolve(ctx, file, true)
			if err != nil || n.Attr.Mode&0777 != 0640 {
				t.Fatalf("replacement mode: %+v %v", n.Attr, err)
			}
			var out bytes.Buffer
			_, err = bob.Cat(ctx, file, &out)
			if err != nil {
				denied(t, err)
				if out.Len() != 0 {
					t.Fatal("denied replacement read exposed bytes")
				}
			} else if out.String() != "replacement\n" {
				t.Fatalf("replacement content %q", out.String())
			}
			// Only NFSv4 reaches successful ACL-preserving replacement.
			t.Logf("ACL_REPLACEMENT path=%s bob_before=%t bob_after=%t mode=0640", file, inherited, err == nil)
			if (err == nil) != inherited {
				t.Fatal("NFSv4 replacement changed named-user access")
			}
			entries, err := alice.LS(ctx, to)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name, ".nfs-upload-") {
					t.Fatalf("staging leaked: %s", entry.Name)
				}
			}
		}
	})
	if cfg.Version != "3" {
		t.Run("replacement-staging-name-refusal", func(t *testing.T) {
			parent := create(t, "acl/inherit", name+"-stage-swap", 0700, true)
			file := create(t, parent, "target", 0600, false)
			source := filepath.Join(t.TempDir(), "replacement")
			if err := os.WriteFile(source, []byte("must not publish"), 0600); err != nil {
				t.Fatal(err)
			}
			var swapped string
			_, err := alice.PutWithOptions(ctx, source, file, session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
				if done == 0 || swapped != "" {
					return
				}
				entries, e := alice.LS(ctx, parent)
				if e != nil {
					t.Fatal(e)
				}
				p, _, e := alice.Resolve(ctx, parent, true)
				if e != nil {
					t.Fatal(e)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name, ".nfs-upload-") {
						swapped = entry.Name
						break
					}
				}
				if swapped == "" {
					t.Fatal("missing staging path")
				}
				if e := alice.Client.Rename(ctx, p.Handle, swapped, p.Handle, "moved-stage"); e != nil {
					t.Fatal(e)
				}
				create(t, parent, swapped, 0600, false)
			}})
			if swapped == "" || err == nil || !strings.Contains(err.Error(), "staging object changed") || !strings.Contains(err.Error(), "cleanup withheld") {
				t.Fatalf("stage binding: %v", err)
			}
			read(t, alice, file, "ACL payload\n")
			read(t, alice, parent+"/"+swapped, "ACL payload\n")
			p, _, e := alice.Resolve(ctx, parent, true)
			if e != nil {
				t.Fatal(e)
			}
			for _, leaf := range []string{swapped, "moved-stage"} {
				if e := alice.Client.Remove(ctx, p.Handle, leaf); e != nil {
					t.Fatal(e)
				}
			}
		})
		t.Run("replacement-owner-group-refusal", func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "replacement")
			if err := os.WriteFile(source, []byte("must not publish"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"owner", "group"} {
				file := "acl/mismatch/foreign-" + kind
				before, _, err := alice.Resolve(ctx, file, true)
				if err != nil {
					t.Fatal(err)
				}
				written, err := alice.PutWithOptions(ctx, source, file, session.TransferOptions{Overwrite: true})
				if written != 0 || err == nil || !strings.Contains(err.Error(), "staging owner/group differs") {
					t.Fatalf("mismatched %s: written=%d err=%v", kind, written, err)
				}
				read(t, alice, file, kind+" mismatch fixture\n")
				after, _, err := alice.Resolve(ctx, file, true)
				if err != nil || !bytes.Equal(before.Handle, after.Handle) || !reflect.DeepEqual(before.Attr, after.Attr) {
					t.Fatalf("refusal changed original metadata: %v", err)
				}
			}
			entries, err := alice.LS(ctx, "acl/mismatch")
			if err != nil || len(entries) != 2 {
				t.Fatalf("mismatch staging leak: %v %v", entries, err)
			}
		})
		t.Run("replacement-source-change-refusal", func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "replacement")
			if err := os.WriteFile(source, []byte("must not publish"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, renamed := range []bool{false, true} {
				base := fmt.Sprintf("%s-changed-%t", name, renamed)
				file := create(t, "acl/inherit", base, 0640, false)
				mutated := false
				_, err := alice.PutWithOptions(ctx, source, file, session.TransferOptions{Overwrite: true, Progress: func(done, total uint64) {
					if done == 0 || mutated {
						return
					}
					mutated = true
					if renamed {
						p, _, e := alice.Resolve(ctx, "acl/inherit", true)
						if e != nil {
							t.Fatal(e)
						}
						if e := alice.Client.Rename(ctx, p.Handle, base, p.Handle, base+"-old"); e != nil {
							t.Fatal(e)
						}
						create(t, "acl/inherit", base, 0640, false)
					} else if e := alice.Chmod(ctx, file, 0600); e != nil {
						t.Fatal(e)
					}
				}})
				if !mutated || err == nil || !strings.Contains(err.Error(), "changed before publication") {
					t.Fatalf("source guard renamed=%t: %v", renamed, err)
				}
				read(t, alice, file, "ACL payload\n")
				entries, e := alice.LS(ctx, "acl/inherit")
				if e != nil {
					t.Fatal(e)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name, ".nfs-upload-") {
						t.Fatal("changed-source staging leaked")
					}
				}
			}
		})
	}
	for i, s := range []*session.Session{alice, bob, stranger} {
		if cfg.Security != "" && cfg.Security != "sys" {
			principal := []string{"alice", "bob", "stranger"}[i] + "@NFS.TEST"
			if s.Client.Security() != cfg.Security || s.Client.Identity() != principal+" ("+cfg.Security+")" {
				t.Fatal("ACL operation changed GSS identity/protection")
			}
		}
	}
}

func TestKernelNFSACLCLI(t *testing.T) {
	kernelProfiles(t, kernelACLCLI)
}

func kernelACLCLI(t *testing.T, cfg nfs.Config) {
	run := func(uid string, commands ...string) (string, error) {
		args := []string{"127.0.0.1", "--nfs-version", cfg.Version, "--transport", cfg.Transport, "--nfs-port", strconv.Itoa(cfg.NFSPort), "--mount-port", strconv.Itoa(cfg.MountPort), "--export", kernelExport(cfg.Version, "data"), "--auto-uid=false", "--auto-escape=false", "--color", "never", "--progress", "never", "--no-banner"}
		if cfg.Security != "" && cfg.Security != "sys" {
			n, err := strconv.ParseUint(uid, 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, kernelKerberosArgs(kernelACLIdentity(t, cfg, uint32(n)))...)
		} else {
			args = append(args, "--uid", uid, "--gid", uid)
		}
		for _, command := range commands {
			args = append(args, "-c", command)
		}
		return runKerberosCLI(t, args)
	}
	src := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(src, []byte("CLI ACL payload\n"), 0600); err != nil {
		t.Fatal(err)
	}
	remote := fmt.Sprintf("acl/inherit/cli-%d", time.Now().UnixNano())
	out, err := run("20001", "mkdir "+remote, "mkdir "+remote+"/child", "put "+strconv.Quote(src)+" "+remote+"/child/file", "chmod 640 "+remote+"/child/file")
	if err != nil {
		t.Fatalf("CLI owner: %v %s", err, out)
	}
	for _, mode := range []string{"640", "600", "640"} {
		out, err = run("20001", "chmod "+mode+" "+remote+"/child/file")
		if err != nil {
			t.Fatalf("CLI chmod: %v %s", err, out)
		}
		dir := t.TempDir()
		dst := filepath.Join(dir, "download")
		out, err = run("20002", "get "+remote+"/child/file "+strconv.Quote(dst), "id")
		if mode == "600" {
			if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
				t.Fatalf("CLI masked read: %v %s", err, out)
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 0 {
				t.Fatalf("denied CLI left download/temp: %v %v", entries, e)
			}
		} else {
			identity := "UID 20002"
			if cfg.Security != "" && cfg.Security != "sys" {
				identity = "bob@NFS.TEST (" + cfg.Security + ")"
			}
			if err != nil || !strings.Contains(out, identity) || (cfg.Security != "" && cfg.Security != "sys" && strings.Contains(out, "AUTH_SYS")) {
				t.Fatalf("CLI named grant/identity: %v %s", err, out)
			}
			got, e := os.ReadFile(dst)
			if e != nil || string(got) != "CLI ACL payload\n" {
				t.Fatalf("CLI bytes: %q %v", got, e)
			}
		}
	}
}
