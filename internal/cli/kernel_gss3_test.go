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

// Only supported public combinations belong here. Protected UDP has a separate
// internal diagnostic; this suite never bypasses public security selection.
func kernelGSS3Profiles(t *testing.T, run func(*testing.T, nfs.Config)) {
	t.Helper()
	if os.Getenv("NFS_VIEWER_KERNEL_GSS_V3") != "1" {
		t.Skip("requires isolated kernel NFSv3/GSS fixture")
	}
	required := func(key string) string {
		t.Helper()
		v := os.Getenv("NFS_VIEWER_KERNEL_KRB5_" + key)
		if v == "" {
			t.Fatalf("missing explicit kernel Kerberos fixture setting %s", key)
		}
		return v
	}
	config, spn := required("CONFIG"), required("SPN")
	keytab, cache := required("ALICE_KEYTAB"), required("ALICE_CCACHE")
	required("BOB_KEYTAB")
	required("STRANGER_KEYTAB")
	for _, profile := range [][2]string{{"tcp", "krb5"}, {"tcp", "krb5i"}, {"tcp", "krb5p"}, {"udp", "krb5"}} {
		for _, credential := range []string{"keytab", "ccache"} {
			t.Run(profile[0]+"/"+profile[1]+"/"+credential, func(t *testing.T) {
				cfg := kernelConfig(t, "3", profile[0])
				cfg.Auth, cfg.Security = nfs.Auth{}, profile[1]
				cfg.Kerberos = nfs.KerberosConfig{ConfigFile: config, SPN: spn, Principal: "alice@NFS.TEST"}
				if credential == "ccache" {
					cfg.Kerberos.CCache = cache
				} else {
					cfg.Kerberos.Keytab = keytab
				}
				run(t, cfg)
			})
		}
	}
}

func TestKernelNFS3GSSBehavior(t *testing.T) {
	kernelGSS3Profiles(t, func(t *testing.T, cfg nfs.Config) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		connect := func(t *testing.T, config nfs.Config, export string) *session.Session {
			t.Helper()
			c, err := nfs.Connect(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			s := session.New(c, config.Host, false, false, nil)
			if err := s.Use(ctx, kernelExport("3", export)); err != nil {
				t.Fatal(err)
			}
			return s
		}
		alice := connect(t, cfg, "data")
		bob := connect(t, kernelACLIdentity(t, cfg, 20002), "data")
		stranger := connect(t, kernelACLIdentity(t, cfg, 20004), "data")
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
		name := fmt.Sprintf("gss3-%d", time.Now().UnixNano())
		if !t.Run("identity-mapping", func(t *testing.T) {
			for _, user := range []struct {
				name string
				uid  uint32
				s    *session.Session
			}{{"alice", 20001, alice}, {"bob", 20002, bob}, {"stranger", 20004, stranger}} {
				file := "gss3-identity-" + user.name + "-" + name
				n, err := user.s.Client.Create(ctx, user.s.Root.Handle, file, 0600, false)
				if err != nil {
					t.Fatal(err)
				}
				a, err := user.s.Client.GetAttr(ctx, n.Handle)
				if err != nil || a.UID != user.uid || a.GID != user.uid || a.Mode&0777 != 0600 || a.Size != 0 {
					t.Fatalf("numeric principal mapping: %+v %v", a, err)
				}
				if user.s.Client.Identity() != user.name+"@NFS.TEST ("+cfg.Security+")" {
					t.Fatal("identity changed")
				}
				t.Logf("GSS3_IDENTITY path=%s uid=%d gid=%d mode=%o size=%d", file, a.UID, a.GID, a.Mode&0777, a.Size)
			}
		}) {
			return
		}
		local := t.TempDir()
		src := filepath.Join(local, "source")
		payload := bytes.Repeat([]byte{0, 255, 27, 'N', 'F', 'S'}, 30000)
		if err := os.WriteFile(src, payload, 0600); err != nil {
			t.Fatal(err)
		}
		t.Run("listing-links-empty-binary", func(t *testing.T) {
			entries, err := alice.LS(ctx, "wide")
			if err != nil || len(entries) != 300 {
				t.Fatalf("listing: %d %v", len(entries), err)
			}
			for i, e := range entries {
				if e.Name != fmt.Sprintf("entry-%03d.txt", i) || e.Attr.Size != 12 || e.Attr.Type != 1 {
					t.Fatalf("entry %d: %+v", i, e)
				}
			}
			read(t, alice, "link.txt", []byte("kernel fixture\n"))
			if _, _, err := alice.Resolve(ctx, "dangling", true); !errors.Is(err, nfs.Status(2)) {
				t.Fatalf("dangling: %v", err)
			}
			empty := filepath.Join(local, "empty")
			if err := os.WriteFile(empty, nil, 0600); err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				source, remote string
				data           []byte
			}{{empty, name + "-empty", nil}, {src, name + "-binary", payload}} {
				if n, err := alice.Put(ctx, item.source, item.remote); err != nil || n != int64(len(item.data)) {
					t.Fatalf("put: %d %v", n, err)
				}
				dst := filepath.Join(t.TempDir(), "download")
				if n, err := alice.Get(ctx, item.remote, dst); err != nil || n != int64(len(item.data)) {
					t.Fatalf("get: %d %v", n, err)
				}
				if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, item.data) {
					t.Fatalf("download: %v", err)
				}
			}
		})
		t.Run("transfer-server-denials", func(t *testing.T) {
			file := name + "-private-file" // Parent remains searchable: pin ordinary ACCESS, not subtree ESTALE.
			if _, err := alice.Put(ctx, src, file); err != nil {
				t.Fatal(err)
			}
			if err := alice.Chmod(ctx, file, 0600); err != nil {
				t.Fatal(err)
			}
			n, _, err := alice.Resolve(ctx, file, true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := alice.Put(ctx, src, file); !errors.Is(err, session.ErrDestinationExists) {
				t.Fatalf("collision: %v", err)
			}
			dir := t.TempDir()
			_, err = bob.Get(ctx, file, filepath.Join(dir, "denied"))
			denied(t, err)
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("denied publication: %v %v", entries, err)
			}
			var out bytes.Buffer
			_, err = bob.Client.ReadTo(ctx, n.Handle, &out)
			denied(t, err)
			if out.Len() != 0 {
				t.Fatal("denied READ exposed bytes")
			}
			_, err = bob.Client.WriteFrom(ctx, n.Handle, strings.NewReader("forbidden"))
			denied(t, err)
			denied(t, bob.Client.Chmod(ctx, n.Handle, 0777))
			read(t, alice, file, payload)
			if err := alice.Chmod(ctx, file, 0644); err != nil {
				t.Fatal(err)
			}
			read(t, bob, file, payload)
			if bob.Client.Identity() != "bob@NFS.TEST ("+cfg.Security+")" {
				t.Fatal("denial changed identity")
			}
		})
		t.Run("namespace-denials", func(t *testing.T) {
			dir := name + "-private-dir"
			if err := alice.Mkdir(ctx, dir); err != nil {
				t.Fatal(err)
			}
			if err := alice.Chmod(ctx, dir, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := alice.Put(ctx, src, dir+"/file"); err != nil {
				t.Fatal(err)
			}
			parent, _, err := alice.Resolve(ctx, dir, true)
			if err != nil {
				t.Fatal(err)
			}
			for _, other := range []*session.Session{bob, stranger} {
				_, err := other.Put(ctx, src, dir+"/denied")
				denied(t, err)
				_, err = other.Client.Create(ctx, parent.Handle, "denied-direct", 0600, false)
				denied(t, err)
				denied(t, other.Client.Remove(ctx, parent.Handle, "file"))
				denied(t, other.Client.Rename(ctx, parent.Handle, "file", parent.Handle, "renamed"))
			}
			entries, err := alice.LS(ctx, dir)
			if err != nil || len(entries) != 1 || entries[0].Name != "file" {
				t.Fatalf("denied namespace changed: %v %v", entries, err)
			}
			read(t, alice, dir+"/file", payload)
		})
		t.Run("supplementary-group", func(t *testing.T) {
			parent, _, err := alice.Resolve(ctx, "gss-groups", true)
			if err != nil || parent.Attr.UID != 0 || parent.Attr.GID != 20003 || parent.Attr.Mode&07777 != 0770 {
				t.Fatalf("group policy: %+v %v", parent.Attr, err)
			}
			read(t, alice, "gss-groups/read.txt", []byte("gss supplementary fixture\n"))
			n, err := alice.Client.Create(ctx, parent.Handle, name, 0600, false)
			if err != nil {
				t.Fatal(err)
			}
			a, err := alice.Client.GetAttr(ctx, n.Handle)
			if err != nil || a.UID != 20001 || a.GID != 20001 {
				t.Fatalf("primary identity: %+v %v", a, err)
			}
			if _, err := alice.Put(ctx, src, "shared/"+name); err != nil {
				t.Fatal(err)
			}
			n, _, err = alice.Resolve(ctx, "shared/"+name, true)
			if err != nil || n.Attr.UID != 20001 || n.Attr.GID != 20003 {
				t.Fatalf("setgid inheritance: %+v %v", n.Attr, err)
			}
			for _, other := range []*session.Session{bob, stranger} {
				var out bytes.Buffer
				_, err = other.Cat(ctx, "gss-groups/read.txt", &out)
				denied(t, err)
				if out.Len() != 0 {
					t.Fatal("nonmember read exposed bytes")
				}
				_, err = other.Put(ctx, src, "shared/denied-"+name)
				denied(t, err)
				_, err = other.Client.Create(ctx, parent.Handle, "denied-"+name, 0600, false)
				denied(t, err)
			}
		})
		t.Run("staged-replacement-cancellation", func(t *testing.T) {
			// Keep the existing leaf name; legacy replacement now refuses before
			// staging even when this fixture currently has only mode permissions.
			dir := name + "-replacement"
			if err := alice.Mkdir(ctx, dir); err != nil {
				t.Fatal(err)
			}
			file := dir + "/file"
			if _, err := alice.Put(ctx, src, file); err != nil {
				t.Fatal(err)
			}
			if err := alice.Chmod(ctx, file, 0640); err != nil {
				t.Fatal(err)
			}
			replacement := filepath.Join(local, "replacement")
			if err := os.WriteFile(replacement, []byte("replacement\n"), 0600); err != nil {
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
			kernelLegacyReplacementRefusal(t, ctx, alice, replacement, file)
			denyRead()
			if err := alice.Chmod(ctx, file, 0644); err != nil {
				t.Fatal(err)
			}
			read(t, bob, file, payload)
			kernelLegacyReplacementRefusal(t, ctx, alice, replacement, file)
			read(t, bob, file, payload)
			newFile := dir + "/new-file"
			kernelNewDestinationOverwriteIntent(t, ctx, alice, replacement, newFile)
			read(t, alice, file, payload)
		})
		t.Run("read-only-export", func(t *testing.T) {
			ro := connect(t, cfg, "readonly")
			read(t, ro, "read.txt", []byte("read-only export\n"))
			_, err := ro.Put(ctx, src, name)
			for _, err := range []error{err, ro.Mkdir(ctx, name+"-dir"), ro.Chmod(ctx, "read.txt", 0777)} {
				if !errors.Is(err, nfs.Status(30)) {
					t.Fatalf("expected read-only filesystem: %v", err)
				}
			}
			read(t, ro, "read.txt", []byte("read-only export\n"))
		})
		t.Run("security-selection", func(t *testing.T) {
			sysCfg := cfg
			sysCfg.Security, sysCfg.Kerberos = "sys", nfs.KerberosConfig{}
			sysCfg.Auth = nfs.Auth{UID: 20001, GID: 20001, Groups: []uint32{20003}}
			c, err := nfs.Connect(ctx, sysCfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Mount(ctx, kernelExport("3", "data")); err == nil || !strings.Contains(err.Error(), "export does not allow AUTH_SYS") {
				t.Fatalf("GSS-only export selection: %v", err)
			}
			read(t, alice, "read.txt", []byte("kernel fixture\n"))
			if alice.Client.Identity() != "alice@NFS.TEST ("+cfg.Security+")" {
				t.Fatal("security selection changed identity")
			}
		})
	})
}

func TestKernelNFS3GSSCLI(t *testing.T) {
	kernelGSS3Profiles(t, func(t *testing.T, cfg nfs.Config) {
		run := func(uid uint32, commands ...string) (string, error) {
			args := []string{"127.0.0.1", "--nfs-version", "3", "--transport", cfg.Transport, "--nfs-port", strconv.Itoa(cfg.NFSPort), "--mount-port", strconv.Itoa(cfg.MountPort), "--export", kernelExport("3", "data"), "--auto-uid=false", "--auto-escape=false", "--color", "never", "--progress", "never", "--no-banner"}
			args = append(args, kernelKerberosArgs(kernelACLIdentity(t, cfg, uid))...)
			for _, command := range commands {
				args = append(args, "-c", command)
			}
			return runKerberosCLI(t, args)
		}
		src, dst := filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "download")
		payload := bytes.Repeat([]byte{0, 255, 27, 'C', 'L', 'I'}, 2000)
		if err := os.WriteFile(src, payload, 0600); err != nil {
			t.Fatal(err)
		}
		remote := fmt.Sprintf("gss3-cli-%d", time.Now().UnixNano())
		out, err := run(20001, "put "+strconv.Quote(src)+" "+remote, "chmod 600 "+remote, "get "+remote+" "+strconv.Quote(dst), "id")
		if err != nil || !strings.Contains(out, "alice@NFS.TEST ("+cfg.Security+")") || strings.Contains(out, "AUTH_SYS") {
			t.Fatalf("CLI owner: %v %s", err, out)
		}
		if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("CLI bytes: %v", err)
		}
		deniedDir := t.TempDir()
		out, err = run(20002, "get "+remote+" "+strconv.Quote(filepath.Join(deniedDir, "denied")))
		if err == nil || !strings.Contains(out+err.Error(), "permission denied") {
			t.Fatalf("CLI denial: %v %s", err, out)
		}
		if entries, err := os.ReadDir(deniedDir); err != nil || len(entries) != 0 {
			t.Fatalf("denied publication: %v %v", entries, err)
		}
		out, err = run(20001, "chmod 644 "+remote)
		if err != nil {
			t.Fatalf("CLI chmod: %v %s", err, out)
		}
		bobDst := filepath.Join(t.TempDir(), "download")
		out, err = run(20002, "get "+remote+" "+strconv.Quote(bobDst), "id")
		if err != nil || !strings.Contains(out, "bob@NFS.TEST ("+cfg.Security+")") || strings.Contains(out, "AUTH_SYS") {
			t.Fatalf("CLI post-denial identity: %v %s", err, out)
		}
		if got, err := os.ReadFile(bobDst); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("CLI granted bytes: %v", err)
		}
	})
}
