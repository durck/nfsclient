package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func msadTestHost(t *testing.T) string {
	t.Helper()
	host := os.Getenv("NFS_VIEWER_MSAD_NFS_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	if host != "127.0.0.1" && host != "192.0.2.20" {
		t.Fatal("only the isolated Microsoft AD fixture host is permitted")
	}
	t.Logf("MSAD_CLIENT os=%s arch=%s host=%s", runtime.GOOS, runtime.GOARCH, host)
	return host
}

// This independent lane uses the enrolled Microsoft AD guest, its existing
// nv-* keys and SSSD IDs. It must never enable the historical MIT cleanup lane.
func TestMicrosoftADNFS(t *testing.T) {
	if os.Getenv("NFS_VIEWER_MSAD_NFS") != "1" {
		t.Skip("requires the enrolled Microsoft AD interop fixture")
	}
	base := os.Getenv("NFS_VIEWER_MSAD_NFS_CREDENTIALS")
	if !filepath.IsAbs(base) {
		t.Fatal("explicit absolute credential directory required")
	}
	host := msadTestHost(t)
	var udpSize uint32
	if value := os.Getenv("NFS_VIEWER_MSAD_UDP_SIZE"); value != "" {
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || n < 512 || n > 4096 {
			t.Fatal("invalid fixture UDP size", err)
		}
		udpSize = uint32(n)
	}
	t.Logf("MSAD_UDP_SIZE bytes=%d (zero means default)", udpSize)
	profiles := [][2]string{{"3", "tcp"}, {"3", "udp"}, {"4.0", "tcp"}, {"4.1", "tcp"}, {"4.2", "tcp"}}
	for _, profile := range profiles {
		for _, sec := range []string{"krb5", "krb5i", "krb5p"} {
			for _, credential := range []string{"keytab", "ccache"} {
				t.Run(profile[0]+"/"+profile[1]+"/"+sec+"/"+credential, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					connect := func(user string) *session.Session {
						k := nfs.KerberosConfig{ConfigFile: filepath.Join(base, "krb5.conf"), Principal: user + "@MSAD.NFS.TEST", SPN: "nfs/nfs-interop.msad.nfs.test", Keytab: filepath.Join(base, user+".keytab")}
						if user == "nv-alice" && credential == "ccache" {
							k.Keytab = ""
							k.CCache = filepath.Join(base, user+".ccache")
						}
						cfg := nfs.Config{Host: host, Version: profile[0], Transport: profile[1], NFSPort: 2049, MountPort: 20048, Timeout: 5 * time.Second, Security: sec, Kerberos: k}
						if profile[1] == "udp" {
							cfg.UDPSize = udpSize
						}
						c, err := nfs.Connect(ctx, cfg)
						if err != nil {
							t.Fatal(err)
						}
						s := session.New(c, host, false, false, nil)
						t.Cleanup(func() { s.Client.Close() })
						export := "/"
						if profile[0] == "3" {
							export = "/srv/nfs-viewer-msad-interop"
						}
						if err := s.Use(ctx, export); err != nil {
							t.Fatal(err)
						}
						return s
					}
					alice, bob := connect("nv-alice"), connect("nv-bob")
					sh := &Shell{Session: alice, Out: io.Discard, Err: io.Discard, LocalDir: t.TempDir(), ProgressMode: "never"}
					var buf bytes.Buffer
					if _, err := alice.Cat(ctx, "readers.txt", &buf); err != nil || buf.String() != "domain-reader-seed\n" {
						t.Fatalf("domain supplementary group grant: %v", err)
					}
					buf.Reset()
					if _, err := bob.Cat(ctx, "readers.txt", &buf); !errors.Is(err, nfs.Status(13)) || buf.Len() != 0 {
						t.Fatalf("domain group denial: %v bytes=%d", err, buf.Len())
					}
					remote := fmt.Sprintf("data/%s-%s-%s-%s", profile[0], profile[1], sec, credential)
					local := filepath.Join(t.TempDir(), "source")
					payload := bytes.Repeat([]byte("Microsoft AD NFS binary\x00\n"), 32768)
					if err := os.WriteFile(local, payload, 0600); err != nil {
						t.Fatal(err)
					}
					if n, err := alice.Put(ctx, local, remote); err != nil || n != int64(len(payload)) {
						t.Fatalf("upload: %d %v", n, err)
					}
					node, _, err := alice.Resolve(ctx, remote, false)
					mapped := node.Attr.UID == 25001 && node.Attr.GID == 25000
					if profile[0] != "3" {
						mapped = node.Attr.Owner == "nv-alice@msad.nfs.test" && node.Attr.Group == "nviusers@msad.nfs.test"
					}
					if err != nil || !mapped {
						t.Fatalf("principal mapping: %+v %v", node.Attr, err)
					}
					if err := alice.Chmod(ctx, remote, 0600); err != nil {
						t.Fatal(err)
					}
					buf.Reset()
					if _, err := bob.Cat(ctx, remote, &buf); !errors.Is(err, nfs.Status(13)) || buf.Len() != 0 {
						t.Fatalf("private denial: %v", err)
					}
					if profile[0] == "3" {
						policy := &nfs.NFS3ACL{Attr: node.Attr, Access: []nfs.NFS3ACLEntry{
							{Tag: nfs.ACLUserObj, ID: 25001, Perm: 6}, {Tag: nfs.ACLUser, ID: 25002, Perm: 7},
							{Tag: nfs.ACLGroupObj, ID: 25000, Perm: 0}, {Tag: nfs.ACLMask, Perm: 4}, {Tag: nfs.ACLOther, Perm: 0},
						}}
						policy.Attr.Mode = 0640
						if err := alice.Client.SetNFS3ACL(ctx, node.Handle, policy); err != nil {
							t.Fatal(err)
						}
						payload = bytes.Repeat([]byte("replacement-with-hidden-ACL-rights\x00"), 32768)
						if err := os.WriteFile(local, payload, 0600); err != nil {
							t.Fatal(err)
						}
						if _, err := sh.Execute(ctx, fmt.Sprintf("replace %q %q", local, remote)); err != nil {
							t.Fatalf("ACL replacement: %v", err)
						}
						node, _, err = alice.Resolve(ctx, remote, false)
						if err != nil {
							t.Fatal(err)
						}
						preserved, err := alice.Client.GetNFS3ACL(ctx, node.Handle)
						if err != nil {
							t.Fatal(err)
						}
						found := false
						for _, ace := range preserved.Access {
							if ace.Tag == nfs.ACLUser && ace.ID == 25002 && ace.Perm == 7 {
								found = true
							}
						}
						if !found {
							t.Fatal("replacement lost masked-off named-user rights")
						}
						buf.Reset()
						if _, err := bob.Cat(ctx, remote, &buf); err != nil || !bytes.Equal(buf.Bytes(), payload) {
							t.Fatal("named-user grant after replacement", err)
						}
					}
					if _, err := sh.Execute(ctx, "reconnect"); err != nil {
						t.Fatal(err)
					}
					out := filepath.Join(t.TempDir(), "download")
					if err := os.WriteFile(out+".nfs-part", payload[:len(payload)/2], 0600); err != nil {
						t.Fatal(err)
					}
					if _, err := sh.Execute(ctx, fmt.Sprintf("reget %q %q", remote, out)); err != nil {
						t.Fatalf("download: %v", err)
					}
					got, err := os.ReadFile(out)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("payload mismatch", err)
					}
					if err := alice.Chmod(ctx, remote, 0640); err != nil {
						t.Fatal(err)
					}
					buf.Reset()
					if _, err := bob.Cat(ctx, remote, &buf); err != nil || !bytes.Equal(buf.Bytes(), payload) {
						t.Fatal("domain primary group grant", err)
					}
					if profile[0] == "4.1" && sec == "krb5p" && credential == "keytab" {
						source := filepath.Join(sh.LocalDir, "tree")
						if err := os.MkdirAll(filepath.Join(source, "sub", "empty"), 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(source, "sub", "binary"), payload, 0600); err != nil {
							t.Fatal(err)
						}
						for _, line := range []string{"puttree tree data/tree", "gettree data/tree tree-out"} {
							if _, err := sh.Execute(ctx, line); err != nil {
								t.Fatalf("%s: %v", line, err)
							}
						}
						got, err := os.ReadFile(filepath.Join(sh.LocalDir, "tree-out", "sub", "binary"))
						if err != nil || !bytes.Equal(got, payload) {
							t.Fatal("recursive payload mismatch", err)
						}
						if a, err := os.Stat(filepath.Join(sh.LocalDir, "tree-out", "sub", "empty")); err != nil || !a.IsDir() {
							t.Fatal("missing empty directory", err)
						}
					}
					t.Logf("MSAD_NFS principal=nv-alice@MSAD.NFS.TEST uid=25001 gid=25000 supplementary_gid=25003 bytes=%d", len(payload))
				})
			}
		}
	}
}
