package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// The explicit ACL-read fixture adds only an immutable masked file to the
// existing kernel ACL seeds. These tests issue no filesystem mutations.
func TestKernelNFSACLRead(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KERNEL_NFSACL") != "1" || os.Getenv("NFS_VIEWER_KERNEL") != "1" {
		t.Skip("requires isolated kernel NFSACL read fixture")
	}
	if os.Getenv("NFS_VIEWER_KERNEL_GSS_V3") == "1" {
		t.Run("gss", func(t *testing.T) { kernelGSS3Profiles(t, kernelNFSACLRead) })
		return
	}
	t.Run("sys", func(t *testing.T) {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(transport, func(t *testing.T) { kernelNFSACLRead(t, kernelConfig(t, "3", transport)) })
		}
	})
}

type kernelNFSACLSeed struct {
	path             string
	mode             uint32
	access, defaults []nfs.NFS3ACLEntry
	cli              []string
}

func kernelNFSACLEntries(owner, bob, mask uint32) []nfs.NFS3ACLEntry {
	return []nfs.NFS3ACLEntry{
		{Tag: nfs.ACLUserObj, ID: 20001, Perm: owner},
		{Tag: nfs.ACLUser, ID: 20002, Perm: bob},
		{Tag: nfs.ACLGroupObj, ID: 20001, Perm: 0},
		{Tag: nfs.ACLMask, ID: 0, Perm: mask},
		{Tag: nfs.ACLOther, ID: 0, Perm: 0},
	}
}

func kernelNFSACLRead(t *testing.T, cfg nfs.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connect := func(uid uint32) *session.Session {
		t.Helper()
		config := kernelACLIdentity(t, cfg, uid)
		c, err := nfs.Connect(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		s := session.New(c, config.Host, false, false, nil)
		if err := s.Use(ctx, kernelExport("3", "data")); err != nil {
			t.Fatal(err)
		}
		identity, auth := c.Identity(), c.Auth
		if cfg.Security != "" && cfg.Security != "sys" {
			user := map[uint32]string{20001: "alice", 20002: "bob", 20004: "stranger"}[uid]
			if identity != user+"@NFS.TEST ("+cfg.Security+")" {
				t.Fatalf("unexpected selected ACL identity: %s", identity)
			}
		}
		auth.Groups = append([]uint32(nil), auth.Groups...)
		t.Cleanup(func() {
			if c.Identity() != identity || !reflect.DeepEqual(c.Auth, auth) {
				t.Error("ACL reads changed the selected identity")
			}
		})
		return s
	}
	alice, bob, stranger := connect(20001), connect(20002), connect(20004)
	grant := kernelNFSACLSeed{path: "acl/grant/read.txt", mode: 0640, access: kernelNFSACLEntries(6, 4, 4),
		cli: []string{"user::rw-", "user:20002:r--", "group::---", "mask::r--", "other::---"}}
	inherit := kernelNFSACLSeed{path: "acl/inherit", mode: 0770, access: kernelNFSACLEntries(7, 7, 7), defaults: kernelNFSACLEntries(7, 7, 7),
		cli: []string{"user::rwx", "user:20002:rwx", "group::---", "mask::rwx", "other::---",
			"default:user::rwx", "default:user:20002:rwx", "default:group::---", "default:mask::rwx", "default:other::---"}}
	masked := kernelNFSACLSeed{path: "acl/inherit/masked.txt", mode: 0600, access: kernelNFSACLEntries(6, 7, 0),
		cli: []string{"user::rw-", "user:20002:rwx\t#effective:---", "group::---", "mask::---", "other::---"}}
	readACL := func(t *testing.T, s *session.Session, seed kernelNFSACLSeed) {
		t.Helper()
		node, _, err := s.Resolve(ctx, seed.path, false)
		if err != nil {
			t.Fatal(err)
		}
		before, err := s.Client.GetAttr(ctx, node.Handle)
		if err != nil {
			t.Fatal(err)
		}
		acl, err := s.Client.GetNFS3ACL(ctx, node.Handle)
		if err != nil || acl == nil {
			t.Fatalf("GETACL %s: %v", seed.path, err)
		}
		if acl.Attr.UID != 20001 || acl.Attr.GID != 20001 || acl.Attr.Mode&07777 != seed.mode || !reflect.DeepEqual(acl.Attr, before) {
			t.Fatalf("GETACL attributes %s: before=%+v acl=%+v", seed.path, before, acl.Attr)
		}
		if !slices.Equal(acl.Access, seed.access) || !slices.Equal(acl.Default, seed.defaults) {
			t.Fatalf("GETACL entries %s: access=%+v default=%+v", seed.path, acl.Access, acl.Default)
		}
		after, _, err := s.Resolve(ctx, seed.path, false)
		if err != nil || !bytes.Equal(node.Handle, after.Handle) || !reflect.DeepEqual(before, after.Attr) {
			t.Fatalf("GETACL changed file identity or metadata for %s: %v", seed.path, err)
		}
		t.Logf("NFS3_ACL path=%s uid=%d gid=%d mode=%04o access=%d default=%d identity=%s", seed.path, acl.Attr.UID, acl.Attr.GID, acl.Attr.Mode&07777, len(acl.Access), len(acl.Default), s.Client.Identity())
	}
	read := func(t *testing.T, s *session.Session, path, want string) {
		t.Helper()
		var out bytes.Buffer
		if n, err := s.Cat(ctx, path, &out); err != nil || n != int64(len(want)) || out.String() != want {
			t.Fatalf("fixture read %s: bytes=%d error=%v", path, n, err)
		}
	}
	denyRead := func(t *testing.T, s *session.Session, path string) {
		t.Helper()
		var out bytes.Buffer
		n, err := s.Cat(ctx, path, &out)
		if n != 0 || out.Len() != 0 || (!errors.Is(err, nfs.Status(13)) && !errors.Is(err, nfs.Status(1))) {
			t.Fatalf("fixture read denial %s: bytes=%d exposed=%d error=%v", path, n, out.Len(), err)
		}
	}
	t.Run("access", func(t *testing.T) {
		readACL(t, alice, grant)
		readACL(t, bob, grant)
		read(t, bob, grant.path, "acl grant fixture\n")
		denyRead(t, stranger, grant.path)
	})
	t.Run("default", func(t *testing.T) {
		readACL(t, alice, inherit)
		readACL(t, bob, inherit)
	})
	t.Run("mask", func(t *testing.T) {
		readACL(t, alice, masked)
		readACL(t, bob, masked)
		read(t, alice, masked.path, "acl masked fixture\n")
		denyRead(t, bob, masked.path)
		denyRead(t, stranger, masked.path)
		read(t, bob, grant.path, "acl grant fixture\n")
	})
	t.Run("cli", func(t *testing.T) {
		for _, seed := range []kernelNFSACLSeed{grant, inherit, masked} {
			kernelNFSACLCLIRead(t, cfg, 20001, seed)
		}
		kernelNFSACLCLIRead(t, cfg, 20002, masked)
	})
}

func kernelNFSACLCLIRead(t *testing.T, cfg nfs.Config, uid uint32, seed kernelNFSACLSeed) {
	t.Helper()
	identity := kernelACLIdentity(t, cfg, uid)
	args := []string{"127.0.0.1", "--nfs-version", "3", "--transport", cfg.Transport,
		"--nfs-port", strconv.Itoa(cfg.NFSPort), "--mount-port", strconv.Itoa(cfg.MountPort),
		"--export", kernelExport("3", "data"), "--auto-uid=false", "--auto-escape=false",
		"--no-banner", "--color", "never", "--progress", "never", "--timeout", "4s"}
	if cfg.Security == "" || cfg.Security == "sys" {
		args = append(args, "--uid", strconv.FormatUint(uint64(uid), 10), "--gid", strconv.FormatUint(uint64(uid), 10), "--groups", "")
	} else {
		args = append(args, kernelKerberosArgs(identity)...)
	}
	args = append(args, "-c", "acl "+seed.path)
	out, err := runKerberosCLI(t, args)
	if err != nil {
		t.Fatalf("CLI acl %s: %v %s", seed.path, err, out)
	}
	out = strings.ReplaceAll(out, "\r\n", "\n")
	for _, line := range []string{"# NFSv3 ACL (read-only)", "# owner: 20001  group: 20001", "# Masked permissions are not a server access decision."} {
		if strings.Count(out, line+"\n") != 1 {
			t.Fatalf("CLI ACL diagnostic missing or repeated %q: %s", line, out)
		}
	}
	var got []string
	for _, line := range strings.Split(out, "\n") {
		for _, prefix := range []string{"user:", "group:", "mask:", "other:", "default:"} {
			if strings.HasPrefix(line, prefix) {
				got = append(got, line)
				break
			}
		}
	}
	if !slices.Equal(got, seed.cli) {
		t.Fatalf("CLI ACL entries %s: got=%q want=%q", seed.path, got, seed.cli)
	}
}
