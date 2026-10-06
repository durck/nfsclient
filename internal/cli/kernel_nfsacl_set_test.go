package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

// This API-only suite changes ACLs solely on new acl-set-* objects. Retain
// them for the runner's independent numeric getfacl/stat/content snapshots.
func TestKernelNFSACLSet(t *testing.T) {
	if os.Getenv("NFS_VIEWER_KERNEL_NFSACL_SET") != "1" || os.Getenv("NFS_VIEWER_KERNEL") != "1" {
		t.Skip("requires isolated kernel NFSACL mutation fixture")
	}
	if os.Getenv("NFS_VIEWER_KERNEL_GSS_V3") == "1" {
		t.Run("gss", func(t *testing.T) { kernelGSS3Profiles(t, kernelNFSACLSet) })
		return
	}
	t.Run("sys", func(t *testing.T) {
		for _, transport := range []string{"tcp", "udp"} {
			t.Run(transport, func(t *testing.T) { kernelNFSACLSet(t, kernelConfig(t, "3", transport)) })
		}
	})
}

func kernelNFSACLSetClone(policy *nfs.NFS3ACL) *nfs.NFS3ACL {
	copy := *policy
	copy.Access = slices.Clone(policy.Access)
	copy.Default = slices.Clone(policy.Default)
	return &copy
}

func kernelNFSACLSet(t *testing.T, cfg nfs.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
		auth.Groups = slices.Clone(auth.Groups)
		if cfg.Security != "" && cfg.Security != "sys" {
			user := map[uint32]string{20001: "alice", 20002: "bob"}[uid]
			if identity != user+"@NFS.TEST ("+cfg.Security+")" {
				t.Fatalf("unexpected selected SETACL identity: %s", identity)
			}
		}
		t.Cleanup(func() {
			if c.Identity() != identity || !reflect.DeepEqual(c.Auth, auth) {
				t.Error("SETACL changed the selected identity")
			}
		})
		return s
	}
	alice, bob := connect(20001), connect(20002)
	parent := fmt.Sprintf("acl-set-%d", time.Now().UnixNano())
	parentNode, err := alice.Client.Create(ctx, alice.Root.Handle, parent, 0755, true)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "NFSACL SET fixture\n"
	create := func(t *testing.T, name string, mode uint32, directory bool) string {
		t.Helper()
		node, err := alice.Client.Create(ctx, parentNode.Handle, name, mode, directory)
		if err != nil {
			t.Fatal(err)
		}
		if !directory {
			if n, err := alice.Client.WriteFrom(ctx, node.Handle, strings.NewReader(payload)); err != nil || n != int64(len(payload)) {
				t.Fatalf("fixture write: bytes=%d error=%v", n, err)
			}
		}
		return parent + "/" + name
	}
	get := func(t *testing.T, s *session.Session, path string) (nfs.Node, *nfs.NFS3ACL) {
		t.Helper()
		node, _, err := s.Resolve(ctx, path, false)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := s.Client.GetNFS3ACL(ctx, node.Handle)
		if err != nil || policy == nil {
			t.Fatalf("GETACL %s: %v", path, err)
		}
		if policy.Attr.UID != 20001 || policy.Attr.GID != 20001 {
			t.Fatalf("unexpected fixture ownership %s: %+v", path, policy.Attr)
		}
		return node, policy
	}
	apply := func(t *testing.T, path string, change func(*nfs.NFS3ACL)) *nfs.NFS3ACL {
		t.Helper()
		beforeNode, before := get(t, alice, path)
		wanted := kernelNFSACLSetClone(before)
		change(wanted)
		input := kernelNFSACLSetClone(wanted)
		if err := alice.Client.SetNFS3ACL(ctx, beforeNode.Handle, wanted); err != nil {
			t.Fatalf("SETACL %s: %v", path, err)
		}
		if !reflect.DeepEqual(wanted, input) {
			t.Fatal("SETACL changed its caller's policy")
		}
		afterNode, after := get(t, alice, path)
		if !bytes.Equal(beforeNode.Handle, afterNode.Handle) || !slices.Equal(after.Access, wanted.Access) || !slices.Equal(after.Default, wanted.Default) || after.Attr.Mode&07777 != wanted.Attr.Mode&07777 {
			t.Fatalf("SETACL readback %s: got=%+v want=%+v", path, after, wanted)
		}
		// ACL changes may update ctime and mode, but must preserve the object,
		// ownership, file bytes/size, mtime and remaining returned metadata.
		stable := before.Attr
		stable.Mode, stable.CTime, stable.Change = after.Attr.Mode, after.Attr.CTime, after.Attr.Change
		if !reflect.DeepEqual(stable, after.Attr) {
			t.Fatalf("SETACL changed non-policy metadata %s: before=%+v after=%+v", path, before.Attr, after.Attr)
		}
		return after
	}
	read := func(t *testing.T, s *session.Session, path string, allowed bool) {
		t.Helper()
		var out bytes.Buffer
		n, err := s.Cat(ctx, path, &out)
		if allowed {
			if err != nil || n != int64(len(payload)) || out.String() != payload {
				t.Fatalf("fixture read %s: bytes=%d error=%v", path, n, err)
			}
		} else if n != 0 || out.Len() != 0 || (!errors.Is(err, nfs.Status(13)) && !errors.Is(err, nfs.Status(1))) {
			t.Fatalf("fixture read denial %s: bytes=%d exposed=%d error=%v", path, n, out.Len(), err)
		}
	}
	retain := func(t *testing.T, path string) {
		t.Helper()
		_, policy := get(t, alice, path)
		var digest string
		if policy.Attr.Type == 1 {
			read(t, alice, path, true)
			hash := sha256.Sum256([]byte(payload))
			digest = hex.EncodeToString(hash[:])
		}
		record := struct {
			Path     string             `json:"path"`
			Type     uint32             `json:"type"`
			UID      uint32             `json:"uid"`
			GID      uint32             `json:"gid"`
			Mode     string             `json:"mode"`
			Size     uint64             `json:"size"`
			FileID   uint64             `json:"file_id"`
			SHA256   string             `json:"sha256,omitempty"`
			Access   []nfs.NFS3ACLEntry `json:"access"`
			Default  []nfs.NFS3ACLEntry `json:"default"`
			Identity string             `json:"identity"`
		}{path, policy.Attr.Type, policy.Attr.UID, policy.Attr.GID, fmt.Sprintf("%04o", policy.Attr.Mode&07777), policy.Attr.Size, policy.Attr.FileID, digest, policy.Access, policy.Default, alice.Client.Identity()}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("NFS3_ACL_SET %s", encoded)
	}
	t.Run("minimal", func(t *testing.T) {
		path := create(t, "minimal", 0644, false)
		apply(t, path, func(policy *nfs.NFS3ACL) {
			policy.Attr.Mode = 0600
			policy.Access = []nfs.NFS3ACLEntry{{Tag: nfs.ACLUserObj, ID: 20001, Perm: 6}, {Tag: nfs.ACLGroupObj, ID: 20001}, {Tag: nfs.ACLMask}, {Tag: nfs.ACLOther}}
			policy.Default = nil
		})
		read(t, bob, path, false)
		retain(t, path)
	})
	t.Run("mask-and-grant", func(t *testing.T) {
		for _, name := range []string{"hidden", "expanded"} {
			path := create(t, name, 0600, false)
			apply(t, path, func(policy *nfs.NFS3ACL) {
				policy.Access = kernelNFSACLEntries(6, 7, 0)
			})
			read(t, bob, path, false)
			if name == "expanded" {
				apply(t, path, func(policy *nfs.NFS3ACL) {
					policy.Attr.Mode = 0640
					for i := range policy.Access {
						if policy.Access[i].Tag == nfs.ACLMask {
							policy.Access[i].Perm = 4
						}
					}
				})
				read(t, bob, path, true)
			}
			retain(t, path)
		}
	})
	t.Run("default-preserve-and-clear", func(t *testing.T) {
		for _, name := range []string{"defaults-preserved", "defaults-cleared"} {
			path := create(t, name, 0700, true)
			apply(t, path, func(policy *nfs.NFS3ACL) {
				policy.Attr.Mode = 0770
				policy.Access = kernelNFSACLEntries(7, 7, 7)
				policy.Default = kernelNFSACLEntries(7, 7, 7)
			})
			apply(t, path, func(policy *nfs.NFS3ACL) {
				policy.Attr.Mode = 0750
				policy.Access = kernelNFSACLEntries(7, 5, 5)
				if name == "defaults-cleared" {
					policy.Default = nil
				}
			})
			retain(t, path)
		}
	})
	t.Run("nonowner-denial", func(t *testing.T) {
		path := create(t, "denied", 0640, false)
		apply(t, path, func(policy *nfs.NFS3ACL) { policy.Access = kernelNFSACLEntries(6, 4, 4) })
		read(t, bob, path, true)
		beforeNode, before := get(t, bob, path)
		wanted := kernelNFSACLSetClone(before)
		wanted.Attr.Mode, wanted.Access = 0670, kernelNFSACLEntries(6, 7, 7)
		err := bob.Client.SetNFS3ACL(ctx, beforeNode.Handle, wanted)
		if !errors.Is(err, nfs.ErrNFSACLMutationUnverified) || (!errors.Is(err, nfs.Status(13)) && !errors.Is(err, nfs.Status(1))) {
			t.Fatalf("nonowner SETACL must report unverified server denial: %v", err)
		}
		afterNode, after := get(t, alice, path)
		if !bytes.Equal(beforeNode.Handle, afterNode.Handle) || !reflect.DeepEqual(before, after) {
			t.Fatalf("denied SETACL changed policy or metadata: before=%+v after=%+v", before, after)
		}
		read(t, bob, path, true)
		retain(t, path)
	})
}
