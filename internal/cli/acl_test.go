package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"nfs-viewer/internal/nfs"
)

func TestACLDisplayPreservesMaskedRights(t *testing.T) {
	a := &nfs.NFS3ACL{Attr: nfs.Attr{UID: 20001, GID: 20003}, Access: []nfs.NFS3ACLEntry{
		{Tag: nfs.ACLUserObj, ID: 20001, Perm: 6},
		{Tag: nfs.ACLUser, ID: 20002, Perm: 7},
		{Tag: nfs.ACLGroupObj, ID: 20003, Perm: 4},
		{Tag: nfs.ACLGroup, ID: 20004, Perm: 6},
		{Tag: nfs.ACLMask, Perm: 0},
		{Tag: nfs.ACLOther, Perm: 1},
	}, Default: []nfs.NFS3ACLEntry{{Tag: nfs.ACLUserObj, ID: 20001, Perm: 7}, {Tag: nfs.ACLGroupObj, ID: 20003, Perm: 4}, {Tag: nfs.ACLMask, Perm: 5}, {Tag: nfs.ACLOther}}}
	var out bytes.Buffer
	if err := printNFS3ACL(&out, a); err != nil {
		t.Fatal(err)
	}
	want := "# NFSv3 ACL (read-only)\n# owner: 20001  group: 20003\nuser::rw-\nuser:20002:rwx\t#effective:---\ngroup::r--\t#effective:---\ngroup:20004:rw-\t#effective:---\nmask::---\nother::--x\ndefault:user::rwx\ndefault:group::r--\ndefault:mask::r-x\ndefault:other::---\n# Masked permissions are not a server access decision.\n"
	if out.String() != want {
		t.Fatalf("ACL permissions changed or scope unclear:\n%s", out.String())
	}
	if err := printNFS3ACL(failingACLWriter{}, a); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}

func TestNFS4ACLJSONPreservesPolicy(t *testing.T) {
	want := &nfs.NFS4ACL{Attribute: "dacl", Flags: 3, Entries: []nfs.NFS4ACE{
		{Type: 1, Mask: 2, Who: "bob@example.test"},
		{Type: 0, Flags: 0x8b, Mask: 1, Who: "readers@example.test"},
		{Type: 0, Mask: 0x1f01ff, Who: "OWNER@"},
		{Type: 0, Mask: 1, Who: "bob@example.test"},
	}}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseV4ACLJSON(data)
	if err != nil || got.Attribute != want.Attribute || got.Flags != want.Flags || !slices.Equal(got.Entries, want.Entries) {
		t.Fatalf("policy changed: %+v %v", got, err)
	}
	if _, err := parseV4ACLJSON([]byte(`{"attribute":"acl","flags":0,"entries":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestNFS4ACLJSONRejectsAmbiguousPolicy(t *testing.T) {
	for _, document := range []string{
		`null`, `{}`, `[]`,
		`{"attribute":"acl","flags":0,"entries":null}`,
		`{"attribute":"acl","flags":0,"entries":[]}{}`,
		`{"attribute":"acl","flags":0,"flags":1,"entries":[]}`,
		`{"Attribute":"acl","flags":0,"entries":[]}`,
		`{"attribute":"acl","flags":0,"entry":[]}`,
		`{"attribute":"acl","flags":0,"entries":[{"flags":0,"mask":1,"who":"OWNER@"}]}`,
		`{"attribute":"acl","flags":0,"entries":[{"type":0,"flags":0,"mask":1,"who":null}]}`,
		`{"attribute":"acl","flags":0,"entries":[{"type":0,"flags":0,"mask":1,"who":"OWNER@","who":"EVERYONE@"}]}`,
		`{"attribute":"acl","flags":0,"entries":[{"type":4294967296,"flags":0,"mask":1,"who":"OWNER@"}]}`,
		`{"attribute":"acl","flags":0,"entries":[{"type":-1,"flags":0,"mask":1,"who":"OWNER@"}]}`,
		`{"attribute":"acl","flags":0,"entries":[{"type":0,"flags":0,"mask":1.5,"who":"OWNER@"}]}`,
		`{"attribute":"acl","flags":0,"entries":[{"type":0,"flags":0,"mask":1,"who":"\ud800"}]}`,
		`{"attribute":"acl","flags":0,"entries":[{"type":0,"flags":0,"mask":1,"who":"\udc00"}]}`,
		"{\"attribute\":\"acl\",\"flags\":0,\"entries\":[{\"type\":0,\"flags\":0,\"mask\":1,\"who\":\"bad\xff\"}]}",
	} {
		if _, err := parseV4ACLJSON([]byte(document)); err == nil {
			t.Fatalf("accepted ambiguous policy: %s", document)
		}
	}
}

func TestNFS4ACLJSONUnicodeIdentity(t *testing.T) {
	for _, who := range []string{`"\ud83d\ude00@example.test"`, `"literal\\ud800@example.test"`, `"Алиса@example.test"`} {
		data := []byte(`{"attribute":"acl","flags":0,"entries":[{"type":0,"flags":0,"mask":1,"who":` + who + `}]}`)
		if _, err := parseV4ACLJSON(data); err != nil {
			t.Fatalf("valid Unicode identity rejected: %v", err)
		}
	}
}

func TestNFS4ACLCommandsValidateBeforeNetwork(t *testing.T) {
	sh, _, out := testShell(t)
	for _, line := range []string{"getacl", "getacl file", "getacl file local acl extra", "setacl", "setacl file", "setacl file local extra"} {
		if _, err := sh.Execute(context.Background(), line); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("%q: %v", line, err)
		}
	}
	sh.Session.AutoUID = true
	sh.Session.Client.Auth = nfs.Auth{UID: 32123, GID: 32124, Groups: []uint32{32125}}
	before := sh.Session.Client.Auth
	file := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(file, []byte(`{"attribute":"acl","flags":0,"entries":[{}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(context.Background(), "setacl missing "+quoteForACLTest(file)); err == nil || !strings.Contains(err.Error(), "ACL JSON") {
		t.Fatalf("invalid JSON reached path resolution: %v", err)
	}
	if !sh.Session.AutoUID || !reflect.DeepEqual(before, sh.Session.Client.Auth) || out.Len() != 0 {
		t.Fatal("failed ACL command changed identity or printed success")
	}
	for _, command := range []string{"acl", "getacl", "setacl"} {
		if !slices.Contains(commands, command) {
			t.Fatalf("missing completion %s", command)
		}
	}
}

func quoteForACLTest(path string) string { return `"` + strings.ReplaceAll(path, `\`, `/`) + `"` }

type failingACLWriter struct{}

func (failingACLWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestACLCommandFailureKeepsIdentity(t *testing.T) {
	sh, root, out := testShell(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	sh.Session.AutoUID = true
	sh.Session.Client.Auth = nfs.Auth{UID: 32123, GID: 32124, Groups: []uint32{32125}}
	before := sh.Session.Client.Auth
	_, err := sh.Execute(context.Background(), "acl file")
	// This independent peer closes an unknown-program request without a valid
	// RPC error reply. Keep that malformed-reply error distinct from capability.
	if !errors.Is(err, io.ErrUnexpectedEOF) || out.Len() != 0 {
		t.Fatalf("invalid reply exposed policy: %q %v", out.String(), err)
	}
	if !sh.Session.AutoUID || !reflect.DeepEqual(before, sh.Session.Client.Auth) {
		t.Fatal("ACL inspection changed selected identity or auto-uid")
	}
	for _, line := range []string{"acl", "acl file extra"} {
		if _, err := sh.Execute(context.Background(), line); err == nil || !strings.Contains(err.Error(), "usage: acl PATH") {
			t.Fatalf("bad argument check %q: %v", line, err)
		}
	}
	if err := os.Symlink("file", filepath.Join(root, "link")); err == nil {
		if _, err := sh.Execute(context.Background(), "acl link"); err == nil || !strings.Contains(err.Error(), "symbolic links are not followed") {
			t.Fatalf("link followed: %v", err)
		}
	}
}
