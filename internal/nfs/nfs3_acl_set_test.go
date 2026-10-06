package nfs

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestNFS3ACLSetRejectsInputWithoutNetwork(t *testing.T) {
	good := &NFS3ACL{Attr: Attr{Type: 1, UID: 1000, GID: 1000, Mode: 0644}, Access: aclBaseForTest()}
	for _, tc := range []struct {
		name string
		edit func(*NFS3ACL)
	}{
		{"empty", func(a *NFS3ACL) { a.Access = nil }},
		{"large", func(a *NFS3ACL) { a.Access = make([]NFS3ACLEntry, 1025) }},
		{"permission", func(a *NFS3ACL) { a.Access[0].Perm = 8 }},
		{"owner", func(a *NFS3ACL) { a.Access[0].ID++ }},
		{"duplicate", func(a *NFS3ACL) { a.Access = append(a.Access, a.Access[0]) }},
		{"special", func(a *NFS3ACL) { a.Attr.Mode |= 04000 }},
		{"unknown-mode", func(a *NFS3ACL) { a.Attr.Mode |= 0100000 }},
		{"mode-mismatch", func(a *NFS3ACL) { a.Attr.Mode = 0600 }},
		{"symlink", func(a *NFS3ACL) { a.Attr.Type = 5 }},
		{"file-default", func(a *NFS3ACL) { a.Default = aclBaseForTest() }},
		{"default-tag", func(a *NFS3ACL) { a.Access[0].Tag |= 0x1000 }},
		{"invalid-user", func(a *NFS3ACL) { a.Access = append(a.Access, NFS3ACLEntry{ACLUser, ^uint32(0), 4}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := *good
			policy.Access = append([]NFS3ACLEntry(nil), good.Access...)
			tc.edit(&policy)
			c := &Client{version: "3"} // Any network call panics: rejection must be local.
			if err := c.SetNFS3ACL(context.Background(), []byte{1}, &policy); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	for _, version := range []string{"2", "4.0", "4.1", "4.2"} {
		if err := (&Client{version: version}).SetNFS3ACL(context.Background(), []byte{1}, good); err == nil {
			t.Fatal("unsupported version accepted")
		}
	}
	for _, fh := range [][]byte{nil, make([]byte, 65)} {
		if err := (&Client{version: "3"}).SetNFS3ACL(context.Background(), fh, good); err == nil {
			t.Fatal("invalid handle accepted")
		}
	}
	if err := (&Client{version: "3"}).SetNFS3ACL(context.Background(), []byte{1}, nil); err == nil {
		t.Fatal("nil policy accepted")
	}
}

func TestNFS3ACLSetReplyRequiresCompleteFraming(t *testing.T) {
	complete := aclReplyForTest(1, 0644, aclBaseForTest(), nil)[:92]
	for length := 0; length < len(complete); length++ {
		if _, _, err := decodeNFS3ACLSet(&decoder{b: complete[:length]}); err == nil {
			t.Fatalf("accepted truncated reply of %d bytes", length)
		}
	}
	for _, raw := range [][]byte{append(append([]byte(nil), complete...), 0), {0, 0, 0, 0, 0, 0, 0, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, _, err := decodeNFS3ACLSet(&decoder{b: raw}); err == nil {
			t.Fatal("accepted oversized/trailing/invalid-boolean reply")
		}
	}
	if attr, present, err := decodeNFS3ACLSet(&decoder{b: complete}); err != nil || !present || attr.Mode != 0644 {
		t.Fatalf("complete post-op attributes: %+v %t %v", attr, present, err)
	}
	if _, present, err := decodeNFS3ACLSet(&decoder{b: make([]byte, 8)}); err != nil || present {
		t.Fatalf("valid omitted post-op attributes: %t %v", present, err)
	}
	for _, raw := range [][]byte{{0, 0, 0, 13, 0, 0, 0, 0}, {0, 0, 0, 13, 0, 0, 0, 1}} {
		if _, _, err := decodeNFS3ACLSet(&decoder{b: raw}); !errors.Is(err, Status(13)) {
			t.Fatalf("lost denial status: %v", err)
		}
	}
}

func TestNFS3ACLCanonicalDoesNotAlterCaller(t *testing.T) {
	input := aclBaseForTest()
	input[0], input[3] = input[3], input[0]
	before := append([]NFS3ACLEntry(nil), input...)
	got, err := canonicalNFS3ACLList(input, Attr{UID: 1000, GID: 1000}, false)
	if err != nil || !reflect.DeepEqual(input, before) || !reflect.DeepEqual(got, aclBaseForTest()) {
		t.Fatalf("canonicalization changed caller or raw rights: %+v %v", got, err)
	}
}
