package nfs

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func aclBaseForTest() []NFS3ACLEntry {
	return []NFS3ACLEntry{{ACLUserObj, 1000, 6}, {ACLGroupObj, 1000, 4}, {ACLMask, 0, 4}, {ACLOther, 0, 4}}
}

func aclReplyForTest(typ, mode uint32, access, defaults []NFS3ACLEntry) encoder {
	var e encoder
	e.u32(0)
	e.u32(1)
	start := len(e)
	compatibilityAttr(&e)
	binary.BigEndian.PutUint32(e[start:], typ)
	binary.BigEndian.PutUint32(e[start+4:], mode)
	e.u32(nfsACLMask)
	for i, entries := range [][]NFS3ACLEntry{access, defaults} {
		e.u32(uint32(len(entries)))
		e.u32(uint32(len(entries)))
		for _, entry := range entries {
			tag := entry.Tag
			if i == 1 {
				tag |= nfsACLDefault
			}
			e.u32(tag)
			e.u32(entry.ID)
			e.u32(entry.Perm)
		}
	}
	return e
}

func TestNFS3ACLDecode(t *testing.T) {
	access := aclBaseForTest()
	// Named user equal to owner and same numeric named user/group are legal.
	access = append(access, NFS3ACLEntry{ACLUser, 1000, 7}, NFS3ACLEntry{ACLGroup, 1000, 2})
	defaults := []NFS3ACLEntry{{ACLOther, 0, 1}, {ACLMask, 0, 7}, {ACLGroupObj, 1000, 0}, {ACLUserObj, 1000, 7}}
	a, err := decodeNFS3ACL(&decoder{b: aclReplyForTest(2, 0644, access, defaults)})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Access) != 6 || a.Access[1] != (NFS3ACLEntry{ACLUser, 1000, 7}) || a.Default[0] != (NFS3ACLEntry{ACLUserObj, 1000, 7}) || a.Attr.UID != 1000 {
		t.Fatalf("lost identities/raw permissions or unsorted default: %+v", a)
	}
	minimal, err := decodeNFS3ACL(&decoder{b: aclReplyForTest(1, 0644, aclBaseForTest(), nil)})
	if err != nil || !reflect.DeepEqual(minimal.Access, aclBaseForTest()) || minimal.Default == nil || len(minimal.Default) != 0 {
		t.Fatalf("minimum wire ACL: %+v %v", minimal, err)
	}
	large := aclBaseForTest()
	for i := 0; i < maxNFSACLEntries-4; i++ {
		large = append(large, NFS3ACLEntry{ACLUser, uint32(i), 7})
	}
	if a, err := decodeNFS3ACL(&decoder{b: aclReplyForTest(2, 0644, large, large)}); err != nil || len(a.Access) != maxNFSACLEntries || len(a.Default) != maxNFSACLEntries {
		t.Fatalf("maximum bounded policy: %v", err)
	}
}

func TestNFS3ACLRejectsIncompletePolicy(t *testing.T) {
	valid := aclReplyForTest(1, 0644, aclBaseForTest(), nil)
	for n := 0; n < len(valid); n++ {
		if a, err := decodeNFS3ACL(&decoder{b: valid[:n]}); err == nil || a != nil {
			t.Fatalf("truncated reply at %d exposed policy: %+v %v", n, a, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(encoder) encoder
	}{
		{"missing attributes", func(e encoder) encoder { binary.BigEndian.PutUint32(e[4:], 0); return e }},
		{"invalid attr bool", func(e encoder) encoder { binary.BigEndian.PutUint32(e[4:], 2); return e }},
		{"unsupported type", func(e encoder) encoder { binary.BigEndian.PutUint32(e[8:], 5); return e }},
		{"unknown mask", func(e encoder) encoder { binary.BigEndian.PutUint32(e[92:], 31); return e }},
		{"partial mask", func(e encoder) encoder { binary.BigEndian.PutUint32(e[92:], 3); return e }},
		{"count mismatch", func(e encoder) encoder { binary.BigEndian.PutUint32(e[96:], 5); return e }},
		{"count only", func(e encoder) encoder { binary.BigEndian.PutUint32(e[100:], 0); return e }},
		{"too many", func(e encoder) encoder {
			binary.BigEndian.PutUint32(e[96:], 1025)
			binary.BigEndian.PutUint32(e[100:], 1025)
			return e
		}},
		{"wrong default flag", func(e encoder) encoder { binary.BigEndian.PutUint32(e[104:], ACLUserObj|nfsACLDefault); return e }},
		{"unknown tag", func(e encoder) encoder { binary.BigEndian.PutUint32(e[104:], 0x2001); return e }},
		{"owner mismatch", func(e encoder) encoder { binary.BigEndian.PutUint32(e[108:], 1001); return e }},
		{"unknown perm bits", func(e encoder) encoder { binary.BigEndian.PutUint32(e[112:], 8); return e }},
		{"mode mismatch", func(e encoder) encoder { binary.BigEndian.PutUint32(e[112:], 7); return e }},
		{"trailing", func(e encoder) encoder { return append(e, 0, 0, 0, 0) }},
		{"reply bound", func(e encoder) encoder { return make(encoder, maxNFSACLReply+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a, err := decodeNFS3ACL(&decoder{b: tc.mutate(append(encoder(nil), valid...))}); err == nil || a != nil {
				t.Fatalf("exposed invalid policy: %+v %v", a, err)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		entries []NFS3ACLEntry
	}{
		{"empty", nil},
		{"no mask", []NFS3ACLEntry{{ACLUserObj, 1000, 6}, {ACLGroupObj, 1000, 4}, {ACLOther, 0, 4}}},
		{"duplicate", append(aclBaseForTest(), NFS3ACLEntry{ACLMask, 0, 4})},
		{"duplicate named", append(aclBaseForTest(), NFS3ACLEntry{ACLUser, 7, 4}, NFS3ACLEntry{ACLUser, 7, 6})},
		{"undefined id", append(aclBaseForTest(), NFS3ACLEntry{ACLUser, ^uint32(0), 4})},
		{"group mismatch", []NFS3ACLEntry{{ACLUserObj, 1000, 6}, {ACLGroupObj, 1001, 4}, {ACLMask, 0, 4}, {ACLOther, 0, 4}}},
		{"other id", []NFS3ACLEntry{{ACLUserObj, 1000, 6}, {ACLGroupObj, 1000, 4}, {ACLMask, 0, 4}, {ACLOther, 1, 4}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a, err := decodeNFS3ACL(&decoder{b: aclReplyForTest(1, 0644, tc.entries, nil)}); err == nil || a != nil {
				t.Fatalf("accepted invalid policy %+v %v", a, err)
			}
		})
	}
	if a, err := decodeNFS3ACL(&decoder{b: aclReplyForTest(1, 0644, aclBaseForTest(), aclBaseForTest())}); err == nil || a != nil {
		t.Fatal("regular file accepted default policy")
	}
	for _, status := range []uint32{13, 70, 10004} {
		var e encoder
		e.u32(status)
		e.u32(0)
		if a, err := decodeNFS3ACL(&decoder{b: e}); !errors.Is(err, Status(status)) || a != nil {
			t.Fatalf("status %d: %v", status, err)
		}
	}
}

func TestNFS3ACLPreflight(t *testing.T) {
	for _, version := range []string{"2", "4.0", "4.1", "4.2"} {
		c := &Client{version: version}
		if _, err := c.GetNFS3ACL(context.Background(), []byte("fh")); !errors.Is(err, ErrNFSACLUnavailable) {
			t.Fatalf("version %s: %v", version, err)
		}
	}
	for _, fh := range [][]byte{nil, make([]byte, 65)} {
		if _, err := (&Client{version: "3"}).GetNFS3ACL(context.Background(), fh); err == nil {
			t.Fatal("invalid handle accepted")
		}
	}
}

func FuzzNFS3ACLDecode(f *testing.F) {
	f.Add([]byte(aclReplyForTest(1, 0644, aclBaseForTest(), nil)))
	f.Add([]byte(aclReplyForTest(2, 0644, aclBaseForTest(), aclBaseForTest())))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := decodeNFS3ACL(&decoder{b: b})
		if err != nil {
			if a != nil {
				t.Fatal("partial policy on error")
			}
			return
		}
		if a == nil || len(a.Access) < 4 || len(a.Access) > maxNFSACLEntries || len(a.Default) > maxNFSACLEntries {
			t.Fatal("invalid accepted ACL")
		}
	})
}
