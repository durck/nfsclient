package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"nfs-viewer/internal/nfs"
)

func rootNode(id uint64) nfs.Node {
	return nfs.Node{Handle: []byte(fmt.Sprint(id)), Attr: nfs.Attr{Type: 2, FSID: 1, FileID: id, HasFSID: true, HasFileID: true}}
}

func TestRootIdentityOmitted(t *testing.T) {
	n := rootNode(0)
	n.Attr.HasFileID = false
	if sameRootObject(n, n) || !strings.Contains(RootObjectID(n), "unavailable") {
		t.Fatal("omitted identity treated as a zero-valued identity")
	}
	result, err := traceRootAncestor(context.Background(), n, n, nil)
	if err != nil || !strings.Contains(result, "unverified") {
		t.Fatalf("%s %v", result, err)
	}
	n.Attr.HasFileID = true
	n.Attr.FSID = 0
	if !sameRootObject(n, n) {
		t.Fatal("explicit zero identity rejected")
	}
}

func TestTraceRootAncestor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		target    uint64
		parents   map[string]uint64
		lookupErr error
		want      string
		wantErr   bool
	}{
		{"same", 1, nil, nil, "original export object", false},
		{"ancestor", 3, map[string]uint64{"1": 2, "2": 3}, nil, "ancestor of the export (2 parent steps)", false},
		{"boundary", 3, map[string]uint64{"1": 1}, nil, "namespace boundary", false},
		{"cycle", 3, map[string]uint64{"1": 2, "2": 1}, nil, "cycle", false},
		{"access denied", 3, nil, nfs.Status(13), "unverified", false},
		{"transport failed", 3, nil, errors.New("connection lost"), "unverified", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := traceRootAncestor(context.Background(), rootNode(1), rootNode(tc.target), func(_ context.Context, fh []byte, name string) (nfs.Node, error) {
				if name != ".." {
					t.Fatalf("unexpected lookup %q", name)
				}
				if tc.lookupErr != nil {
					return nfs.Node{}, tc.lookupErr
				}
				return rootNode(tc.parents[string(fh)]), nil
			})
			if !strings.Contains(result, tc.want) || (err != nil) != tc.wantErr {
				t.Fatalf("%q %v", result, err)
			}
		})
	}
}

func TestTraceRootBoundsAndIdentity(t *testing.T) {
	calls := 0
	lookup := func(_ context.Context, fh []byte, _ string) (nfs.Node, error) {
		calls++
		return rootNode(uint64(calls + 1)), nil
	}
	result, err := traceRootAncestor(context.Background(), rootNode(1), rootNode(1000), lookup)
	if err != nil || !strings.Contains(result, "64-step") || calls != 64 {
		t.Fatalf("unbounded traversal: %q %d %v", result, calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if _, err := traceRootAncestor(ctx, rootNode(1), rootNode(1000), lookup); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancellation ignored: %v / %d", err, calls)
	}
	a, b := rootNode(1), rootNode(1)
	b.Attr.FSIDMinor = 1
	if sameRootObject(a, b) {
		t.Fatal("different filesystems identified as one object")
	}
	copy := cloneRoot(a)
	copy.Handle[0] = '9'
	if string(a.Handle) != "1" {
		t.Fatal("saved handle aliases selected root")
	}
}
