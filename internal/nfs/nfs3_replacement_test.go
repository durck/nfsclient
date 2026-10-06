package nfs

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNFS3ReplacementRejectsLocalInputsBeforeRPC(t *testing.T) {
	for name, input := range map[string]struct {
		parent []byte
		name   string
	}{
		"empty-parent": {nil, "file"}, "large-parent": {make([]byte, 65), "file"},
		"empty-name": {[]byte{1}, ""}, "large-name": {[]byte{1}, strings.Repeat("x", 256)},
		"dot": {[]byte{1}, "."}, "parent": {[]byte{1}, ".."},
		"slash": {[]byte{1}, "a/b"}, "nul": {[]byte{1}, "a\x00b"},
	} {
		t.Run(name, func(t *testing.T) {
			c := aclRPCClient(t, 0, 0, nil)
			got, err := c.CaptureNFS3Replacement(context.Background(), input.parent, input.name)
			if got != nil || !errors.Is(err, ErrNFS3ReplacementRefused) || c.nfs.xid != 0 {
				t.Fatalf("invalid local path caused I/O or returned a snapshot: %v", err)
			}
		})
	}
	for _, version := range []string{"2", "4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) {
			c := aclRPCClient(t, 0, 0, nil)
			c.version = version
			if got, err := c.CaptureNFS3Replacement(context.Background(), []byte{1}, "file"); got != nil || !errors.Is(err, ErrNFS3ReplacementRefused) || c.nfs.xid != 0 {
				t.Fatalf("unsupported version sent RPC: %v", err)
			}
		})
	}
	c := aclRPCClient(t, 0, 0, nil)
	if !errors.Is(c.VerifyNFS3ReplacementSource(context.Background(), nil), ErrNFS3ReplacementRefused) ||
		!errors.Is(c.CheckNFS3ReplacementStage(context.Background(), []byte{1}, "stage", []byte{2}, nil), ErrNFS3ReplacementRefused) || c.nfs.xid != 0 {
		t.Fatal("missing snapshot was not rejected locally")
	}
}

func TestNFS3ReplacementAllowsGSSContextObjectReplacement(t *testing.T) {
	source := replacementRPCSource()
	c := replacementRPCPeer(t, 2, []replacementRPCObject{source, source, source, source, source, source})
	original := replacementRPCCapture(t, c)
	// Simulate the context object's replacement on the same transport without
	// changing authenticated identity. Actual KDC renewal is a separate fixture.
	renewed := *c.nfs.gss
	c.nfs.gss = &renewed
	if err := c.VerifyNFS3ReplacementSource(context.Background(), original); err != nil {
		t.Fatalf("same-identity context replacement refused: %v", err)
	}
}

func replacementAttr3() Attr {
	return Attr{Type: 1, Mode: 0640, UID: 20001, GID: 20003, NLink: 1,
		Size: 17, FSID: 9, FileID: 41, MTime: time.Unix(100, 0), CTime: time.Unix(100, 0),
		HasNLink: true, HasSize: true, HasFSID: true, HasFileID: true, HasMTime: true, HasCTime: true}
}

func TestNFS3ReplacementRequiresCompleteSingleLinkFile(t *testing.T) {
	base := replacementAttr3()
	if err := validateNFS3ReplacementAttr(base); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Attr){
		"directory":      func(a *Attr) { a.Type = 2 },
		"symlink":        func(a *Attr) { a.Type = 5 },
		"special-mode":   func(a *Attr) { a.Mode |= 04000 },
		"multiple-links": func(a *Attr) { a.NLink = 2 },
		"unlinked":       func(a *Attr) { a.NLink = 0 },
		"missing-links":  func(a *Attr) { a.HasNLink = false },
		"missing-size":   func(a *Attr) { a.HasSize = false },
		"missing-fsid":   func(a *Attr) { a.HasFSID = false },
		"missing-fileid": func(a *Attr) { a.HasFileID = false },
		"missing-mtime":  func(a *Attr) { a.HasMTime = false },
		"missing-ctime":  func(a *Attr) { a.HasCTime = false },
	} {
		t.Run(name, func(t *testing.T) {
			a := base
			change(&a)
			if validateNFS3ReplacementAttr(a) == nil || sameNFS3ReplacementAttr(base, a) {
				t.Fatal("incomplete or unsuitable observation accepted")
			}
		})
	}
	// Zero-valued identifiers, size and epoch times are valid when present.
	base.Size, base.FSID, base.FileID = 0, 0, 0
	base.MTime, base.CTime = time.Unix(0, 0), time.Unix(0, 0)
	if err := validateNFS3ReplacementAttr(base); err != nil {
		t.Fatal(err)
	}
}

func TestNFS3ReplacementObservesEveryStableField(t *testing.T) {
	base := replacementAttr3()
	for name, change := range map[string]func(*Attr){
		"mode": func(a *Attr) { a.Mode ^= 1 },
		"uid":  func(a *Attr) { a.UID++ }, "gid": func(a *Attr) { a.GID++ },
		"size": func(a *Attr) { a.Size++ }, "fsid": func(a *Attr) { a.FSID++ },
		"fileid":   func(a *Attr) { a.FileID++ },
		"mtime-ns": func(a *Attr) { a.MTime = a.MTime.Add(time.Nanosecond) },
		"ctime-ns": func(a *Attr) { a.CTime = a.CTime.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			a := base
			change(&a)
			if sameNFS3ReplacementAttr(base, a) {
				t.Fatal("changed metadata accepted")
			}
		})
	}
	// Instant equality is independent of the local time-zone representation.
	other := base
	other.MTime, other.CTime = base.MTime.In(time.FixedZone("fixture", 3600)), base.CTime.In(time.FixedZone("fixture", 3600))
	if !sameNFS3ReplacementAttr(base, other) {
		t.Fatal("equal instants differ")
	}
}

func TestNFS3LinkCountDecodedWithoutJSONChange(t *testing.T) {
	for _, links := range []uint32{0, 1, 2, ^uint32(0)} {
		wire := aclRPCBody()[8:92]
		binary.BigEndian.PutUint32(wire[8:], links)
		d := &decoder{b: wire}
		a := readAttr(d)
		if d.err != nil || len(d.b) != 0 || !a.HasNLink || a.NLink != links {
			t.Fatalf("missing NFSv3 link count: %+v / %v", a, d.err)
		}
		b, err := json.Marshal(a)
		if err != nil || strings.Contains(strings.ToLower(string(b)), "link") {
			t.Fatal("internal link observation changed JSON output")
		}
	}
}
