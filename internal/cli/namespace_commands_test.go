package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func TestNamespaceArgumentParsing(t *testing.T) {
	for _, args := range [][]string{nil, {"a"}, {"a", "b", "c"}, {"-f", "a", "b"}, {"-s", "a"}, {"-s", "-s", "a"}, {"--", "a"}} {
		if _, _, _, err := parseLinkArgs(args); err == nil {
			t.Fatal("accepted", args)
		}
	}
	for _, tt := range []struct {
		args         []string
		symbolic     bool
		source, dest string
	}{
		{[]string{"a", "b"}, false, "a", "b"}, {[]string{"-s", "../missing", "b"}, true, "../missing", "b"},
		{[]string{"--", "-s", "b"}, false, "-s", "b"}, {[]string{"-s", "--", "-target", "-link"}, true, "-target", "-link"},
		{[]string{"a", "-s"}, false, "a", "-s"},
	} {
		symbolic, src, dst, err := parseLinkArgs(tt.args)
		if err != nil || symbolic != tt.symbolic || src != tt.source || dst != tt.dest {
			t.Fatal(tt, symbolic, src, dst, err)
		}
	}
	for _, value := range []string{"", ":group", "owner:", "a:b:c"} {
		if _, _, err := parseOwnership(value); err == nil {
			t.Fatal("accepted", value)
		}
	}
	o, g, err := parseOwnership("User@Domain:Group@Domain")
	if err != nil || *o != "User@Domain" || *g != "Group@Domain" {
		t.Fatal(o, g, err)
	}
}

// namespaceWire is a small independent XDR codec for this test-only NFSv3
// peer. Unlike go-nfs v0.0.4, it decodes LINK3args according to RFC 1813.
type namespaceWire struct {
	b   []byte
	err error
}

func (x *namespaceWire) put(v uint32) { x.b = binary.BigEndian.AppendUint32(x.b, v) }
func (x *namespaceWire) str(v string) {
	x.put(uint32(len(v)))
	x.b = append(x.b, []byte(v)...)
	for len(x.b)%4 != 0 {
		x.b = append(x.b, 0)
	}
}
func (x *namespaceWire) take(n int) []byte {
	if n < 0 || n > len(x.b) {
		x.err = io.ErrUnexpectedEOF
		return nil
	}
	b := x.b[:n]
	x.b = x.b[n:]
	return b
}
func (x *namespaceWire) get() uint32 {
	b := x.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (x *namespaceWire) text() string {
	n := int(x.get())
	b := x.take(n)
	x.take((4 - n%4) % 4)
	return string(b)
}

type namespaceObject struct {
	kind, uid, gid uint32
	target         string
}
type namespacePeer struct {
	mu         sync.Mutex
	objects    map[string]*namespaceObject
	names      map[string]string
	calls      map[uint32]int
	drop, deny uint32
	mismatch   bool
}

func namespaceAttrs(x *namespaceWire, o *namespaceObject) {
	for _, v := range []uint32{o.kind, 0644, 1, o.uid, o.gid, 0, 7, 0, 7, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0} {
		x.put(v)
	}
}
func (p *namespacePeer) response(proc uint32, x *namespaceWire) (namespaceWire, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[proc]++
	var e namespaceWire
	if proc == 0 {
		return e, false, nil
	}
	if proc == p.deny {
		e.put(13)
		return e, false, nil
	}
	e.put(0)
	fh := x.text()
	o := p.objects[fh]
	if o == nil {
		return e, false, fmt.Errorf("unknown handle %q", fh)
	}
	switch proc {
	case 1:
		namespaceAttrs(&e, o)
	case 3:
		name := x.text()
		id, ok := p.names[name]
		if !ok {
			e.b = nil
			e.put(2)
			break
		}
		e.str(id)
		e.put(1)
		namespaceAttrs(&e, p.objects[id])
		e.put(0)
	case 5:
		e.put(0)
		e.str(o.target)
	case 15:
		dir, name := x.text(), x.text()
		if dir == "cross" {
			e.b = nil
			e.put(18)
			break
		}
		if _, ok := p.names[name]; ok {
			e.b = nil
			e.put(17)
			break
		}
		p.names[name] = fh
		e.put(0)
		e.put(0)
		e.put(0)
	case 10:
		name := x.text()
		if x.get() != 1 || x.get() != 0777 {
			return e, false, errors.New("bad symlink mode")
		}
		for range 5 {
			if x.get() != 0 {
				return e, false, errors.New("unexpected symlink attribute")
			}
		}
		target := x.text()
		if _, ok := p.names[name]; ok {
			e.b = nil
			e.put(17)
			break
		}
		p.objects[name] = &namespaceObject{kind: 5, target: target}
		p.names[name] = name
		for range 4 {
			e.put(0)
		}
	case 2:
		if x.get() != 0 {
			return e, false, errors.New("ownership touched mode")
		}
		for i := 0; i < 2; i++ {
			if x.get() != 0 {
				v := x.get()
				if !p.mismatch {
					if i == 0 {
						o.uid = v
					} else {
						o.gid = v
					}
				}
			}
		}
		for range 4 {
			if x.get() != 0 {
				return e, false, errors.New("ownership touched size/time/guard")
			}
		}
		e.put(0)
		e.put(0)
	default:
		return e, false, fmt.Errorf("unexpected NFS procedure %d", proc)
	}
	return e, proc == p.drop, x.err
}

func newNamespaceShell(t *testing.T, drop, deny uint32, mismatch bool) (*Shell, *namespacePeer, *bytes.Buffer) {
	t.Helper()
	p := &namespacePeer{objects: map[string]*namespaceObject{"root": {kind: 2, uid: 1000, gid: 1001}, "file": {kind: 1, uid: 1000, gid: 1001}, "cross": {kind: 2}, "old-link": {kind: 5, target: "file"}}, names: map[string]string{"file": "file", "cross": "cross", "old-link": "old-link"}, calls: map[uint32]int{}, drop: drop, deny: deny, mismatch: mismatch}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				for {
					var header [4]byte
					if _, err := io.ReadFull(c, header[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(header[:]) & 0x7fffffff
					if n > 1<<20 {
						t.Error("oversize RPC")
						return
					}
					data := make([]byte, n)
					if _, err := io.ReadFull(c, data); err != nil {
						return
					}
					x := namespaceWire{b: data}
					xid := x.get()
					x.get()
					x.get()
					prog := x.get()
					vers := x.get()
					proc := x.get()
					flavor := x.get()
					auth := namespaceWire{b: []byte(x.text())}
					x.get()
					x.text()
					if prog != 100003 || vers != 3 || flavor != 1 {
						t.Errorf("unexpected RPC %d/%d flavor %d", prog, vers, flavor)
						return
					}
					auth.get()
					auth.text()
					uid, gid := auth.get(), auth.get()
					if uid != 77 || gid != 88 {
						t.Errorf("identity switched to %d:%d", uid, gid)
						return
					}
					body, drop, err := p.response(proc, &x)
					if err != nil {
						t.Error(err)
						return
					}
					if drop {
						return
					}
					r := namespaceWire{}
					for _, v := range []uint32{xid, 1, 0, 0, 0, 0} {
						r.put(v)
					}
					r.b = append(r.b, body.b...)
					binary.BigEndian.PutUint32(header[:], uint32(len(r.b))|0x80000000)
					if _, err := c.Write(append(header[:], r.b...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); wg.Wait() })
	port := l.Addr().(*net.TCPAddr).Port
	c, err := nfs.Connect(context.Background(), nfs.Config{Host: "127.0.0.1", Version: "3", NFSPort: port, MountPort: port, Timeout: time.Second, Auth: nfs.Auth{UID: 77, GID: 88}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	s := session.New(c, "127.0.0.1", true, false, nil)
	s.Export = "/"
	s.Root = nfs.Node{Handle: []byte("root"), Attr: nfs.Attr{Type: 2, UID: 1000, GID: 1001}}
	out := &bytes.Buffer{}
	return &Shell{Session: s, Out: out, Err: io.Discard}, p, out
}

func TestNamespaceLinksAndOwnershipShell(t *testing.T) {
	sh, p, out := newNamespaceShell(t, 0, 0, false)
	ctx := context.Background()
	before := sh.Session.Client.Auth
	run := func(line string) {
		t.Helper()
		if _, err := sh.Execute(ctx, line); err != nil {
			t.Fatal(line, err)
		}
	}
	run("ln file alias")
	run(`ln -s ../missing/./target dangling`)
	run("readlink dangling")
	if out.String() != "../missing/./target\n" {
		t.Fatal(out.String())
	}
	sh.Session.AutoUIDScan = true
	run("chown 123:456 file")
	run("chgrp 789 alias")
	if err := sh.runNamespaceCommand(ctx, "ln", []string{"-s", "unsafe\x1b[31m\n", "escaped"}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	run("readlink escaped")
	if strings.ContainsAny(out.String(), "\x1b") || out.String() != label("unsafe\x1b[31m\n")+"\n" {
		t.Fatal("unsafe link output", out.String())
	}
	if !reflect.DeepEqual(sh.Session.Client.Auth, before) || !sh.Session.AutoUID || !sh.Session.AutoUIDScan {
		t.Fatal("identity policy changed")
	}
	for _, line := range []string{"ln old-link bad", "ln cross bad", "chown 0 old-link", "chgrp 0 old-link/", "readlink file", "ln -s x alias", "ln file alias", "ln file cross/new", "chown user file", "chgrp -1 file"} {
		sh.Session.AutoUID = false
		if _, err := sh.Execute(ctx, line); err == nil {
			t.Fatal("accepted", line)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.names["alias"] != "file" || p.objects["file"].uid != 123 || p.objects["file"].gid != 789 || p.objects["dangling"].target != "../missing/./target" {
		t.Fatal(p.names, p.objects)
	}
}

func TestNamespaceMutationFailureShell(t *testing.T) {
	for _, tt := range []struct {
		name, line string
		drop, deny uint32
		mismatch   bool
		status     nfs.Status
	}{
		{"link-lost", "ln file alias", 15, 0, false, 0}, {"symlink-lost", "ln -s missing dangling", 10, 0, false, 0},
		{"owner-lost", "chown 123 file", 2, 0, false, 0}, {"owner-mismatch", "chown 123 file", 0, 0, true, 0},
		{"owner-readback-denied", "chown 123 file", 0, 1, false, 13},
		{"owner-denied", "chown 123 file", 0, 2, false, 13}, {"link-denied", "ln file alias", 0, 15, false, 13},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sh, p, _ := newNamespaceShell(t, tt.drop, tt.deny, tt.mismatch)
			before := sh.Session.Client.Auth
			sh.Session.AutoUIDScan = true
			_, err := sh.Execute(context.Background(), tt.line)
			if !reflect.DeepEqual(before, sh.Session.Client.Auth) || !sh.Session.AutoUID || !sh.Session.AutoUIDScan {
				t.Fatal("failure changed identity policy")
			}
			if err == nil || tt.status != 0 && !errors.Is(err, tt.status) {
				t.Fatal(err)
			}
			if tt.deny != 15 && !errors.Is(err, nfs.ErrMutationUncertain) {
				t.Fatal("missing uncertainty", err)
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			proc := uint32(2)
			if strings.HasPrefix(tt.name, "link") {
				proc = 15
			}
			if strings.HasPrefix(tt.name, "symlink") {
				proc = 10
			}
			if p.calls[proc] != 1 {
				t.Fatal("mutation replayed", p.calls)
			}
		})
	}
}
