package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func legacyTestDocument(version, typ uint32) legacyACLDocument {
	d := legacyACLDocument{Version: version, Type: typ, UID: 20001, GID: 20003, Mode: 0640,
		Access: []legacyACLEntry{{1, 20001, 6}, {2, 20002, 7}, {4, 20003, 0}, {16, 0, 4}, {32, 0, 0}}, Default: []legacyACLEntry{}}
	if typ == 2 {
		d.Default = append(d.Default, d.Access...)
	}
	return d
}

func TestLegacyACLJSONStrict(t *testing.T) {
	valid, _ := json.Marshal(legacyTestDocument(3, 2))
	for _, edit := range []struct{ old, new string }{
		{`"version":3`, `"version":4`}, {`"version":3`, `"version":2,"version":3`},
		{`"type":2`, `"Type":2`}, {`"uid":20001`, `"uid":20002`}, {`"type":2`, `"type":5`},
		{`"mode":416`, `"mode":448`}, {`"perm":7`, `"perm":8`}, {`"id":20002`, `"id":4294967296`},
		{`"tag":2`, `"tag":3`}, {`"tag":2`, `"tag":null`}, {`"tag":2`, `"tag":2,"tag":2`},
		{`"tag":2,`, ``}, {`"gid":20003`, `"gid":-1`}, {`"mode":416`, `"mode":416.1`},
	} {
		bad := strings.Replace(string(valid), edit.old, edit.new, 1)
		if bad == string(valid) {
			t.Fatalf("test did not modify %s", edit.old)
		}
		if _, _, err := parseLegacyACLJSON([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	for _, bad := range []string{`null`, `[]`, `{}`, string(valid) + `{}`, strings.Replace(string(valid), `"access":[`, `"extra":1,"access":[`, 1)} {
		if _, _, err := parseLegacyACLJSON([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	file, _ := json.Marshal(legacyTestDocument(2, 1))
	for _, replacement := range []string{`"default":null`, `"default":{}`, `"omitted":[]`} {
		if _, _, err := parseLegacyACLJSON([]byte(strings.Replace(string(file), `"default":[]`, replacement, 1))); err == nil {
			t.Fatal(replacement)
		}
	}
	if p, v, err := parseLegacyACLJSON(file); err != nil || v != 2 || p.Default == nil || len(p.Access) != 5 {
		t.Fatalf("roundtrip: %+v %d %v", p, v, err)
	}
}

// Independent loopback wire peer: checks protocol version, handles and AUTH_SYS
// on every observation/mutation, and retains applied policy after a lost reply.
type legacyACLPeer struct {
	mu                  sync.Mutex
	doc                 legacyACLDocument
	fault               string
	sets, gets, lookups int
}

func (p *legacyACLPeer) attr(typ uint32) []byte {
	d := p.doc
	if d.Version == 2 {
		bits := uint32(0100000)
		if typ == 2 {
			bits = 0040000
		}
		if typ == 5 {
			bits = 0120000
		}
		return missingV4Words(nil, typ, bits|d.Mode, 1, d.UID, d.GID, 17, 4096, 0, 1, 9, 41, 100, 0, 100, 0, 101, 0)
	}
	b := missingV4Words(nil, typ, d.Mode, 1, d.UID, d.GID, 0, 17, 0, 4096, 0, 0, 0, 9, 0, 41, 100, 0, 100, 0, 101, 0)
	return b
}

func (p *legacyACLPeer) policyBody() []byte {
	b := missingV4Words(nil, 0)
	if p.doc.Version == 3 {
		b = missingV4Words(b, 1)
	}
	b = append(b, p.attr(p.doc.Type)...)
	b = missingV4Words(b, 15)
	for i, entries := range [][]legacyACLEntry{p.doc.Access, p.doc.Default} {
		b = missingV4Words(b, uint32(len(entries)), uint32(len(entries)))
		for _, e := range entries {
			tag := e.Tag
			if i == 1 {
				tag |= 0x1000
			}
			b = missingV4Words(b, tag, e.ID, e.Perm)
		}
	}
	return b
}

func (p *legacyACLPeer) request(raw []byte) ([]byte, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := &missingV4Decoder{b: raw}
	xid := d.word()
	if d.word() != 0 || d.word() != 2 {
		return nil, false, errors.New("bad RPC header")
	}
	program, version, proc := d.word(), d.word(), d.word()
	wantVersion := p.doc.Version
	if program == 100005 && wantVersion == 2 {
		wantVersion = 1
	}
	if version != wantVersion {
		return nil, false, fmt.Errorf("version %d", version)
	}
	if d.word() != 1 {
		return nil, false, errors.New("identity flavor changed")
	}
	cred := &missingV4Decoder{b: d.opaque()}
	cred.word()
	cred.opaque()
	if cred.word() != 32123 || cred.word() != 32124 || cred.word() != 1 || cred.word() != 32125 || cred.err != nil || len(cred.b) != 0 {
		return nil, false, errors.New("selected identity changed")
	}
	if d.word() != 0 || len(d.opaque()) != 0 {
		return nil, false, errors.New("unexpected verifier")
	}
	var body []byte
	if program == 100005 && (proc == 1 || proc == 3) {
		if string(d.opaque()) != "/" || d.err != nil || len(d.b) != 0 {
			return nil, false, errors.New("unexpected mount path")
		}
		if proc == 1 {
			body = missingV4Words(nil, 0)
			if version == 1 {
				body = append(body, make([]byte, 32)...)
			} else {
				body = missingV4Opaque(body, make([]byte, 32))
				body = missingV4Words(body, 1, 1)
			}
		}
		return append(missingV4Words(nil, xid, 1, 0, 0, 0, 0), body...), false, nil
	}
	if proc == 0 && program == 100003 {
		return missingV4Words(nil, xid, 1, 0, 0, 0, 0), false, nil
	}
	var handle []byte
	if version == 2 {
		handle = d.take(32)
	} else {
		handle = d.opaque()
	}
	if len(handle) != 32 {
		return nil, false, errors.New("invalid handle")
	}
	if program == 100003 && handle[0] == 0 && proc == 1 {
		body = append(missingV4Words(nil, 0), p.attr(2)...)
	} else if program == 100003 && handle[0] == 0 && version == 2 && proc == 16 {
		d.take(8)
		body = missingV4Words(nil, 0, 0, 1)
	} else if program == 100003 && handle[0] == 0 && version == 3 && proc == 17 {
		d.take(24)
		body = missingV4Words(nil, 0, 0, 0, 0, 0, 1)
	} else if program == 100003 && handle[0] == 0 && version == 2 && proc == 17 {
		body = missingV4Words(nil, 0, 8192, 4096, 100, 90, 80)
	} else if program == 100003 && handle[0] == 0 && version == 3 && proc == 19 {
		body = missingV4Words(nil, 0, 0, 32768, 32768, 4096, 32768, 32768, 4096, 32768, 0, 1<<30, 0, 1, 0)
	} else if program == 100003 && (proc == 3 && version == 3 || proc == 4 && version == 2) {
		p.lookups++
		if handle[0] != 0 {
			return nil, false, errors.New("wrong lookup parent")
		}
		name := string(d.opaque())
		typ := p.doc.Type
		if name == "link" {
			typ = 5
		} else if name != "target" {
			return nil, false, fmt.Errorf("unknown path %s", name)
		}
		body = missingV4Words(nil, 0)
		fh := bytes.Repeat([]byte{1}, 32)
		if version == 2 {
			body = append(body, fh...)
		} else {
			body = missingV4Opaque(body, fh)
			body = missingV4Words(body, 1)
		}
		body = append(body, p.attr(typ)...)
		if version == 3 {
			body = missingV4Words(body, 0)
		}
	} else if program == 100227 && handle[0] == 1 && proc == 1 {
		p.gets++
		if d.word() != 15 {
			return nil, false, errors.New("incomplete GETACL mask")
		}
		body = p.policyBody()
		if p.fault == "unsupported" {
			body = missingV4Words(nil, 10004)
		}
		if p.fault == "selected-change" {
			if version == 2 {
				binary.BigEndian.PutUint32(body[44:], 42)
			} else {
				binary.BigEndian.PutUint32(body[64:], 42)
			}
		}
	} else if program == 100227 && handle[0] == 1 && proc == 2 {
		p.sets++
		if d.word() != 5 {
			return nil, false, errors.New("incomplete SETACL mask")
		}
		for i, target := range []*[]legacyACLEntry{&p.doc.Access, &p.doc.Default} {
			count, length := d.word(), d.word()
			if count != length || count > 1024 {
				return nil, false, errors.New("bad ACL count")
			}
			*target = []legacyACLEntry{}
			for j := uint32(0); j < count; j++ {
				tag, id, perm := d.word(), d.word(), d.word()
				if (tag&0x1000 != 0) != (i == 1) {
					return nil, false, errors.New("bad default flag")
				}
				*target = append(*target, legacyACLEntry{tag &^ 0x1000, id, perm})
			}
		}
		p.doc.Mode = p.doc.Access[0].Perm << 6
		for _, e := range p.doc.Access {
			if e.Tag == 16 {
				p.doc.Mode |= e.Perm << 3
			}
			if e.Tag == 32 {
				p.doc.Mode |= e.Perm
			}
		}
		if p.fault == "lost-reply" {
			return nil, true, nil
		}
		if p.fault == "readback-mismatch" {
			p.doc.Access[1].Perm = 1
		}
		body = missingV4Words(nil, 0)
		if version == 3 {
			body = missingV4Words(body, 1)
		}
		body = append(body, p.attr(p.doc.Type)...)
	} else {
		return nil, false, fmt.Errorf("unexpected RPC %d/%d", program, proc)
	}
	if d.err != nil || len(d.b) != 0 {
		return nil, false, errors.New("trailing or malformed request")
	}
	return append(missingV4Words(nil, xid, 1, 0, 0, 0, 0), body...), false, nil
}

func legacyACLListener(t *testing.T, version, typ uint32) (int, *legacyACLPeer) {
	t.Helper()
	p := &legacyACLPeer{doc: legacyTestDocument(version, typ)}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				for {
					var header [4]byte
					if _, err := io.ReadFull(conn, header[:]); err != nil {
						return
					}
					size := binary.BigEndian.Uint32(header[:])
					if size&0x80000000 == 0 || size&0x7fffffff > 1<<20 {
						t.Error("invalid RPC record")
						return
					}
					raw := make([]byte, size&0x7fffffff)
					if _, err := io.ReadFull(conn, raw); err != nil {
						return
					}
					reply, drop, err := p.request(raw)
					if err != nil {
						t.Error(err)
						return
					}
					if drop {
						return
					}
					wire := append(missingV4Words(nil, 0x80000000|uint32(len(reply))), reply...)
					if _, err := conn.Write(wire); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); wg.Wait() })
	return l.Addr().(*net.TCPAddr).Port, p
}

func legacyACLShell(t *testing.T, version, typ uint32) (*Shell, *legacyACLPeer, *bytes.Buffer) {
	t.Helper()
	port, p := legacyACLListener(t, version, typ)
	c, err := nfs.Connect(context.Background(), nfs.Config{Host: "127.0.0.1", Version: strconv.Itoa(int(version)), NFSPort: port, MountPort: port, Timeout: time.Second, Auth: nfs.Auth{UID: 32123, GID: 32124, Groups: []uint32{32125}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	sess := session.New(c, "127.0.0.1", false, false, nil)
	sess.Export = "/"
	sess.AutoUID = true
	sess.Root = nfs.Node{Handle: make([]byte, 32), Attr: nfs.Attr{Type: 2, UID: 999, GID: 999}}
	out := &bytes.Buffer{}
	return &Shell{Session: sess, Out: out, Err: io.Discard, LocalDir: t.TempDir()}, p, out
}

func TestLegacyACLCLIWireRoundTrip(t *testing.T) {
	for _, version := range []uint32{2, 3} {
		for _, typ := range []uint32{1, 2} {
			t.Run(fmt.Sprintf("v%d/type%d", version, typ), func(t *testing.T) {
				sh, p, out := legacyACLShell(t, version, typ)
				auth := sh.Session.Client.Auth
				ctx := context.Background()
				if _, err := sh.Execute(ctx, "getacl target policy.json"); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(filepath.Join(sh.LocalDir, "policy.json"))
				if err != nil {
					t.Fatal(err)
				}
				var doc legacyACLDocument
				if err := json.Unmarshal(data, &doc); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(doc, legacyTestDocument(version, typ)) {
					t.Fatalf("export lost policy: %+v", doc)
				}
				doc.Access[1].Perm = 5
				data, _ = json.Marshal(doc)
				if err := os.WriteFile(filepath.Join(sh.LocalDir, "edit.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := sh.Execute(ctx, "setacl target edit.json"); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), "exact readback verified") {
					t.Fatal(out.String())
				}
				if _, err := sh.Execute(ctx, "getacl target policy.json"); !errors.Is(err, os.ErrExist) {
					t.Fatalf("export overwrite: %v", err)
				}
				if typ == 2 {
					doc.Default = []legacyACLEntry{}
					data, _ = json.Marshal(doc)
					if err := os.WriteFile(filepath.Join(sh.LocalDir, "edit.json"), data, 0600); err != nil {
						t.Fatal(err)
					}
					if _, err := sh.Execute(ctx, "setacl target edit.json"); err != nil {
						t.Fatal(err)
					}
				}
				p.mu.Lock()
				observed := p.doc
				sets := p.sets
				p.mu.Unlock()
				if !reflect.DeepEqual(doc, observed) || sets != int(typ) {
					t.Fatalf("policy/readback: %+v sets=%d", observed, sets)
				}
				if !sh.Session.AutoUID || !reflect.DeepEqual(auth, sh.Session.Client.Auth) {
					t.Fatal("identity changed")
				}
			})
		}
	}
}

func TestLegacyACLCLIWireRefusals(t *testing.T) {
	for _, version := range []uint32{2, 3} {
		for _, fault := range []string{"malformed", "owner", "type", "version", "symlink", "intermediate-symlink", "unsupported", "selected-change", "lost-reply", "readback-mismatch"} {
			t.Run(fmt.Sprintf("v%d/%s", version, fault), func(t *testing.T) {
				sh, p, out := legacyACLShell(t, version, 2)
				doc := legacyTestDocument(version, 2)
				doc.Access[1].Perm = 5
				path := "target"
				switch fault {
				case "owner":
					doc.UID = 20002
					doc.Access[0].ID = 20002
					doc.Default[0].ID = 20002
				case "type":
					doc.Type = 1
					doc.Default = []legacyACLEntry{}
				case "version":
					doc.Version = 5 - version
				case "symlink":
					path = "link"
				case "intermediate-symlink":
					path = "link/target"
				}
				data, _ := json.Marshal(doc)
				if fault == "malformed" {
					data = []byte(`{"version":3}`)
				}
				if err := os.WriteFile(filepath.Join(sh.LocalDir, "policy.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
				p.mu.Lock()
				p.fault = fault
				p.mu.Unlock()
				_, err := sh.Execute(context.Background(), "setacl "+path+" policy.json")
				if err == nil || out.Len() != 0 {
					t.Fatalf("false success: %s %v", out.String(), err)
				}
				uncertain := fault == "lost-reply" || fault == "readback-mismatch"
				if errors.Is(err, nfs.ErrNFSACLMutationUnverified) != uncertain {
					t.Fatalf("uncertainty classification: %v", err)
				}
				if fault == "unsupported" && !errors.Is(err, nfs.ErrNFSACLUnavailable) {
					t.Fatal(err)
				}
				p.mu.Lock()
				sets, lookups := p.sets, p.lookups
				applied := p.doc.Access[1].Perm
				p.mu.Unlock()
				wantSets := 0
				if uncertain {
					wantSets = 1
				}
				if sets != wantSets {
					t.Fatalf("mutation count %d: %v", sets, err)
				}
				if fault == "lost-reply" && applied != 5 {
					t.Fatal("lost-reply policy rolled back")
				}
				if (fault == "malformed" || fault == "version") && lookups != 0 {
					t.Fatal("invalid policy reached network")
				}
				if !sh.Session.AutoUID || sh.Session.Client.Auth.UID != 32123 {
					t.Fatal("selected identity changed")
				}
			})
		}
	}
}
