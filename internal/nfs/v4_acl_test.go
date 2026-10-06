package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
)

func acl4TestPolicy(attribute string) (*NFS4ACL, encoder) {
	// Literal RFC 8881 values; the oracle never calls the production ACL codec.
	entries := []replacementTestACE{{1, 0, 2, "bob@example.test"}, {0, 0, 0x1f01ff, "OWNER@"}, {0, 0, 1, "bob@example.test"}, {0, 0x40, 1, "readers@example.test"}, {0, 0, 1, "bob@example.test"}}
	flags := uint32(0)
	if attribute == "dacl" {
		flags = 3
		entries[2].flags = 0x8b
	}
	if attribute == "sacl" {
		flags = 4
		entries = []replacementTestACE{{2, 0x10, 1, "EVERYONE@"}, {3, 0xa0, 2, "bob@example.test"}, {2, 0, 1, "OWNER@"}}
	}
	acl := &NFS4ACL{Attribute: attribute, Flags: flags, Entries: []NFS4ACE{}}
	for _, a := range entries {
		acl.Entries = append(acl.Entries, NFS4ACE{a.kind, a.flags, a.mask, a.who})
	}
	wire := replacementTestACL(entries...)
	if attribute != "acl" {
		wire = append(replacementTestU32(flags), wire...)
	}
	return acl, wire
}

type aclCredentialObserver struct {
	net.Conn
	client *Client
	calls  int
}

func (c *aclCredentialObserver) Write(packet []byte) (int, error) {
	d := &decoder{b: packet}
	d.u32() // TCP record marker.
	for range 6 {
		d.u32()
	} // RPC call header through procedure.
	if d.u32() != 1 {
		return 0, errors.New("ACL request changed AUTH_SYS flavor")
	}
	a := &decoder{b: d.opaque(400)}
	a.u32()
	a.str()
	if a.u32() != 32123 || a.u32() != 32124 || a.u32() != 1 || a.u32() != 32125 || a.err != nil || len(a.b) != 0 {
		return 0, errors.New("ACL requests did not retain selected credentials")
	}
	c.calls++
	if c.calls == 1 {
		// Change the foreground profile synchronously after its first RPC was
		// encoded. Mutation/readback must use the original snapshot, including
		// a deep copy of supplementary groups.
		c.client.Auth.UID = 0
		c.client.Auth.GID = 0
		c.client.Auth.Groups[0] = 0
	}
	return c.Conn.Write(packet)
}

func TestNFS4ACLFixedCredentials(t *testing.T) {
	want, wire := acl4TestPolicy("acl")
	fields := replacementTestAttrs()
	fields[12] = wire
	v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
		if code == 9 {
			return replacementTestReply(readBitmap4(d), fields), 0, nil
		}
		if code != 34 {
			return nil, 0, fmt.Errorf("unexpected operation %d", code)
		}
		d.take(16)
		readBitmap4(d)
		d.opaque(65536)
		var e encoder
		bitmap4(&e, 12)
		return e, 0, nil
	})
	v.c.Auth = Auth{UID: 32123, GID: 32124, Groups: []uint32{32125}}
	observer := &aclCredentialObserver{Conn: v.c.nfs.conn, client: v.c}
	v.c.nfs.conn = observer
	if err := v.c.SetNFS4ACL(context.Background(), []byte("file"), want); err != nil {
		t.Fatal(err)
	}
	if observer.calls != 3 {
		t.Fatalf("calls=%d", observer.calls)
	}
}

func TestNFS4ACLOrderedRoundTrip(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, attribute := range []string{"acl", "dacl", "sacl"} {
			if minor == 0 && attribute != "acl" {
				continue
			}
			t.Run(fmt.Sprintf("4.%d/%s", minor, attribute), func(t *testing.T) {
				want, wire := acl4TestPolicy(attribute)
				bit := map[string]uint32{"acl": 12, "dacl": 58, "sacl": 59}[attribute]
				fields := replacementTestAttrs()
				var supported encoder
				bitmap4(&supported, 0, 1, 12, 13, 58, 59)
				fields[0], fields[13], fields[bit] = supported, replacementTestU32(15), wire
				if attribute != "acl" {
					fields[1] = replacementTestU32(2)
				}
				var calls []uint32
				v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
					calls = append(calls, code)
					switch code {
					case 9:
						return replacementTestReply(readBitmap4(d), fields), 0, nil
					case 34:
						if !bytes.Equal(d.take(16), make([]byte, 16)) || !slices.Equal(readBitmap4(d), []uint32{bit}) || !bytes.Equal(d.opaque(65536), wire) {
							return nil, 0, errors.New("SETATTR changed order, identity, flags, mask or unrelated attributes")
						}
						var e encoder
						bitmap4(&e, bit)
						return e, 0, nil
					default:
						return nil, 0, fmt.Errorf("unexpected payload/state operation %d", code)
					}
				})
				ctx := context.Background()
				got, err := v.c.GetNFS4ACL(ctx, []byte("file"), attribute)
				if err != nil || got.Flags != want.Flags || !slices.Equal(got.Entries, want.Entries) {
					t.Fatalf("get=%+v err=%v", got, err)
				}
				if err := v.c.SetNFS4ACL(ctx, []byte("file"), got); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(calls, []uint32{9, 9, 34, 9}) {
					t.Fatalf("operations %v", calls)
				}
			})
		}
	}
}

func TestNFS4ACLRefusalsAndReadback(t *testing.T) {
	for _, mode := range []string{"missing", "unsupported", "unadvertised", "read-denied", "write-denied", "readonly", "malformed", "bad-ack", "changed-order", "changed-flags", "readback-denied", "budget"} {
		t.Run(mode, func(t *testing.T) {
			want, wire := acl4TestPolicy("acl")
			fields := replacementTestAttrs()
			fields[12] = wire
			reads, writes := 0, 0
			v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
				switch code {
				case 9:
					reads++
					bits := readBitmap4(d)
					if mode == "read-denied" || mode == "readback-denied" && reads > 1 {
						return nil, 13, nil
					}
					if mode == "unsupported" {
						return nil, 10032, nil
					}
					if mode == "missing" {
						delete(fields, 12)
					}
					if mode == "unadvertised" {
						fields[13] = replacementTestU32(1)
					}
					if mode == "malformed" {
						fields[12] = wire[:len(wire)-1]
					}
					return replacementTestReply(bits, fields), 0, nil
				case 34:
					writes++
					d.take(16)
					readBitmap4(d)
					d.opaque(65536)
					var e encoder
					if mode == "write-denied" || mode == "readonly" {
						bitmap4(&e)
						status := Status(13)
						if mode == "readonly" {
							status = 30
						}
						return e, status, nil
					}
					if mode == "bad-ack" {
						bitmap4(&e)
						return e, 0, nil
					}
					if mode == "changed-order" {
						fields[12] = replacementTestACL(replacementTestACE{0, 0, 1, "bob@example.test"}, replacementTestACE{1, 0, 2, "bob@example.test"})
					}
					if mode == "changed-flags" {
						fields[12] = replacementTestACL(replacementTestACE{1, 0x40, 2, "bob@example.test"})
					}
					bitmap4(&e, 12)
					return e, 0, nil
				default:
					return nil, 0, fmt.Errorf("payload changed: op %d", code)
				}
			})
			if mode == "budget" {
				v.maxRequestPayload = 64
			}
			err := v.c.SetNFS4ACL(context.Background(), []byte("file"), want)
			if err == nil {
				t.Fatal("policy loss accepted")
			}
			if mode == "write-denied" && !errors.Is(err, Status(13)) || mode == "readonly" && !errors.Is(err, Status(30)) || mode == "unsupported" && !errors.Is(err, Status(10032)) {
				t.Fatalf("lost server status: %v", err)
			}
			if strings.HasPrefix(mode, "changed-") || mode == "readback-denied" {
				if !strings.Contains(err.Error(), "SETATTR succeeded") || reads != 2 || writes != 1 {
					t.Fatalf("ambiguous result: %v %d/%d", err, reads, writes)
				}
			}
			if mode == "missing" || mode == "unadvertised" || mode == "read-denied" || mode == "malformed" || mode == "unsupported" || mode == "budget" {
				if writes != 0 {
					t.Fatal("preflight failure wrote policy")
				}
			}
		})
	}
}

func TestValidateNFS4ACL(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*NFS4ACL)
	}{
		{"type", func(a *NFS4ACL) { a.Entries[0].Type = 4 }},
		{"mask", func(a *NFS4ACL) { a.Entries[0].Mask = 0x200000 }},
		{"flag", func(a *NFS4ACL) { a.Entries[0].Flags = 0x100 }},
		{"inherited-acl", func(a *NFS4ACL) { a.Entries[0].Flags = 0x80 }},
		{"allow-audit-flags", func(a *NFS4ACL) { a.Entries[0].Flags = 0x10 }},
		{"attribute", func(a *NFS4ACL) { a.Attribute = "ACL" }},
		{"acl-flags", func(a *NFS4ACL) { a.Flags = 1 }},
		{"null-entries", func(a *NFS4ACL) { a.Entries = nil }},
		{"empty-who", func(a *NFS4ACL) { a.Entries[0].Who = "" }},
		{"control-who", func(a *NFS4ACL) { a.Entries[0].Who = "bad\nwho" }},
		{"oversize-who", func(a *NFS4ACL) { a.Entries[0].Who = strings.Repeat("x", 4097) }},
		{"count", func(a *NFS4ACL) { a.Entries = make([]NFS4ACE, 1025) }},
		{"sacl-allow", func(a *NFS4ACL) { a.Attribute = "sacl" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := acl4TestPolicy("acl")
			tc.mutate(a)
			if err := ValidateNFS4ACL(a); err == nil {
				t.Fatal("invalid policy accepted")
			}
			if err := (&Client{}).SetNFS4ACL(context.Background(), nil, a); err == nil {
				t.Fatal("invalid policy sent")
			}
		})
	}
	for _, attribute := range []string{"acl", "dacl", "sacl"} {
		a := &NFS4ACL{Attribute: attribute, Entries: []NFS4ACE{}}
		if err := ValidateNFS4ACL(a); err != nil {
			t.Fatal(err)
		}
	}
	// RFC 8881 6.2.1.4.1: both event flags absent is valid for AUDIT/ALARM.
	for _, kind := range []uint32{2, 3} {
		if err := ValidateNFS4ACL(&NFS4ACL{Attribute: "sacl", Entries: []NFS4ACE{{Type: kind, Mask: 1, Who: "OWNER@"}}}); err != nil {
			t.Fatal(err)
		}
	}
}
