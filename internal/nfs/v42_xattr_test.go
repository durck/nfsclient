package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type xattrPeerState struct {
	variant      string
	values       map[string][]byte
	ops          []uint32
	attrs, pages int
}

func xattrPeer42(t *testing.T, p *xattrPeerState) *Client {
	t.Helper()
	if p.values == nil {
		p.values = map[string][]byte{}
	}
	v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		if code == 53 {
			e = append(e, d.take(16)...)
			e.u32(d.u32())
			//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
			if d.u32() != 0 || d.u32() != 0 {
				return nil, 0, errors.New("slot")
			}
			cache := d.boolean()
			next := &decoder{b: d.b}
			next.u32()
			next.opaque(128)
			operation := next.u32()
			if cache != (operation == 73 || operation == 75) {
				return nil, 0, fmt.Errorf("xattr cache policy %d", operation)
			}
			for range 4 {
				e.u32(0)
			}
			return e, 0, nil
		}
		p.ops = append(p.ops, code)
		switch code {
		case 9:
			bits := readBitmap4(d)
			var a encoder
			if len(bits) == 1 && bits[0] == 0 {
				bitmap4(&e, 0)
				if p.variant == "unadvertised" {
					bitmap4(&a, 0, 1, 3)
				} else {
					bitmap4(&a, 0, 1, 3, 82)
				}
			} else if len(bits) == 1 && bits[0] == 82 {
				if p.variant == "omitted" {
					bitmap4(&e)
				} else {
					bitmap4(&e, 82)
					value := uint32(1)
					if p.variant == "unsupported" {
						value = 0
					}
					if p.variant == "bad-support-bool" {
						value = 2
					}
					a.u32(value)
				}
			} else {
				p.attrs++
				bitmap4(&e, 1, 3)
				a.u32(1)
				change := uint64(7)
				if p.variant == "changed" && p.attrs > 1 {
					change++
				}
				a.u64(change)
			}
			e.opaque(a)
		case 72:
			key := d.str()
			value, ok := p.values[key]
			if !ok {
				return nil, 10095, nil
			}
			if p.variant == "oversized" {
				value = make([]byte, MaxXattrValue+1)
			}
			if p.variant == "mismatch" {
				value = []byte("unexpected")
			}
			e.opaque(value)
			if p.variant == "truncated" {
				e = e[:len(e)-1]
			}
		case 73:
			option, key := d.u32(), d.str()
			value := d.opaque(MaxXattrValue)
			if p.variant == "denied" {
				return nil, 13, nil
			}
			_, exists := p.values[key]
			if option == 1 && exists {
				return nil, 17, nil
			}
			if option == 2 && !exists {
				return nil, 10095, nil
			}
			p.values[key] = append([]byte(nil), value...)
			if p.variant == "bad-change" {
				e.u32(2)
			} else {
				e.u32(1)
			}
			e.u64(7)
			e.u64(8)
		case 75:
			key := d.str()
			if _, ok := p.values[key]; !ok {
				return nil, 10095, nil
			}
			if p.variant != "remove-unapplied" {
				delete(p.values, key)
			}
			e.u32(1)
			e.u64(7)
			e.u64(8)
		case 74:
			cookie, limit := d.u64(), d.u32()
			if limit != 65536 {
				return nil, 0, errors.New("wrong LISTXATTRS limit")
			}
			p.pages++
			next := uint64(9)
			eof := uint32(0)
			names := []string{"z"}
			if cookie == 9 {
				next = 10
				eof = 1
				names = []string{"a"}
			}
			switch p.variant {
			case "cycle":
				next = 0
			case "duplicate":
				if cookie == 9 {
					names = []string{"z"}
				}
			case "empty":
				names = nil
				eof = 1
			case "no-progress":
				names = nil
			case "bad-eof":
				eof = 2
			case "bad-name":
				names = []string{"a\x00b"}
			case "invalid-utf8":
				names = []string{"\xff"}
			case "long-name":
				names = []string{strings.Repeat("x", 256)}
			}
			e.u64(next)
			if p.variant == "count-overflow" {
				e.u32(4097)
				return e, 0, nil
			}
			e.u32(uint32(len(names)))
			for _, name := range names {
				e.str(name)
			}
			e.u32(eof)
		default:
			return nil, 0, fmt.Errorf("unexpected xattr operation %d", code)
		}
		return e, 0, nil
	})
	v.session = bytes.Repeat([]byte{9}, 16)
	v.sequence = 1
	return v.c
}

func TestV42XattrRoundtrip(t *testing.T) {
	ctx := context.Background()
	p := &xattrPeerState{}
	c := xattrPeer42(t, p)
	fh := []byte("file")
	value := []byte{0, 255, 'a'}
	if err := c.SetXattr(ctx, fh, "example", value, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.SetXattr(ctx, fh, "example", value, 1); !errors.Is(err, Status(17)) {
		t.Fatal("create collision", err)
	}
	if err := c.SetXattr(ctx, fh, "missing", value, 2); !errors.Is(err, Status(10095)) {
		t.Fatal("replace missing", err)
	}
	if err := c.SetXattr(ctx, fh, "example", nil, 2); err != nil {
		t.Fatal("empty value", err)
	}
	if got, err := c.GetXattr(ctx, fh, "example"); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	if err := c.SetXattr(ctx, fh, "example", value, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveXattr(ctx, fh, "example"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveXattr(ctx, fh, "example"); !errors.Is(err, Status(10095)) {
		t.Fatal("remove missing", err)
	}
	if _, err := c.GetXattr(ctx, fh, "example"); !errors.Is(err, Status(10095)) {
		t.Fatal("get missing", err)
	}
}

func TestV42XattrCapabilityGate(t *testing.T) {
	for _, variant := range []string{"unadvertised", "unsupported", "omitted", "bad-support-bool"} {
		t.Run(variant, func(t *testing.T) {
			p := &xattrPeerState{variant: variant}
			c := xattrPeer42(t, p)
			if _, err := c.GetXattr(context.Background(), []byte("file"), "name"); err == nil {
				t.Fatal("unsupported operation sent")
			}
			for _, code := range p.ops {
				if code != 9 {
					t.Fatal("extension sent before support established", p.ops)
				}
			}
			if variant == "unadvertised" && len(p.ops) != 1 {
				t.Fatal("queried unadvertised attribute", p.ops)
			}
		})
	}
}

func TestV42XattrList(t *testing.T) {
	for _, variant := range []string{"valid", "empty", "cycle", "duplicate", "no-progress", "bad-eof", "bad-name", "invalid-utf8", "long-name", "count-overflow", "changed"} {
		t.Run(variant, func(t *testing.T) {
			p := &xattrPeerState{variant: variant}
			c := xattrPeer42(t, p)
			names, err := c.ListXattrs(context.Background(), []byte("file"))
			if variant == "valid" {
				if err != nil || strings.Join(names, ",") != "a,z" || p.pages != 2 {
					t.Fatal(names, err, p.pages)
				}
				return
			}
			if variant == "empty" {
				if err != nil || len(names) != 0 {
					t.Fatal(names, err)
				}
				return
			}
			if err == nil || names != nil || p.pages > 2 {
				t.Fatal("bad/partial listing exposed", names, err, p.pages)
			}
		})
	}
}

func TestV42XattrFailureNoReplay(t *testing.T) {
	for _, variant := range []string{"denied", "bad-change", "mismatch", "remove-unapplied", "oversized", "truncated"} {
		t.Run(variant, func(t *testing.T) {
			p := &xattrPeerState{variant: variant, values: map[string][]byte{"name": {1, 2, 3}}}
			c := xattrPeer42(t, p)
			var err error
			if variant == "remove-unapplied" {
				err = c.RemoveXattr(context.Background(), []byte("file"), "name")
			} else {
				err = c.SetXattr(context.Background(), []byte("file"), "name", []byte{1, 2, 3}, 0)
			}
			if err == nil {
				t.Fatal("failure missed")
			}
			mutations := 0
			for _, code := range p.ops {
				if code == 73 || code == 75 {
					mutations++
				}
			}
			if mutations != 1 {
				t.Fatal("mutation replayed", p.ops)
			}
			if variant == "bad-change" && !c.v4.stateLost.Load() {
				t.Fatal("bad change_info accepted")
			}
		})
	}
}

func TestV42XattrLocalRefusals(t *testing.T) {
	for _, name := range []string{"", "bad/name", "bad\x00name", "\xff", strings.Repeat("x", 256)} {
		if _, err := new(Client).GetXattr(context.Background(), nil, name); err == nil {
			t.Fatal("bad name", name)
		}
	}
	for _, variant := range []string{"old", "size", "option", "budget", "canceled", "read-lock", "partial", "uncertain", "identity"} {
		t.Run(variant, func(t *testing.T) {
			c := &Client{}
			v := &v4Client{c: c, minor: 2}
			c.v4 = v
			value := []byte{1}
			option := uint32(0)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch variant {
			case "old":
				v.minor = 1
			case "size":
				value = make([]byte, MaxXattrValue+1)
			case "option":
				option = 3
			case "budget":
				v.maxRequestPayload = 1
			case "canceled":
				cancel()
			default:
				l := &v4Lock{info: LockInfo{Write: true, Length: LockToEOF}, file: &v4Open{fh: []byte("file")}}
				v.locks = map[uint64]*v4Lock{1: l}
				if variant == "read-lock" {
					l.info.Write = false
				}
				if variant == "partial" {
					l.info.Length = 1
				}
				if variant == "uncertain" {
					l.info.Uncertain = true
				}
				if variant == "identity" {
					l.file.auth.UID = 1
				}
			}
			if err := c.SetXattr(ctx, []byte("file"), "name", value, option); err == nil {
				t.Fatal("local refusal missing")
			}
		})
	}
}
