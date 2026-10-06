package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

func labelPeer42(t *testing.T, variant string, locked bool, gets, sets *int) *Client {
	t.Helper()
	label := SecurityLabel{Format: 7, Policy: 42, Data: []byte{0, 255, 'a'}}
	v := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 53:
			e = append(e, d.take(16)...)
			e.u32(d.u32())
			//lint:ignore SA4000 Each decoder call consumes the next distinct wire field.
			if d.u32() != 0 || d.u32() != 0 {
				return nil, 0, errors.New("bad slot")
			}
			cache := d.boolean()
			// A SETATTR is cached; its separate variable GETATTR is not.
			next := &decoder{b: d.b}
			if next.u32() != 22 {
				return nil, 0, errors.New("missing fh")
			}
			next.opaque(128)
			if (next.u32() == 34) != cache {
				return nil, 0, errors.New("bad label cache policy")
			}
			for range 4 {
				e.u32(0)
			}
		case 9:
			*gets++
			bits := readBitmap4(d)
			if len(bits) != 1 || bits[0] != 80 {
				return nil, 0, errors.New("wrong requested label attribute")
			}
			if variant == "unsupported" {
				return nil, 10004, nil
			}
			if variant == "missing" {
				bitmap4(&e)
				e.opaque(nil)
				return e, 0, nil
			}
			if variant == "unsolicited" {
				bitmap4(&e, 79)
			} else {
				bitmap4(&e, 80)
			}
			var a encoder
			a.u32(label.Format)
			a.u32(label.Policy)
			if variant == "mismatch" {
				a.opaque([]byte("different"))
			} else if variant == "oversized" {
				a.opaque(make([]byte, MaxSecurityLabel+1))
			} else {
				a.opaque(label.Data)
			}
			if variant == "truncated" {
				a = a[:len(a)-1]
			}
			if variant == "trailing" {
				a.u32(1)
			}
			e.opaque(a)
		case 34:
			*sets++
			want := make([]byte, 16)
			if locked {
				want = bytes.Repeat([]byte{8}, 16)
			}
			if !bytes.Equal(d.take(16), want) {
				return nil, 0, errors.New("wrong label stateid")
			}
			bits := readBitmap4(d)
			if len(bits) != 1 || bits[0] != 80 {
				return nil, 0, errors.New("wrong label SETATTR bit")
			}
			a := &decoder{b: d.opaque(65536)}
			if a.u32() != label.Format || a.u32() != label.Policy || !bytes.Equal(a.opaque(MaxSecurityLabel), label.Data) || a.err != nil || len(a.b) != 0 {
				return nil, 0, errors.New("wrong label SETATTR value")
			}
			switch variant {
			case "denied":
				bitmap4(&e)
				return e, 13, nil
			case "bad-error":
				return nil, 13, nil
			case "error-trailing":
				bitmap4(&e)
				e.u32(7)
				return e, 13, nil
			case "error-unsolicited":
				bitmap4(&e, 33)
				return e, 13, nil
			case "unacknowledged":
				bitmap4(&e)
			default:
				bitmap4(&e, 80)
			}
		default:
			return nil, 0, fmt.Errorf("unexpected label op %d", code)
		}
		return e, 0, nil
	})
	v.session = bytes.Repeat([]byte{9}, 16)
	v.sequence = 1
	if locked {
		v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Write: true, Length: LockToEOF}, file: &v4Open{fh: []byte("file"), auth: v.c.Auth}, sid: bytes.Repeat([]byte{8}, 16)}}
	}
	return v.c
}

func TestV42SecurityLabelRead(t *testing.T) {
	for _, variant := range []string{"valid", "missing", "unsupported", "unsolicited", "oversized", "truncated", "trailing"} {
		t.Run(variant, func(t *testing.T) {
			gets, sets := 0, 0
			c := labelPeer42(t, variant, false, &gets, &sets)
			label, err := c.GetSecurityLabel(context.Background(), []byte("file"))
			if gets != 1 || sets != 0 {
				t.Fatal("unexpected calls", gets, sets)
			}
			if variant == "valid" {
				if err != nil || label.Format != 7 || label.Policy != 42 || !bytes.Equal(label.Data, []byte{0, 255, 'a'}) {
					t.Fatal(label, err)
				}
				return
			}
			if err == nil || len(label.Data) != 0 {
				t.Fatal("invalid label exposed", label, err)
			}
			if variant == "missing" && !errors.Is(err, Status(10032)) {
				t.Fatal(err)
			}
			if variant == "unsupported" && !errors.Is(err, Status(10004)) {
				t.Fatal(err)
			}
			if variant != "missing" && variant != "unsupported" && !c.v4.stateLost.Load() {
				t.Fatal("malformed attributes left connection reusable")
			}
		})
	}
}

func TestV42SecurityLabelSet(t *testing.T) {
	for _, locked := range []bool{false, true} {
		for _, variant := range []string{"valid", "denied", "bad-error", "error-trailing", "error-unsolicited", "unacknowledged", "mismatch", "missing"} {
			t.Run(fmt.Sprintf("%s/locked=%t", variant, locked), func(t *testing.T) {
				gets, sets := 0, 0
				c := labelPeer42(t, variant, locked, &gets, &sets)
				err := c.SetSecurityLabel(context.Background(), []byte("file"), SecurityLabel{7, 42, []byte{0, 255, 'a'}})
				if (err == nil) != (variant == "valid") || sets != 1 {
					t.Fatal("mutation/result", sets, gets, err)
				}
				if variant == "valid" || variant == "mismatch" || variant == "missing" {
					if gets != 1 {
						t.Fatal("missing readback", gets)
					}
				} else if gets != 0 {
					t.Fatal("readback after rejected mutation", gets)
				}
				if variant == "denied" && (!errors.Is(err, Status(13)) || c.v4.stateLost.Load()) {
					t.Fatal("confirmed denial", err)
				}
				if (variant == "bad-error" || variant == "error-trailing" || variant == "error-unsolicited" || variant == "unacknowledged") && !c.v4.stateLost.Load() {
					t.Fatal("malformed mutation reply left connection reusable")
				}
			})
		}
	}
}

func TestV42LabelLocalRefusals(t *testing.T) {
	for _, variant := range []string{"old", "oversized", "budget", "cancel", "read-lock", "partial", "uncertain", "identity"} {
		t.Run(variant, func(t *testing.T) {
			c := &Client{}
			v := &v4Client{c: c, minor: 2}
			c.v4 = v
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			label := SecurityLabel{Data: []byte("x")}
			switch variant {
			case "old":
				v.minor = 1
			case "oversized":
				label.Data = make([]byte, MaxSecurityLabel+1)
			case "budget":
				v.maxRequestPayload = 1
			case "cancel":
				cancel()
			default:
				l := &v4Lock{info: LockInfo{Write: true, Length: LockToEOF}, file: &v4Open{fh: []byte("file")}}
				v.locks = map[uint64]*v4Lock{1: l}
				if variant == "read-lock" {
					l.info.Write = false
				}
				if variant == "partial" {
					l.info.Length = 10
				}
				if variant == "uncertain" {
					l.info.Uncertain = true
				}
				if variant == "identity" {
					l.file.auth.UID = 5
				}
			}
			if err := c.SetSecurityLabel(ctx, []byte("file"), label); err == nil {
				t.Fatal("local refusal missing")
			}
		})
	}
}
