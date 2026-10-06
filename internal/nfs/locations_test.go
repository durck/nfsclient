package nfs

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

func locationFixture() encoder {
	var e encoder
	e.u32(2)
	e.str("data")
	e.str("junction")
	e.u32(1)
	e.u32(1)
	e.str("replica.test")
	e.u32(1)
	e.str("relocated")
	return e
}

func TestLocationsBoundedWire(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, mode := range []string{"valid", "truncated", "trailing", "depth", "locations", "servers", "empty-server", "dot-path", "slash-path", "bad-utf8", "missing-bit", "unsolicited", "moved-lookup"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				v := peer4(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
					var e encoder
					switch code {
					case 15:
						if d.str() != "junction" {
							t.Error("lookup changed")
						}
						if mode == "moved-lookup" {
							return nil, 10019, nil
						}
					case 9:
						if !slices.Equal(readBitmap4(d), []uint32{24}) {
							t.Error("GETATTR requested absent-file attributes")
						}
						bits := []uint32{24}
						a := locationFixture()
						switch mode {
						case "truncated":
							a = a[:len(a)-1]
						case "trailing":
							a = append(a, 0)
						case "depth":
							a = nil
							a.u32(65)
						case "locations":
							a = nil
							a.u32(0)
							a.u32(9)
						case "servers":
							a = nil
							a.u32(0)
							a.u32(1)
							a.u32(9)
						case "empty-server":
							a = nil
							a.u32(0)
							a.u32(1)
							a.u32(1)
							a.str("")
						case "dot-path", "slash-path", "bad-utf8":
							a = nil
							a.u32(1)
							a.str(map[string]string{"dot-path": "..", "slash-path": "a/b", "bad-utf8": "\xff"}[mode])
						case "missing-bit":
							bits = nil
						case "unsolicited":
							bits = []uint32{4, 24}
						}
						bitmap4(&e, bits...)
						e.opaque(a)
					default:
						t.Errorf("unexpected referral operation %d", code)
					}
					return e, 0, nil
				})
				out, err := v.c.Locations(context.Background(), []byte("parent"), "junction")
				if (err == nil) != (mode == "valid") {
					t.Fatal("wrong bounded-wire decision", err)
				}
				if err == nil && (!slices.Equal(out.Root, []string{"data", "junction"}) || len(out.Locations) != 1 || out.Locations[0].Servers[0] != "replica.test") {
					t.Fatal("wrong namespace decode")
				}
			})
		}
	}
}

func TestMovedReplyRejectsTrailingBody(t *testing.T) {
	v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
		if code == 15 {
			d.str()
			return encoder{0, 0, 0, 1}, 10019, nil
		}
		return nil, 0, nil
	})
	_, err := v.lookup(context.Background(), []byte("parent"), "junction")
	if err == nil || !v.stateLost.Load() {
		t.Fatal("malformed MOVED accepted as an authorized namespace transition", err)
	}
}
