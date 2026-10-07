package nfs

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestNamespaceV4LinkWire(t *testing.T) {
	for _, status := range []Status{0, 1, 17, 18} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var handles []string
			var ops []uint32
			v := peer4WithHandle(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				ops = append(ops, code)
				var e encoder
				switch code {
				case 32:
				case 11:
					if d.str() != "alias" {
						return nil, 0, errors.New("wrong hardlink name")
					}
					if status != 0 {
						return nil, status, nil
					}
					e.u32(1)
					e.u64(1)
					e.u64(2)
				default:
					return nil, 0, fmt.Errorf("unexpected op %d", code)
				}
				return e, 0, nil
			}, func(fh []byte) error { handles = append(handles, string(fh)); return nil })
			err := v.c.Link(context.Background(), []byte("source"), []byte("parent"), "alias")
			if status == 0 && err != nil || status != 0 && !errors.Is(err, status) {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(handles, []string{"source", "parent"}) || !reflect.DeepEqual(ops, []uint32{32, 11}) {
				t.Fatal(handles, ops)
			}
		})
	}
}

func TestNamespaceV4SymlinkWire(t *testing.T) {
	for _, scenario := range []string{"success", "exists", "denied", "getfh-failed", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			v := peer4(t, 0, func(code uint32, d *decoder) (encoder, Status, error) {
				var e encoder
				switch code {
				case 6:
					calls++
					if d.u32() != 5 || d.str() != "../missing/./target" || d.str() != "link" || !reflect.DeepEqual(readBitmap4(d), []uint32{33}) {
						return nil, 0, errors.New("symlink target or request changed")
					}
					a := &decoder{b: d.opaque(32)}
					if a.u32() != 0777 || a.err != nil || len(a.b) != 0 {
						return nil, 0, errors.New("wrong mode")
					}
					if scenario == "exists" {
						return nil, 17, nil
					}
					if scenario == "denied" {
						return nil, 13, nil
					}
					if scenario == "malformed" {
						return e, 0, nil
					}
					e.u32(1)
					e.u64(1)
					e.u64(2)
					bitmap4(&e, 33)
				case 10:
					if scenario == "getfh-failed" {
						return nil, 5, nil
					}
					e.opaque([]byte("made"))
				default:
					return nil, 0, fmt.Errorf("unexpected op %d", code)
				}
				return e, 0, nil
			})
			err := v.c.Symlink(context.Background(), []byte("parent"), "link", "../missing/./target")
			if calls != 1 {
				t.Fatal(calls)
			}
			switch scenario {
			case "success":
				if err != nil {
					t.Fatal(err)
				}
			case "exists":
				if !errors.Is(err, Status(17)) || errors.Is(err, ErrMutationUncertain) {
					t.Fatal(err)
				}
			case "denied":
				if !errors.Is(err, Status(13)) || errors.Is(err, ErrMutationUncertain) {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, ErrMutationUncertain) {
					t.Fatal(err)
				}
			}
		})
	}
}
