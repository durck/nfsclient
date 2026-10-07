package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

func namedInspectionPeer(t *testing.T, minor uint32, mode string) (*Client, *[]byte) {
	t.Helper()
	current := ""
	value := []byte{0, 255, 3, 4}
	if mode == "empty" {
		value = []byte{}
	}
	if mode == "maximum" {
		value = make([]byte, MaxNamedAttributeValue)
	}
	if mode == "large" || mode == "growth" {
		value = make([]byte, MaxNamedAttributeValue+1)
	}
	read, lookups := false, 0
	v := peer4WithHandle(t, minor, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 53:
			e = append(e, d.take(16)...)
			e.u32(d.u32())
			e.u32(d.u32())
			d.u32()
			d.boolean()
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 9:
			bits := readBitmap4(d)
			typ, size, change := uint32(1), uint64(0), uint64(7)
			if current == "dir" {
				typ = 8
			}
			if current == "attr" || current == "other" {
				typ, size = 9, uint64(len(value))
				if mode == "symlink" {
					typ = 5
				}
				if mode == "growth" {
					size = 4
				}
				if mode == "change" && read {
					change++
				}
			}
			fields := map[uint32]encoder{1: replacementTestU32(typ), 3: replacementTestU64(change), 4: replacementTestU64(size)}
			return replacementTestReply(bits, fields), 0, nil
		case 19:
			if d.boolean() || current != "file" {
				return nil, 0, errors.New("OPENATTR attempted creation or wrong base")
			}
			if mode == "absent" {
				return nil, 2, nil
			}
			if mode == "unsupported" {
				return nil, 10004, nil
			}
			current = "dir"
		case 10:
			e.opaque([]byte(current))
		case 15:
			if current != "dir" || d.str() != "binary" {
				return nil, 0, errors.New("invalid named lookup")
			}
			lookups++
			current = "attr"
			if mode == "rebind" && lookups > 1 {
				current = "other"
			}
		case 26:
			d.u64()
			d.take(8)
			d.u32()
			d.u32()
			readBitmap4(d)
			e = append(e, []byte("verifier")...)
			count := 1
			if mode == "many" {
				count = 65
			}
			for i := 0; i < count; i++ {
				e.u32(1)
				e.u64(uint64(i + 1))
				name := "binary"
				if count > 1 {
					name = fmt.Sprintf("name%d", i)
				}
				if mode == "bad-name" {
					name = ".."
				}
				e.str(name)
				var a encoder
				a.u32(9)
				a.opaque([]byte("attr"))
				bitmap4(&e, 1, 19)
				e.opaque(a)
			}
			e.u32(0)
			e.u32(1)
		case 18:
			d.u32()
			if d.u32() != 1 || d.u32() != 0 {
				return nil, 0, errors.New("attribute OPEN is not read-only")
			}
			d.u64()
			d.opaque(1024)
			create, claim, name := d.u32(), d.u32(), d.str()
			if create != 0 || claim != 0 || name != "binary" || current != "dir" {
				return nil, 0, errors.New("attribute OPEN creates or changes object")
			}
			current = "attr"
			e = append(e, bytes.Repeat([]byte{7}, 16)...)
			e.u32(1)
			e.u64(1)
			e.u64(1)
			e.u32(0)
			e.u32(0)
			e.u32(0)
		case 25:
			d.take(16)
			offset, count := d.u64(), d.u32()
			if current != "attr" {
				return nil, 0, errors.New("READ wrong object")
			}
			n := min(uint64(count), uint64(len(value))-offset)
			if offset+n == uint64(len(value)) {
				e.u32(1)
			} else {
				e.u32(0)
			}
			e.opaque(value[offset : offset+n])
			read = true
		case 4:
			d.u32()
			e = append(e, d.take(16)...)
		default:
			return nil, 0, fmt.Errorf("unexpected named inspection op %d", code)
		}
		return e, 0, nil
	}, func(fh []byte) error { current = string(fh); return nil })
	if minor > 0 {
		v.session = bytes.Repeat([]byte{1}, 16)
	}
	return v.c, &value
}

func TestNamedAttributesReadOnly(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			c, value := namedInspectionPeer(t, minor, "normal")
			attrs, err := c.ListNamedAttributes(context.Background(), []byte("file"))
			if err != nil || len(attrs) != 1 || attrs[0].Name != "binary" || attrs[0].Size != 4 {
				t.Fatalf("list: %+v %v", attrs, err)
			}
			got, err := c.GetNamedAttribute(context.Background(), []byte("file"), "binary")
			if err != nil || !bytes.Equal(got, *value) {
				t.Fatalf("value: %x %v", got, err)
			}
		})
	}
}

func TestNamedAttributesInspectionFailures(t *testing.T) {
	for _, mode := range []string{"empty", "maximum"} {
		t.Run(mode, func(t *testing.T) {
			c, expected := namedInspectionPeer(t, 0, mode)
			value, err := c.GetNamedAttribute(context.Background(), []byte("file"), "binary")
			if err != nil || !bytes.Equal(value, *expected) {
				t.Fatalf("value boundary %s: %d %v", mode, len(value), err)
			}
		})
	}
	for _, mode := range []string{"large", "growth", "symlink", "change", "rebind", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := namedInspectionPeer(t, 0, mode)
			if value, err := c.GetNamedAttribute(context.Background(), []byte("file"), "binary"); err == nil || value != nil {
				t.Fatalf("accepted %s: %d %v", mode, len(value), err)
			}
		})
	}
	for _, mode := range []string{"many", "bad-name", "unsupported"} {
		t.Run("list/"+mode, func(t *testing.T) {
			c, _ := namedInspectionPeer(t, 0, mode)
			if attrs, err := c.ListNamedAttributes(context.Background(), []byte("file")); err == nil || attrs != nil {
				t.Fatalf("accepted %s: %v", mode, err)
			}
		})
	}
	c, _ := namedInspectionPeer(t, 0, "absent")
	if attrs, err := c.ListNamedAttributes(context.Background(), []byte("file")); err != nil || attrs == nil || len(attrs) != 0 {
		t.Fatalf("absent: %+v %v", attrs, err)
	}
	for _, name := range []string{"", ".", "..", "a/b", "a\x00b", string([]byte{255})} {
		if err := ValidateNamedAttributeName(name); err == nil {
			t.Fatalf("accepted invalid name %q", name)
		}
	}
}
