package nfs

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

// FileLocations describes the server-relative filesystem root and its alternate
// namespace roots. Advertised server strings are data, never dial authority.
type FileLocations struct {
	Root      []string
	Locations []FileLocation
}
type FileLocation struct {
	Servers []string
	Root    []string
}

func readLocationPath(d *decoder) []string {
	n := d.u32()
	if n > 64 {
		d.err = errors.New("excessive referral path depth")
		return nil
	}
	p := make([]string, 0, n)
	for i := uint32(0); i < n && d.err == nil; i++ {
		s := string(d.opaque(255))
		if s == "" || s == "." || s == ".." || !utf8.ValidString(s) || strings.ContainsAny(s, "/\\\x00\r\n") {
			d.err = errors.New("invalid referral path component")
			return nil
		}
		p = append(p, s)
	}
	return p
}
func readFileLocations(d *decoder) FileLocations {
	out := FileLocations{Root: readLocationPath(d)}
	n := d.u32()
	if n > 8 {
		d.err = errors.New("excessive referral locations")
		return out
	}
	for i := uint32(0); i < n && d.err == nil; i++ {
		location := FileLocation{}
		count := d.u32()
		if count == 0 || count > 8 {
			d.err = errors.New("invalid referral server count")
			return out
		}
		for j := uint32(0); j < count && d.err == nil; j++ {
			s := string(d.opaque(1024))
			if s == "" || !utf8.ValidString(s) || strings.ContainsAny(s, " /\\\t\x00\r\n") {
				d.err = errors.New("invalid referral server selector")
				return out
			}
			location.Servers = append(location.Servers, s)
		}
		location.Root = readLocationPath(d)
		out.Locations = append(out.Locations, location)
	}
	return out
}

// Locations queries only fs_locations, which is available on an absent
// filesystem. A nonempty child performs LOOKUP before GETATTR, without GETFH.
// This also handles referral servers that refuse to export an absent handle.
func (c *Client) Locations(ctx context.Context, dir []byte, child string) (FileLocations, error) {
	var out FileLocations
	if c == nil || c.v4 == nil {
		return out, errors.New("fs_locations requires NFSv4")
	}
	if child != "" && (child == "." || child == ".." || len(child) > 255 || strings.ContainsAny(child, "/\\\x00\r\n")) {
		return out, errors.New("invalid referral lookup component")
	}
	ops := []v4Op{fh4(dir)}
	if child != "" {
		var e encoder
		e.str(child)
		ops = append(ops, op4(15, e, nil))
	}
	var e encoder
	bitmap4(&e, 24)
	ops = append(ops, op4(9, e, func(d *decoder) {
		bits := readBitmap4(d)
		if len(bits) != 1 || bits[0] != 24 {
			d.err = errors.New("missing or unsolicited fs_locations attribute")
			return
		}
		values := d.opaque(65536)
		a := &decoder{b: values}
		out = readFileLocations(a)
		if a.err != nil {
			d.err = a.err
		} else if len(a.b) != 0 {
			d.err = errors.New("trailing fs_locations data")
		}
	}))
	err := c.v4.compound(ctx, ops...)
	return out, err
}
