package nfs

import (
	"context"
	"errors"
)

// Capability describes client code separately from evidence supplied by this
// object. Advertisement is not a successful operation or an authorization grant.
type Capability struct {
	Name             string `json:"name"`
	Implemented      bool   `json:"client_implemented"`
	ProtocolEligible bool   `json:"protocol_eligible"`
	Server           string `json:"server"`
	Evidence         string `json:"evidence"`
}

type Capabilities struct {
	Version             string       `json:"version"`
	SupportedAttrsKnown bool         `json:"supported_attrs_known"`
	SupportedAttrs      []uint32     `json:"supported_attrs,omitempty"`
	Features            []Capability `json:"features"`
	Offline             OfflineState `json:"offline"`
	LayoutTypes         []uint32     `json:"layout_types,omitempty"`
	FSLayoutTypes       []uint32     `json:"fs_layout_types,omitempty"`
}

type OfflineState string

const (
	OfflineUnknown OfflineState = "unknown"
	OfflineOnline  OfflineState = "online"
	OfflineOffline OfflineState = "offline"
)

// supportedAttributes reads only the mandatory discovery attribute. New
// attribute numbers in its value are harmless; they are not requested/decoded.
func (v *v4Client) supportedAttributes(ctx context.Context, fh []byte) ([]uint32, bool, error) {
	var bits []uint32
	known := false
	err := v.attrs(ctx, fh, []uint32{0}, func(_ uint32, d *decoder) {
		known = true
		n := d.u32()
		if n > 32 {
			d.err = errors.New("supported_attrs bitmap exceeds 1024 bits")
			return
		}
		for i := uint32(0); i < n && d.err == nil; i++ {
			word := d.u32()
			for b := uint32(0); b < 32; b++ {
				if word&(1<<b) != 0 {
					bits = append(bits, i*32+b)
				}
			}
		}
	})
	if unsupported(err) || errors.Is(err, Status(10032)) {
		return nil, false, nil
	}
	return bits, known && err == nil, err
}

func hasAttribute(bits []uint32, want uint32) bool {
	for _, bit := range bits {
		if bit == want {
			return true
		}
	}
	return false
}

// Capabilities makes metadata-only, per-object observations, with no persistent
// cache and no OPEN, READ, optional operation or mutation probes.
func (c *Client) Capabilities(ctx context.Context, fh []byte) (Capabilities, error) {
	r := Capabilities{Version: c.Version(), Offline: OfflineUnknown}
	v4 := c.v4 != nil
	v42 := v4 && c.v4.minor >= 2
	r.Features = []Capability{
		{"acl", true, true, "unknown", "no ACL operation probed"},
		{"xattrs", true, v42, "unknown", "no xattr operation probed"},
		{"named_attributes", true, v4, "unknown", "no OPENATTR probe; named_attr reports presence, not operation support"},
		{"copy", true, v42, "unknown", "optional COPY operation not probed"},
		{"clone", true, v42, "unknown", "optional CLONE operation not probed"},
		{"sparse", true, v42, "unknown", "SEEK/READ_PLUS/space operations not probed"},
		{"offline", true, v42, "unknown", "offline attribute not observed"},
		{"pnfs", true, v4 && c.v4.minor >= 1, "unknown", "layout support not observed"},
	}
	if !v4 {
		return r, nil
	}
	bits, known, err := c.v4.supportedAttributes(ctx, fh)
	if err != nil {
		return r, err
	}
	r.SupportedAttrs, r.SupportedAttrsKnown = bits, known
	if !known {
		return r, nil
	}
	for _, item := range []struct {
		index int
		bit   uint32
	}{{0, 12}, {1, 82}, {6, 83}, {7, 64}} {
		f := &r.Features[item.index]
		if hasAttribute(bits, item.bit) {
			f.Server, f.Evidence = "advertised", "attribute listed in this object's supported_attrs"
		} else {
			f.Server, f.Evidence = "unsupported", "required discovery attribute absent from this object's supported_attrs"
		}
	}
	if hasAttribute(bits, 58) || hasAttribute(bits, 59) {
		r.Features[0].Server, r.Features[0].Evidence = "advertised", "DACL/SACL attribute listed in this object's supported_attrs"
	}
	if !hasAttribute(bits, 64) {
		r.Features[7].Server, r.Features[7].Evidence = "unknown", "per-object layout_types not advertised"
		if hasAttribute(bits, 62) {
			r.Features[7].Server, r.Features[7].Evidence = "advertised", "filesystem layout types advertised; per-object layout eligibility unknown"
		}
	}
	// Read optional values independently so ATTRNOTSUPP on one cannot hide
	// other metadata. Never substitute a default false for a missing value.
	for _, bit := range []uint32{82, 83, 62, 64} {
		if !hasAttribute(bits, bit) {
			continue
		}
		seen := false
		err = c.v4.attrs(ctx, fh, []uint32{bit}, func(_ uint32, d *decoder) {
			seen = true
			switch bit {
			case 82:
				if !d.boolean() {
					r.Features[1].Server, r.Features[1].Evidence = "unsupported", "xattr_support is false"
				}
			case 83:
				r.Offline = OfflineOnline
				if d.boolean() {
					r.Offline = OfflineOffline
				}
			case 62, 64:
				n := d.u32()
				if n > 64 {
					d.err = errors.New("layout_types exceeds 64 entries")
					return
				}
				var layouts []uint32
				for i := uint32(0); i < n && d.err == nil; i++ {
					layouts = append(layouts, d.u32())
				}
				if bit == 64 {
					r.LayoutTypes = layouts
				} else {
					r.FSLayoutTypes = layouts
				}
				if n == 0 {
					r.Features[7].Server, r.Features[7].Evidence = "unsupported", "layout_types is empty for this object"
				} else if bit == 64 {
					r.Features[7].Server, r.Features[7].Evidence = "advertised", "nonempty per-object layout_types; LAYOUTGET not probed"
				} else if !hasAttribute(bits, 64) {
					r.Features[7].Server, r.Features[7].Evidence = "advertised", "nonempty filesystem layout types; per-object eligibility unknown"
				}
			}
		})
		index := map[uint32]int{82: 1, 83: 6, 62: 7, 64: 7}[bit]
		if unsupported(err) || errors.Is(err, Status(10032)) {
			r.Features[index].Server, r.Features[index].Evidence = "unsupported", "server rejected advertised attribute"
			continue
		}
		if err != nil {
			r.Offline = OfflineUnknown
			return r, err
		}
		if !seen {
			r.Features[index].Server, r.Features[index].Evidence = "unknown", "server omitted advertised attribute"
		}
	}
	return r, nil
}

// OfflineMetadata requests RFC 9754 offline only when this object advertises
// it. Absence, omission and unsupported replies remain unknown, never online.
func (c *Client) OfflineMetadata(ctx context.Context, fh []byte) (OfflineState, error) {
	if c.v4 == nil {
		return OfflineUnknown, nil
	}
	bits, known, err := c.v4.supportedAttributes(ctx, fh)
	if err != nil || !known || !hasAttribute(bits, 83) {
		return OfflineUnknown, err
	}
	state := OfflineUnknown
	err = c.v4.attrs(ctx, fh, []uint32{83}, func(_ uint32, d *decoder) {
		state = OfflineOnline
		if d.boolean() {
			state = OfflineOffline
		}
	})
	if unsupported(err) || errors.Is(err, Status(10032)) {
		return OfflineUnknown, nil
	}
	if err != nil {
		return OfflineUnknown, err
	}
	return state, nil
}
