package nfs

import (
	"errors"
	"math"
)

// A single LAYOUTGET grants one stateid for its ordered, contiguous segments.
// Bound the entire reply as well as individual bodies before allocating them.
func decodeFileLayouts(d *decoder, size uint64) ([]byte, []*fileLayout) {
	return decodeFileLayoutRange(d, 0, size)
}

func decodeFileLayoutRange(d *decoder, requested, minimum uint64) ([]byte, []*fileLayout) {
	return decodeLayoutRange(d, requested, minimum, 1)
}

func decodeLayoutRange(d *decoder, requested, minimum uint64, expectedKind uint32) ([]byte, []*fileLayout) {
	if len(d.b) > 32768 {
		d.err = errors.New("pNFS layout response exceeds 32 KiB")
		return nil, nil
	}
	d.boolean()
	state := append([]byte(nil), d.take(16)...)
	n := d.u32()
	if n < 1 || n > 64 {
		d.err = errors.New("pNFS requires 1..64 layout segments")
		return nil, nil
	}
	var layouts []*fileLayout
	defer func() {
		if d.err != nil {
			closeObjectLayouts(layouts)
		}
	}()
	var end uint64
	var iomode uint32
	for i := uint32(0); i < n; i++ {
		offset, length, mode, kind := d.u64(), d.u64(), d.u32(), d.u32()
		body := d.opaque(32768)
		if d.err != nil {
			return nil, nil
		}
		if i == 0 && offset > requested || i > 0 && offset != end || length == 0 || (mode != 1 && mode != 2) || kind != expectedKind || i > 0 && mode != iomode || length == math.MaxUint64 && i+1 != n || length != math.MaxUint64 && length > math.MaxUint64-offset {
			d.err = errors.New("invalid pNFS segment range, order, mode or type")
			return nil, nil
		}
		iomode = mode
		end = math.MaxUint64
		if length != math.MaxUint64 {
			end = offset + length
		}
		sub := &decoder{b: body}
		var l *fileLayout
		if kind == 2 {
			if mode == 2 && length == math.MaxUint64 {
				d.err = errors.New("object writes require finite layout segments")
				return nil, nil
			}
			l = &fileLayout{object: decodeObjectLayout(sub)}
		} else if kind == 3 {
			if length == math.MaxUint64 {
				d.err = errors.New("block I/O requires a finite layout")
				return nil, nil
			}
			if mode == 1 {
				l = &fileLayout{block: decodeBlockExtents(sub, offset, length)}
			} else {
				l = &fileLayout{block: decodeWritableBlockExtents(sub, offset, length)}
			}
		} else if kind == 4 {
			l = &fileLayout{flex: decodeFlexLayout(sub)}
		} else if kind == 1 {
			l = decodeFileLayout(sub)
		} else {
			d.err = errors.New("unsupported pNFS layout type")
			return nil, nil
		}
		layouts = append(layouts, l)
		if sub.err != nil {
			d.err = sub.err
			return nil, nil
		}
		if l.pattern > offset {
			d.err = errors.New("pNFS pattern starts after segment offset")
			return nil, nil
		}
		l.state, l.offset, l.length, l.iomode = state, offset, length, mode
	}
	if minimum > math.MaxUint64-requested || end < requested+minimum || len(d.b) != 0 {
		d.err = errors.New("incomplete pNFS coverage or trailing layout data")
		return nil, nil
	}
	return state, layouts
}

func fileLayoutAt(layouts []*fileLayout, offset uint64) (*fileLayout, error) {
	for _, l := range layouts {
		if offset >= l.offset && offset-l.offset < l.length {
			return l, nil
		}
	}
	return nil, errors.New("pNFS I/O falls outside granted segments")
}
