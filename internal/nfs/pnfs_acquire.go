package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// Acquire complete coverage before any data-server connection. Each response
// must extend coverage; bound total granted segments, including superseded ones.
func (v *v4Client) getLayout(ctx context.Context, fh, sid []byte, size uint64) ([]*fileLayout, error) {
	return v.getLayoutMode(ctx, fh, sid, size, 1)
}

func (v *v4Client) getLayoutMode(ctx context.Context, fh, sid []byte, size uint64, mode uint32) (layouts []*fileLayout, err error) {
	return v.getLayoutType(ctx, fh, sid, size, mode, 1)
}

func (v *v4Client) getLayoutType(ctx context.Context, fh, sid []byte, size uint64, mode, kind uint32) (layouts []*fileLayout, err error) {
	var acquired []*fileLayout
	defer func() {
		retained := map[*objectLayout]bool{}
		if err == nil {
			for _, l := range layouts {
				retained[l.object] = true
			}
		}
		for _, l := range acquired {
			if l.object != nil && !retained[l.object] {
				closeObjectLayouts([]*fileLayout{l})
			}
		}
	}()
	defer func() {
		v.recall.mu.Lock()
		active := v.recall.active
		v.recall.mu.Unlock()
		if err != nil && active {
			err = errors.Join(err, v.returnLayout(fh))
		}
	}()
	var offset uint64
	for granted := 0; granted < 64; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if offset != 0 {
			if err := v.layoutUsable(fh); err != nil {
				return nil, err
			}
			v.recall.mu.Lock()
			sid = append([]byte(nil), v.recall.state...)
			v.recall.mu.Unlock()
		}
		next, err := v.getLayoutRangeType(ctx, fh, sid, offset, min(uint64(1), size-offset), mode, kind)
		if err != nil {
			return nil, err
		}
		acquired = append(acquired, next...)
		granted += len(next)
		if granted > 64 {
			return nil, errors.New("pNFS acquisition exceeds 64 total granted segments")
		}
		// The server can expand a requested range backwards. Its newer grant
		// supersedes that portion of the old coverage; retain only the prefix.
		start := next[0].offset
		var prefix []*fileLayout
		for _, old := range layouts {
			if old.offset >= start {
				break
			}
			copy := *old
			copy.length = min(copy.length, start-copy.offset)
			prefix = append(prefix, &copy)
		}
		layouts = append(prefix, next...)
		last := next[len(next)-1]
		offset = math.MaxUint64
		if last.length != math.MaxUint64 {
			offset = last.offset + last.length
		}
		if err := v.layoutUsable(fh); err != nil {
			return nil, err
		}
		if offset >= size {
			return layouts, nil
		}
	}
	return nil, errors.New("pNFS acquisition exceeds 64 total granted segments")
}

func nextLayoutSequence(seq uint32) uint32 {
	seq++
	if seq == 0 {
		seq = 1
	}
	return seq
}

func (v *v4Client) getLayoutRangeType(ctx context.Context, fh, sid []byte, offset, minimum uint64, mode, kind uint32) ([]*fileLayout, error) {
	started := time.Now()
	var e encoder
	e.u32(0)
	e.u32(kind)
	e.u32(mode)
	e.u64(offset)
	e.u64(math.MaxUint64)
	e.u64(minimum)
	e = append(e, sid...)
	e.u32(32768)
	var layouts []*fileLayout
	accepted := false
	defer func() {
		if !accepted {
			closeObjectLayouts(layouts)
		}
	}()
	op := op4(50, e, func(d *decoder) {
		var state []byte
		state, layouts = decodeLayoutRange(d, offset, minimum, kind)
		if d.err != nil {
			return
		}
		r := v.recall
		r.mu.Lock()
		defer r.mu.Unlock()
		seq := binary.BigEndian.Uint32(state)
		if seq == 0 || offset != 0 && (!bytes.Equal(state[4:], sid[4:]) || seq != nextLayoutSequence(binary.BigEndian.Uint32(sid)) && !(r.recalled && seq == nextLayoutSequence(binary.BigEndian.Uint32(r.state)))) {
			d.err = errors.New("invalid incremental pNFS layout stateid")
			return
		}
		if offset == 0 {
			r.layoutType, r.flexErrors = kind, nil
			r.objectError = nil
			r.active = true
			r.recalled = false
			r.fh = append([]byte(nil), fh...)
		}
		if !r.recalled || int32(seq-binary.BigEndian.Uint32(r.state)) > 0 {
			r.state = append([]byte(nil), state...)
		}
	})
	var result Status
	op.result = func(s Status) { result = s }
	op.failure = func(d *decoder) {
		if result == 10058 {
			d.boolean()
		}
	}
	if err := v.compound(ctx, fh4(fh), op); err != nil {
		return nil, err
	}
	v.lastLease.Store(&started)
	if mode == 2 {
		for _, l := range layouts {
			if l.iomode != 2 {
				return nil, errors.New("pNFS server did not grant a writable layout")
			}
		}
	}
	accepted = true
	return layouts, nil
}
