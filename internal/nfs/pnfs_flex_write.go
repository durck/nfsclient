package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
)

func (l *flexLayout) writeMirrors() [][]*flexDS {
	if l.flags&8 != 0 {
		return [][]*flexDS{l.selected}
	}
	return l.mirrors
}

func (v *v4Client) prepareFlexWriteDevices(ctx context.Context, l *flexLayout, o PNFSOptions) error {
	for _, mirror := range l.writeMirrors() {
		copy := *l
		copy.selected = mirror
		if err := v.prepareFlexDevices(ctx, &copy, o); err != nil {
			return err
		}
		for _, ds := range mirror {
			if ds.wsize == 0 {
				return errors.New("flex Files device has no writable profile")
			}
		}
	}
	return nil
}

type flexWrite struct {
	ds        *Client
	component *flexDS
	endpoint  string
	verifier  []byte
	issued    bool
	op        uint32
	err       error
}

// All mirrors receive the same immutable stripe fragment. No logical byte is
// credited until every required mirror and the MDS metadata are durable.
func (c *Client) writeFlexRange(ctx context.Context, fh []byte, offset, length, size uint64, input io.Reader, layouts []*fileLayout, parallel int, get func(*flexDS) (*Client, string, error), guard func(bool) error, progress func(uint64), boundary ...func() ([]*fileLayout, error)) (count int64, pending bool, resultErr error) {
	verifiers := map[*Client][]byte{}
	for uint64(count) < length {
		if len(boundary) > 0 {
			var err error
			layouts, err = boundary[0]()
			if err != nil {
				return count, false, err
			}
		}
		if err := errors.Join(ctx.Err(), guard(false)); err != nil {
			return count, false, err
		}
		logical := offset + uint64(count)
		segment, err := fileLayoutAt(layouts, logical)
		if err != nil {
			return count, false, err
		}
		l := segment.flex
		_, left := l.position(logical)
		limit := min(left, segment.length-(logical-segment.offset), length-uint64(count), uint64(c.WriteSize), uint64(1<<20))
		var jobs []*flexWrite
		for _, mirror := range l.writeMirrors() {
			index := uint64(0)
			if len(mirror) > 1 {
				index = logical / l.stripe % uint64(len(mirror))
			}
			component := mirror[index]
			ds, endpoint, err := get(component)
			if err != nil {
				c.v4.recordFlexOpError(component, logical, limit, 38, err)
				return count, false, err
			}
			limit = min(limit, uint64(component.wsize), uint64(ds.WriteSize))
			jobs = append(jobs, &flexWrite{ds: ds, component: component, endpoint: endpoint, verifier: verifiers[ds], op: 38})
		}
		if limit == 0 {
			return count, false, errors.New("invalid Flex Files write size")
		}
		data := make([]byte, int(limit))
		if _, err := io.ReadFull(input, data); err != nil {
			return count, false, err
		}
		var failed error
		for start := 0; start < len(jobs); {
			end := start
			used := map[string]bool{}
			for end < len(jobs) && end-start < parallel && !used[jobs[end].endpoint] {
				used[jobs[end].endpoint] = true
				end++
			}
			done := make(chan error, end-start)
			for _, w := range jobs[start:end] {
				go func() { w.err = writeFlexPiece(ctx, w, logical, data, guard); done <- w.err }()
			}
			// Wait for all issued replicas, including after a peer error. The
			// caller's cancellation and each RPC deadline still bound the wait.
			for range jobs[start:end] {
				failed = errors.Join(failed, <-done)
			}
			if failed != nil {
				break
			}
			for _, w := range jobs[start:end] {
				verifiers[w.ds] = w.verifier
			}
			start = end
			// A repeated endpoint is serialized in the next wave. Its verifier
			// must reflect the just-completed wave, not the initial snapshot.
			for _, w := range jobs[start:] {
				w.verifier = verifiers[w.ds]
			}
		}
		issued := false
		for _, w := range jobs {
			issued = issued || w.issued
		}
		if failed == nil {
			failed = guard(true)
		}
		if failed == nil && l.flags&1 == 0 {
			failed = c.v4.commitLayoutWrite(ctx, fh, logical, limit, max(size, logical+limit))
		}
		if failed != nil {
			// Mark every potentially divergent replica. Successful updates on
			// other replicas do not make this logical fragment successful.
			for _, w := range jobs {
				err := w.err
				if err == nil {
					err = failed
				}
				c.v4.recordFlexOpError(w.component, logical, limit, w.op, err)
			}
			return count, issued, failed
		}
		count += int64(limit)
		if progress != nil {
			progress(uint64(count))
		}
		if err := errors.Join(ctx.Err(), guard(false)); err != nil {
			if len(boundary) == 0 || !deviceRecoveryBarrier(err) {
				return count, false, err
			}
		}
	}
	return count, false, nil
}

func writeFlexPiece(ctx context.Context, w *flexWrite, offset uint64, data []byte, guard func(bool) error) error {
	for done := 0; done < len(data); {
		if err := errors.Join(ctx.Err(), guard(false)); err != nil {
			return err
		}
		w.issued, w.op = true, 38
		accepted, stable, verifier, err := writeFlexRPC(ctx, w, offset+uint64(done), data[done:])
		if err != nil {
			return err
		}
		if accepted == 0 || accepted > uint32(len(data)-done) || stable > 2 {
			return errors.New("invalid Flex Files WRITE acknowledgement")
		}
		if err := guard(true); err != nil {
			return err
		}
		if w.verifier != nil && !bytes.Equal(w.verifier, verifier) {
			return errors.New("flex Files device incarnation changed during write")
		}
		w.verifier = verifier
		if stable < 2 {
			w.op = 5
			if err := commitFlexRPC(ctx, w, offset+uint64(done), accepted); err != nil {
				return err
			}
		}
		if err := guard(true); err != nil {
			return err
		}
		done += int(accepted)
	}
	return nil
}

func writeFlexRPC(ctx context.Context, w *flexWrite, offset uint64, data []byte) (accepted, stable uint32, verifier []byte, err error) {
	decode := func(d *decoder) { accepted, stable = d.u32(), d.u32(); verifier = append([]byte(nil), d.take(8)...) }
	var e encoder
	if w.component.major == 4 {
		e = append(e, w.component.state...)
		e.u64(offset)
		e.u32(2)
		e.opaque(data)
		err = w.ds.v4.compound(ctx, fh4(w.component.handle), op4(38, e, decode))
		return
	}
	e.opaque(w.component.handle)
	e.u64(offset)
	e.u32(uint32(len(data)))
	e.u32(2)
	e.opaque(data)
	d, err := w.ds.call(ctx, 7, e)
	if err != nil {
		return 0, 0, nil, err
	}
	wcc(d)
	decode(d)
	if d.err != nil {
		return 0, 0, nil, d.err
	}
	if len(d.b) != 0 {
		return 0, 0, nil, errors.New("trailing Flex Files WRITE reply")
	}
	return
}

func commitFlexRPC(ctx context.Context, w *flexWrite, offset uint64, count uint32) error {
	decode := func(d *decoder) {
		if !bytes.Equal(d.take(8), w.verifier) {
			d.err = errors.New("flex Files COMMIT verifier changed")
		}
	}
	var e encoder
	if w.component.major == 4 {
		e.u64(offset)
		e.u32(count)
		return w.ds.v4.compound(ctx, fh4(w.component.handle), op4(5, e, decode))
	}
	e.opaque(w.component.handle)
	e.u64(offset)
	e.u32(count)
	d, err := w.ds.call(ctx, 21, e)
	if err != nil {
		return err
	}
	wcc(d)
	decode(d)
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return errors.New("trailing Flex Files COMMIT reply")
	}
	return nil
}
