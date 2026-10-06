package nfs

import (
	"bytes"
	"context"
	"errors"
	"io"
)

type pnfsCommit struct {
	offset uint64
	length uint32
}
type pnfsWrite struct {
	ds                *Client
	handle            []byte
	physical, logical uint64
	data              []byte
	endpoint          string
	mdsCommit         bool
	verifier          []byte
	commits           []pnfsCommit
	issued            bool
}

// Each worker owns one distinct DS session. All workers exit before the caller
// accesses their results or performs MDS operations/progress callbacks.
func writePNFSBatch(ctx context.Context, batch []*pnfsWrite, sid []byte, guard func(bool) error) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	write := func(w *pnfsWrite) error {
		for done := 0; done < len(w.data); {
			if err := errors.Join(ctx.Err(), guard(false)); err != nil {
				return err
			}
			args := append(encoder(nil), sid...)
			args.u64(w.physical + uint64(done))
			args.u32(0)
			args.opaque(w.data[done:])
			var accepted, stable uint32
			var verifier []byte
			w.issued = true
			if err := w.ds.v4.compound(ctx, fh4(w.handle), op4(38, args, func(d *decoder) {
				accepted, stable = d.u32(), d.u32()
				verifier = append([]byte(nil), d.take(8)...)
				if accepted == 0 || accepted > uint32(len(w.data)-done) || stable > 2 {
					d.err = errors.New("invalid pNFS WRITE acknowledgement")
				}
			})); err != nil {
				return err
			}
			if err := guard(true); err != nil {
				return err
			}
			if w.verifier != nil && !bytes.Equal(w.verifier, verifier) {
				return errors.New("pNFS data-server incarnation changed during batch")
			}
			w.verifier = verifier
			if stable < 2 {
				if w.mdsCommit {
					// One COMMIT covers the complete fragment after all short
					// acknowledgements. Bound bookkeeping independently of ack size.
					if len(w.commits) == 0 {
						w.commits = []pnfsCommit{{w.logical, uint32(len(w.data))}}
					}
				} else if stable == 0 {
					var args encoder
					args.u64(w.physical + uint64(done))
					args.u32(accepted)
					if err := w.ds.v4.compound(ctx, fh4(w.handle), op4(5, args, func(d *decoder) {
						if !bytes.Equal(d.take(8), verifier) {
							d.err = errors.New("pNFS write verifier changed; batch durability is uncertain")
						}
					})); err != nil {
						return err
					}
				}
			}
			done += int(accepted)
		}
		return guard(true)
	}
	done := make(chan error, len(batch))
	for _, w := range batch {
		go func() { done <- write(w) }()
	}
	var result error
	for range batch {
		if err := <-done; err != nil {
			cancel()
			result = errors.Join(result, err)
		}
	}
	issued := false
	for _, w := range batch {
		issued = issued || w.issued
	}
	return issued, result
}

// A batch is a contiguous bounded window with one stripe fragment per endpoint.
// Nothing in the batch is counted until all data and MDS metadata are durable.
// A failed issued batch is quarantined; later acknowledged stripes are never
// mistaken for a contiguous committed prefix or replayed on another path.
func (c *Client) writePNFSParallel(ctx context.Context, fh, sid []byte, offset, length, size uint64, input io.Reader, layouts []*fileLayout, parallel int, dataServer func([]string) (*Client, string, error), guard func(bool) error, progress func(uint64), boundary ...func() ([]*fileLayout, error)) (count int64, pending bool, resultErr error) {
	verifiers := map[string][]byte{}
	for uint64(count) < length {
		if len(boundary) > 0 {
			var err error
			layouts, err = boundary[0]()
			if err != nil {
				return count, false, err
			}
		}
		var batch []*pnfsWrite
		used := map[string]bool{}
		start := offset + uint64(count)
		next := start
		for next < offset+length && len(batch) < parallel {
			if err := errors.Join(ctx.Err(), guard(false)); err != nil {
				return count, false, err
			}
			layout, err := fileLayoutAt(layouts, next)
			if err != nil {
				return count, false, err
			}
			server, handle, physical, left, err := layout.position(next, fh)
			if err != nil {
				return count, false, err
			}
			ds, endpoint, err := dataServer(layout.endpoints[server])
			if err != nil {
				return count, false, err
			}
			if used[endpoint] {
				break
			}
			limit := min(left, layout.length-(next-layout.offset), offset+length-next, uint64(c.WriteSize), uint64(ds.WriteSize), uint64(1<<20))
			if limit == 0 {
				return count, false, errors.New("invalid pNFS data-server write size")
			}
			data := make([]byte, int(limit))
			if _, err := io.ReadFull(input, data); err != nil {
				return count, false, err
			}
			batch = append(batch, &pnfsWrite{ds: ds, handle: handle, physical: physical, logical: next, data: data, endpoint: endpoint, mdsCommit: layout.util&2 != 0})
			used[endpoint] = true
			next += limit
		}
		issued, err := writePNFSBatch(ctx, batch, sid, guard)
		if err != nil {
			return count, issued, err
		}
		if err := guard(true); err != nil {
			return count, true, err
		}
		for _, w := range batch {
			key := w.endpoint
			if w.mdsCommit {
				key = "metadata"
			}
			if previous := verifiers[key]; previous != nil && !bytes.Equal(previous, w.verifier) {
				return count, true, errors.New("pNFS data-server incarnation changed between batches")
			}
			verifiers[key] = w.verifier
			for _, commit := range w.commits {
				if err := guard(true); err != nil {
					return count, true, err
				}
				var args encoder
				args.u64(commit.offset)
				args.u32(commit.length)
				if err := c.v4.compound(ctx, fh4(fh), op4(5, args, func(d *decoder) {
					if !bytes.Equal(d.take(8), w.verifier) {
						d.err = errors.New("pNFS MDS verifier changed; batch durability is uncertain")
					}
				})); err != nil {
					return count, true, err
				}
			}
		}
		if err := guard(true); err != nil {
			return count, true, err
		}
		if err := c.v4.commitLayoutWrite(ctx, fh, start, next-start, max(size, next)); err != nil {
			return count, true, err
		}
		count += int64(next - start)
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
