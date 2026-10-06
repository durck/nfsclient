package nfs

import (
	"context"
	"errors"
	"net"
)

// Only errors marked at the stream I/O boundary authorize read failover.
// A truncated authenticated XDR body or a GSS renewal error is not transport loss.
type rpcTransportFailure struct{ error }

func (e *rpcTransportFailure) Unwrap() error { return e.error }

func markRPCTransportFailure(err error) error {
	var network *net.OpError
	if errors.As(err, &network) && (network.Op == "read" || network.Op == "write") {
		return &rpcTransportFailure{err}
	}
	return err
}

func retryablePNFSRead(err error) bool {
	var transport *rpcTransportFailure
	return errors.As(err, &transport)
}

type pnfsRead struct {
	ds         *Client
	handle     []byte
	offset     uint64
	limit      uint32
	data       []byte
	paths      []string
	endpoint   string
	err        error
	flex       *flexDS
	flexLayout *flexLayout
	ioErr      error // DS failure, excluding local cancellation or layout loss.
}

// readPNFSBatch owns all workers until they exit, including on errors. Each
// entry has a distinct endpoint/session. No foreground API or progress callback
// runs concurrently with these workers; the MDS lease/backchannel stay active.
func readPNFSBatch(ctx context.Context, batch []*pnfsRead, sid []byte, usable func() error) error {
	return readPNFSBatchRecover(ctx, batch, sid, usable, nil)
}

func readPNFSBatchRecover(ctx context.Context, batch []*pnfsRead, sid []byte, usable func() error, recoverRead func(*pnfsRead) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	read := func(r *pnfsRead) error {
		r.data = nil
		r.ioErr = nil
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := usable(); err != nil {
			return err
		}
		if r.flex != nil {
			return readFlexComponent(ctx, r, usable)
		}
		args := append(encoder(nil), sid...)
		// RFC 8881 13.9.1: use OPEN/LOCK other with DS seqid zero.
		clear(args[:4])
		args.u64(r.offset)
		args.u32(r.limit)
		if err := r.ds.v4.compound(ctx, fh4(r.handle), op4(25, args, func(d *decoder) {
			d.boolean()
			r.data = append([]byte(nil), d.opaque(r.limit)...)
		})); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := usable(); err != nil {
			return err
		}
		// RFC 8881 13.10: only a successful short component READ denotes
		// a hole below the MDS size, bounded here by this stripe/request.
		if uint32(len(r.data)) < r.limit {
			r.data = append(r.data, make([]byte, int(r.limit)-len(r.data))...)
		}
		return nil
	}
	done := make(chan error, len(batch))
	for _, r := range batch {
		go func() { r.err = read(r); done <- r.err }()
	}
	var result error
	for range batch {
		if err := <-done; err != nil {
			if !deviceRecoveryBarrier(err) && (recoverRead == nil || !retryablePNFSRead(err)) {
				cancel() // Fatal failures interrupt and join all outstanding RPCs.
			}
			result = errors.Join(result, err)
		}
	}
	if result != nil && recoverRead != nil && ctx.Err() == nil && usable() == nil {
		// All original workers have exited. Recovery and fresh READs are serial,
		// even if alternate paths converge on one cached session. Nothing from
		// this batch is published until every read has succeeded.
		for _, r := range batch {
			if r.err == nil {
				continue
			}
			if !retryablePNFSRead(r.err) {
				return result
			}
			if err := recoverRead(r); err != nil {
				return errors.Join(result, err)
			}
			if err := read(r); err != nil {
				return errors.Join(result, err)
			}
		}
		return nil
	}
	return result
}
