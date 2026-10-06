package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

func ValidateCopyRange(sourceOffset, destinationOffset, length uint64) error {
	if length == 0 || sourceOffset > ^uint64(0)-length || destinationOffset > ^uint64(0)-length {
		return errors.New("copy range needs a positive finite length without uint64 overflow")
	}
	return nil
}

// CopyRange requests a single synchronous, consecutive intra-server COPY.
// Short copies and uncertain outcomes are reported, never replayed. Destination
// bytes can already have changed when an error is returned.
func (c *Client) CopyRange(ctx context.Context, source, destination []byte, sourceOffset, destinationOffset, length uint64) (uint64, error) {
	return c.copyRange42(ctx, source, destination, sourceOffset, destinationOffset, length, false, 0)
}

// CopyRangeAsync permits asynchronous intra-server COPY and waits for its
// completion on the negotiated backchannel. It never retries the COPY.
func (c *Client) CopyRangeAsync(ctx context.Context, source, destination []byte, sourceOffset, destinationOffset, length uint64, wait time.Duration) (uint64, error) {
	if err := ValidateOffloadWait(wait); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return c.copyRange42(ctx, source, destination, sourceOffset, destinationOffset, length, false, wait)
}

// CloneRange requests one server CLONE. Same-file cloning and zero-length EOF
// sentinel requests are deliberately excluded from this bounded API.
func (c *Client) CloneRange(ctx context.Context, source, destination []byte, sourceOffset, destinationOffset, length uint64) (uint64, error) {
	return c.copyRange42(ctx, source, destination, sourceOffset, destinationOffset, length, true, 0)
}

func (c *Client) copyRange42(ctx context.Context, source, destination []byte, sourceOffset, destinationOffset, length uint64, clone bool, wait time.Duration) (copied uint64, resultErr error) {
	if c.v4 == nil || c.v4.minor != 2 {
		return 0, ErrRequiresV42
	}
	if err := ValidateCopyRange(sourceOffset, destinationOffset, length); err != nil {
		return 0, err
	}
	if len(source) == 0 || len(destination) == 0 || bytes.Equal(source, destination) {
		return 0, errors.New("copy requires two distinct nonempty file handles")
	}
	v := c.v4
	if c.config != nil && c.config.OffloadReconcile && (!clone && wait > 0 || sourceOffset != 0 || destinationOffset != 0 || length > maxReconcileBytes || len(c.Locks()) != 0) {
		return 0, errors.New("automatic reconciliation records require synchronous whole-file intra-server COPY/CLONE up to 16 MiB without retained locks")
	}
	if wait > 0 || c.config != nil && c.config.OffloadJournal != "" {
		operation := "copyrange"
		if clone {
			operation = "clonerange"
		} else if wait > 0 {
			operation = "copyasync"
		}
		end, err := v.beginOffload(offloadIntent{Operation: operation, Source: source, Destination: destination, SourceOffset: sourceOffset, Offset: destinationOffset, Length: length})
		if err != nil {
			return 0, err
		}
		defer end(&resultErr)
	}
	if c.config != nil && c.config.OffloadReconcile {
		if err := c.prepareOffloadReconcile(ctx, source, destination, length); err != nil {
			return 0, err
		}
	}
	if err := c.prepareOffloadExpectation(ctx, c, source, destination, sourceOffset, destinationOffset, length, nil); err != nil {
		return 0, err
	}
	if err := v.checkLockedIO(source, 1); err != nil {
		return 0, err
	}
	if err := v.checkLockedIO(destination, 2); err != nil {
		return 0, err
	}
	srcState, closeSource, err := v.offloadOpenIO(ctx, source, 1)
	if err != nil {
		return 0, err
	}
	acknowledged := false
	cleanup := func(closeIO func() error) {
		if err := closeIO(); err != nil {
			if acknowledged {
				err = fmt.Errorf("server copy acknowledged, but state cleanup failed: %w", err)
			}
			resultErr = errors.Join(resultErr, err)
		}
	}
	defer func() { cleanup(closeSource) }()
	dstState, closeDestination, err := v.offloadOpenIO(ctx, destination, 2)
	if err != nil {
		return 0, err
	}
	defer func() { cleanup(closeDestination) }()
	e := append(encoder(nil), srcState...)
	e = append(e, dstState...)
	e.u64(sourceOffset)
	e.u64(destinationOffset)
	e.u64(length)
	code, name := uint32(60), "COPY"
	var stable uint32
	var verifier []byte
	var offload offloadReply
	var decode func(*decoder)
	if clone {
		code, name = 71, "CLONE"
	} else {
		e.u32(1) // Require consecutive bytes.
		if wait == 0 {
			e.u32(1)
		} else {
			e.u32(0)
		}
		e.u32(0) // Empty source-server list: intra-server only.
		decode = func(d *decoder) {
			if wait > 0 {
				offload = decodeOffloadReply(d)
				consecutive, synchronous := d.boolean(), d.boolean()
				if !consecutive || synchronous != (len(offload.id) == 0) || offload.count > length {
					d.err = errors.New("invalid asynchronous COPY result")
				}
				return
			}
			if d.u32() != 0 {
				d.err = errors.New("COPY returned asynchronous state despite synchronous requirement")
				return
			}
			count := d.u64()
			stable = d.u32()
			verifier = append([]byte(nil), d.take(8)...)
			consecutive, synchronous := d.boolean(), d.boolean()
			if count > length || stable > 2 || !consecutive || !synchronous {
				d.err = errors.New("invalid synchronous COPY result")
			}
			if d.err == nil {
				copied = count
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := v.checkLockedIO(source, 1); err != nil {
		return 0, err
	}
	if err := v.checkLockedIO(destination, 2); err != nil {
		return 0, err
	}
	if err := v.issueOffload(); err != nil {
		return 0, err
	}
	if err := v.compound(ctx, fh4(source), op4(32, nil, nil), fh4(destination), op4(code, e, decode)); err != nil {
		var status Status
		if !errors.As(err, &status) {
			return 0, fmt.Errorf("%s outcome unverified; destination may have changed; request was not replayed: %w", name, err)
		}
		return 0, err
	}
	acknowledged = true
	if wait > 0 {
		offload, err = v.awaitOffload(ctx, destination, offload, length)
		if err != nil {
			return 0, err
		}
		if err := v.checkLockedIO(source, 1); err != nil {
			return offload.count, err
		}
		return v.finishOffload(ctx, destination, destinationOffset, length, offload)
	}
	if clone {
		copied = length
	}
	if err := v.checkLockedIO(source, 1); err != nil {
		return copied, err
	}
	if err := v.checkLockedIO(destination, 2); err != nil {
		return copied, err
	}
	if !clone && stable < 2 && copied > 0 {
		var commit encoder
		commit.u64(destinationOffset)
		commit.u32(0) // Commit through EOF; count4 cannot represent every copy range.
		var committed []byte
		if err := v.compound(ctx, fh4(destination), op4(5, commit, func(d *decoder) { committed = append([]byte(nil), d.take(8)...) })); err != nil {
			return copied, fmt.Errorf("COPY acknowledged but durability unverified: %w", err)
		}
		if !bytes.Equal(verifier, committed) {
			return copied, errors.New("COPY COMMIT verifier changed; durability unverified; copy was not replayed")
		}
	}
	if copied != length {
		return copied, fmt.Errorf("COPY changed %d of %d requested bytes; no continuation attempted: %w", copied, length, io.ErrShortWrite)
	}
	if c.config != nil && c.config.OffloadReconcile {
		if err := v.offloadReconcileReceipt(); err != nil {
			return copied, err
		}
	}
	return copied, nil
}
