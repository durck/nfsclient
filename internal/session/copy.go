package session

import (
	"context"
	"errors"
	"fmt"
	"nfsclient/internal/nfs"
	"time"
)

// CopyRange writes an existing destination. It does not publish a new filename,
// replace file metadata, emulate unsupported operations or promise rollback.
func (s *Session) CopyRange(ctx context.Context, source, destination string, sourceOffset, destinationOffset, length uint64, clone bool) (uint64, error) {
	return s.copyRange(ctx, source, destination, sourceOffset, destinationOffset, length, clone, 0)
}

func (s *Session) CopyRangeAsync(ctx context.Context, source, destination string, sourceOffset, destinationOffset, length uint64, wait time.Duration) (uint64, error) {
	if err := nfs.ValidateOffloadWait(wait); err != nil {
		return 0, err
	}
	return s.copyRange(ctx, source, destination, sourceOffset, destinationOffset, length, false, wait)
}

// CopyFrom uses a separately selected source export with the destination's
// explicit identity and security policy. It verifies observed source stability,
// not a snapshot. Protected sources require explicit privilege options.
func (s *Session) CopyFrom(ctx context.Context, endpoint, export, source, destination string, sourceOffset, destinationOffset, length uint64, wait time.Duration, options nfs.CopyFromOptions) (uint64, error) {
	if err := nfs.ValidateCopyRange(sourceOffset, destinationOffset, length); err != nil {
		return 0, err
	}
	if err := nfs.ValidateOffloadWait(wait); err != nil {
		return 0, err
	}
	if err := nfs.ValidateCopyFromOptions(options); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	client, err := s.Client.ConnectCopySourceOptions(ctx, endpoint, options)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	remote := New(client, endpoint, false, false, s.Notice)
	if err := remote.Use(ctx, export); err != nil {
		return 0, err
	}
	src, err := remote.spaceFile(ctx, source)
	if err != nil {
		return 0, err
	}
	dst, err := s.spaceFile(ctx, destination)
	if err != nil {
		return 0, err
	}
	if sourceOffset+length > src.Attr.Size {
		return 0, errors.New("copy source range extends beyond observed EOF")
	}
	if err := downloadSourceReady(src.Attr, client.Version()); err != nil {
		return 0, err
	}
	n, err := s.Client.CopyRangeFrom(ctx, client, src.Handle, dst.Handle, sourceOffset, destinationOffset, length, wait, options)
	if err != nil {
		return n, err
	}
	after, err := client.GetAttr(ctx, src.Handle)
	if err != nil {
		return n, fmt.Errorf("destination changed, but source stability could not be verified: %w", err)
	}
	if err := verifyDownloadSource(src.Attr, after); err != nil {
		return n, errors.New("source changed during inter-server copy; destination may contain mixed source data")
	}
	return n, nil
}

func (s *Session) copyRange(ctx context.Context, source, destination string, sourceOffset, destinationOffset, length uint64, clone bool, wait time.Duration) (uint64, error) {
	if err := nfs.ValidateCopyRange(sourceOffset, destinationOffset, length); err != nil {
		return 0, err
	}
	src, err := s.spaceFile(ctx, source)
	if err != nil {
		return 0, err
	}
	dst, err := s.spaceFile(ctx, destination)
	if err != nil {
		return 0, err
	}
	if src.Attr.FSID == dst.Attr.FSID && src.Attr.FileID == dst.Attr.FileID {
		return 0, errors.New("copy requires distinct source and destination files")
	}
	if sourceOffset+length > src.Attr.Size {
		return 0, errors.New("copy source range extends beyond observed EOF")
	}
	if err := downloadSourceReady(src.Attr, s.Client.Version()); err != nil {
		return 0, err
	}
	copy := s.Client.CopyRange
	if clone {
		copy = s.Client.CloneRange
	}
	if wait > 0 {
		copy = func(ctx context.Context, source, destination []byte, sourceOffset, destinationOffset, length uint64) (uint64, error) {
			return s.Client.CopyRangeAsync(ctx, source, destination, sourceOffset, destinationOffset, length, wait)
		}
	}
	n, err := copy(ctx, src.Handle, dst.Handle, sourceOffset, destinationOffset, length)
	if err != nil {
		return n, err
	}
	if clone {
		// CLONE atomically snapshots the range at the server. XFS updates the
		// source change/ctime when its blocks become shared, so the COPY
		// stability guard would falsely reject a successful atomic clone.
		return n, nil
	}
	after, err := s.Client.GetAttr(ctx, src.Handle)
	if err != nil {
		return n, fmt.Errorf("destination changed, but source stability could not be verified: %w", err)
	}
	if err := verifyDownloadSource(src.Attr, after); err != nil {
		return n, errors.New("source changed during server copy; destination may contain mixed source data")
	}
	return n, nil
}

func (s *Session) WriteSame(ctx context.Context, remote string, offset, count uint64, pattern []byte, wait time.Duration) (uint64, error) {
	if _, err := nfs.ValidateWriteSame(offset, count, pattern); err != nil {
		return 0, err
	}
	if err := nfs.ValidateOffloadWait(wait); err != nil {
		return 0, err
	}
	n, err := s.spaceFile(ctx, remote)
	if err != nil {
		return 0, err
	}
	return s.Client.WriteSame(ctx, n.Handle, offset, count, pattern, wait)
}

func (s *Session) WriteApplicationDataBlocks(ctx context.Context, remote string, block nfs.ApplicationDataBlock, wait time.Duration) (uint64, error) {
	if _, err := nfs.ValidateApplicationDataBlock(block); err != nil {
		return 0, err
	}
	if err := nfs.ValidateOffloadWait(wait); err != nil {
		return 0, err
	}
	n, err := s.spaceFile(ctx, remote)
	if err != nil {
		return 0, err
	}
	return s.Client.WriteApplicationDataBlocks(ctx, n.Handle, block, wait)
}
