package nfs

import (
	"context"
	"errors"
	"time"
)

// ApplicationDataBlock describes one repeated server-side block. A nil
// FirstNumber omits numbering; an empty Pattern omits the pattern. Unused
// offsets must be zero. The bounded profile reserves eight bytes for a number
// (RFC 7862 section 8.2), with a count4 initial value and no numeric wraparound.
type ApplicationDataBlock struct {
	Offset, BlockSize, BlockCount uint64
	NumberOffset                  uint64
	FirstNumber                   *uint32
	PatternOffset                 uint64
	Pattern                       []byte
}

func ValidateApplicationDataBlock(b ApplicationDataBlock) (uint64, error) {
	if b.BlockSize == 0 || b.BlockSize > 1<<20 || b.BlockCount == 0 || b.BlockCount > ^uint64(0)/b.BlockSize {
		return 0, errors.New("ADB needs a 1..1048576-byte block and a positive nonoverflowing count")
	}
	length := b.BlockSize * b.BlockCount
	if err := ValidateSpaceRange(b.Offset, length); err != nil {
		return 0, err
	}
	if b.FirstNumber == nil {
		if b.NumberOffset != 0 {
			return 0, errors.New("ADB number offset requires an initial number")
		}
	} else if b.BlockSize < 8 || b.NumberOffset > b.BlockSize-8 || b.BlockCount-1 > uint64(^uint32(0)-*b.FirstNumber) {
		return 0, errors.New("ADB number needs eight in-block bytes and must not wrap uint32")
	}
	if len(b.Pattern) == 0 {
		if b.PatternOffset != 0 {
			return 0, errors.New("ADB pattern offset requires a pattern")
		}
	} else {
		if len(b.Pattern) > 4096 || uint64(len(b.Pattern)) > b.BlockSize || b.PatternOffset > b.BlockSize-uint64(len(b.Pattern)) {
			return 0, errors.New("ADB pattern must fit inside the block and contain at most 4096 bytes")
		}
		if b.FirstNumber != nil && b.NumberOffset < b.PatternOffset+uint64(len(b.Pattern)) && b.PatternOffset < b.NumberOffset+8 {
			return 0, errors.New("ADB pattern overlaps the reserved number field")
		}
	}
	return length, nil
}

// WriteSame retains the full-block repeating-pattern API. General ADBs share
// its existing asynchronous completion, cancellation and durability lifecycle.
func (c *Client) WriteSame(ctx context.Context, fh []byte, offset, count uint64, pattern []byte, wait time.Duration) (uint64, error) {
	if c.v4 == nil || c.v4.minor != 2 {
		return 0, ErrRequiresV42
	}
	if _, err := ValidateWriteSame(offset, count, pattern); err != nil {
		return 0, err
	}
	return c.WriteApplicationDataBlocks(ctx, fh, ApplicationDataBlock{Offset: offset, BlockSize: uint64(len(pattern)), BlockCount: count, Pattern: pattern}, wait)
}
