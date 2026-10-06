package nfs

import "errors"

// The fresh READ stream is consumed with one block of memory. Confirmed blocks
// are checked as an ordered hash chain; only the unresolved block is retained.
type blockRecoveryVerifier struct {
	state                       blockJournalState
	position, blockOffset, stop uint64
	block                       []byte
	digest                      string
	confirmed                   uint64
	pending                     []byte
}

func newBlockRecoveryVerifier(s blockJournalState) *blockRecoveryVerifier {
	start := min(s.Intent.Offset, s.Intent.OriginalSize) / s.Intent.BlockSize * s.Intent.BlockSize
	stop := s.NextBlock
	if s.Prepared != nil {
		stop += s.Intent.BlockSize
	}
	return &blockRecoveryVerifier{state: s, blockOffset: start, stop: stop, block: make([]byte, s.Intent.BlockSize)}
}

func (w *blockRecoveryVerifier) consumeBlock() {
	if w.blockOffset < w.state.NextBlock {
		w.digest = chainBlockHash(w.digest, w.blockOffset, w.block)
		w.confirmed++
	} else if w.state.Prepared != nil {
		w.pending = append([]byte(nil), w.block...)
	}
	w.blockOffset += uint64(len(w.block))
	clear(w.block)
}

func (w *blockRecoveryVerifier) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if w.position < w.blockOffset {
			skip := min(uint64(len(p)), w.blockOffset-w.position)
			p = p[skip:]
			w.position += skip
			continue
		}
		if w.blockOffset >= w.stop {
			w.position += uint64(len(p))
			break
		}
		relative := w.position - w.blockOffset
		size := min(uint64(len(p)), uint64(len(w.block))-relative)
		copy(w.block[relative:], p[:size])
		p = p[size:]
		w.position += size
		if w.position == w.blockOffset+uint64(len(w.block)) {
			w.consumeBlock()
		}
	}
	return n, nil
}

func (w *blockRecoveryVerifier) finish(size uint64) error {
	if w.position != size {
		return errors.New("block recovery READ length changed")
	}
	// A partial final block and an as-yet-unpublished growth block read as zero
	// beyond the checked EOF, matching the original pre/postimage convention.
	for w.blockOffset < w.stop {
		w.consumeBlock()
	}
	if w.confirmed != w.state.ConfirmedCount || w.digest != w.state.ConfirmedDigest {
		return errors.New("confirmed block bytes changed; recovery refused")
	}
	return nil
}
