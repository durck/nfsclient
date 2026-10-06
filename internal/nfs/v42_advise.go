package nfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var adviseNames = [...]string{"normal", "sequential", "sequential-backwards", "random", "willneed", "willneed-opportunistic", "dontneed", "noreuse", "read", "write", "init-proximity"}

// ParseAdvice accepts RFC 7862 hint names, including contradictory hints: the
// server may select different advice and is never obliged to act on it.
func ParseAdvice(text string) (uint32, error) {
	var mask uint32
	for _, name := range strings.Split(text, ",") {
		found := false
		for bit, known := range adviseNames {
			if name == known {
				mask |= 1 << bit
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("unknown I/O advice %q", name)
		}
	}
	return mask, nil
}

type AdviceResult struct {
	Hints []string `json:"hints"`
}

func ValidateAdvice(offset, length uint64, hints uint32) error {
	if offset > ^uint64(0)-length {
		return errors.New("advice range exceeds uint64; zero length means through EOF")
	}
	if hints == 0 || hints & ^uint32(0x7ff) != 0 {
		return errors.New("advice requires one or more known NFSv4.2 hints")
	}
	return nil
}

// Advise retains advice on an already-open locked file. Opening and immediately
// closing here would allow the server to forget the hint before the next I/O.
// This bounded API requires a whole-file lock and never replays the operation.
func (c *Client) Advise(ctx context.Context, fh []byte, offset, length uint64, hints uint32) (AdviceResult, error) {
	if c.v4 == nil || c.v4.minor != 2 {
		return AdviceResult{}, ErrRequiresV42
	}
	if err := ValidateAdvice(offset, length, hints); err != nil {
		return AdviceResult{}, err
	}
	v := c.v4
	l := v.lockFor(fh)
	if l == nil {
		return AdviceResult{}, errors.New("advise requires a retained whole-file lock; run lock first")
	}
	if err := v.checkLockedIO(fh, 1); err != nil {
		return AdviceResult{}, err
	}
	e := append(encoder(nil), l.sid...)
	e.u64(offset)
	e.u64(length)
	e.u32(1)
	e.u32(hints)
	result := AdviceResult{Hints: []string{}}
	err := v.compound(ctx, fh4(fh), op4(63, e, func(d *decoder) {
		words := d.u32()
		if words > 8 {
			d.err = errors.New("IO_ADVISE result bitmap exceeds bound")
			return
		}
		for word := uint32(0); word < words; word++ {
			mask := d.u32()
			for bit := uint32(0); bit < 32; bit++ {
				if mask&(1<<bit) == 0 {
					continue
				}
				index := word*32 + bit
				if index >= uint32(len(adviseNames)) {
					d.err = errors.New("IO_ADVISE returned an unknown hint")
					return
				}
				result.Hints = append(result.Hints, adviseNames[index])
			}
		}
	}))
	if err == nil {
		err = v.checkLockedIO(fh, 1)
	}
	if err != nil {
		return AdviceResult{}, err
	}
	return result, nil
}
