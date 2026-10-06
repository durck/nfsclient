package nfs

import (
	"math"
	"testing"
)

func TestObjectRequiredLength(t *testing.T) {
	// The oracle walks individual logical bytes independently of the production
	// last-stripe formula, including tiny ranges near uint64's upper boundary.
	for _, unit := range []uint64{1, 2, 7, 97, 65536, 1 << 20} {
		for _, count := range []int{1, 2, 3, 7, 64} {
			layout := &objectLayout{unit: unit, components: make([]objectCredential, count)}
			for _, first := range []uint64{0, 1, unit - 1, unit, unit + 1, unit*uint64(count) - 1, 1 << 53, math.MaxUint64 - 4096} {
				for _, length := range []uint64{0, 1, 2, 37, 259, 4096} {
					end := first + length
					want := make([]uint64, count)
					for logical := first; logical < end; logical++ {
						stripe, within := logical/unit, logical%unit
						component := stripe % uint64(count)
						want[component] = stripe/uint64(count)*unit + within + 1
					}
					for component := range count {
						if got := objectRequiredLength(layout, component, first, end); got != want[component] {
							t.Fatalf("unit=%d components=%d range=[%d,%d) component=%d: got %d want %d", unit, count, first, end, component, got, want[component])
						}
					}
				}
			}
		}
	}
}
