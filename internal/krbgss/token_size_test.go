package gssapi

import (
	"fmt"
	"testing"
)

func TestTokenSizesMatchWireWithoutConsumingSequence(t *testing.T) {
	for _, etype := range []int32{17, 18} {
		for _, subkeys := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", etype, subkeys), func(t *testing.T) {
				a, b := privacyPair(etype, subkeys)
				for _, ctx := range []*context{a, b} {
					for _, n := range []int{0, 1, 3, 4, 15, 16, 17, 1023} {
						seq := ctx.sequenceNumber
						micSize, sealOverhead, err := ctx.TokenSizes()
						if err != nil || ctx.sequenceNumber != seq {
							t.Fatalf("sizing changed sequence: %v", err)
						}
						// RFC 4121 AES CTS: 16-byte MIC header + 12-byte checksum;
						// Wrap has two headers, 16-byte confounder and 12-byte MAC.
						if micSize != 28 || sealOverhead != 60 {
							t.Fatalf("mic=%d seal overhead=%d", micSize, sealOverhead)
						}
						mic, err := ctx.MakeSignature(make([]byte, n))
						if err != nil {
							t.Fatal(err)
						}
						sealed, err := ctx.Seal(make([]byte, n))
						if err != nil {
							t.Fatal(err)
						}
						if len(mic) != micSize || len(sealed) != n+sealOverhead {
							t.Fatalf("actual token sizes MIC=%d seal=%d payload=%d", len(mic), len(sealed), n)
						}
					}
				}
			})
		}
	}
}
