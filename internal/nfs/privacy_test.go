package nfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Test only RPC framing here; real cryptography is covered by krbgss and MIT.
type testPrivacy struct {
	testMIC
	fail bool
}

func (p testPrivacy) Seal(b []byte) ([]byte, error) {
	if p.fail {
		return nil, errors.New("seal failure")
	}
	return append([]byte(nil), b...), nil
}
func (p testPrivacy) Unseal(b []byte) ([]byte, error) {
	if p.fail {
		return nil, errors.New("unseal failure")
	}
	return append([]byte(nil), b...), nil
}

func TestPrivacyFraming(t *testing.T) {
	g := &rpcGSS{context: testPrivacy{}, seq: 7, service: 3, established: true}
	args := encoder{0, 0, 0, 42}
	wrapped, err := g.protect(args)
	if err != nil {
		t.Fatal(err)
	}
	want := encoder{0, 0, 0, 8, 0, 0, 0, 7, 0, 0, 0, 42}
	if !bytes.Equal(wrapped, want) {
		t.Fatalf("incorrect opaque seq+XDR: %x", wrapped)
	}
	d := &decoder{b: wrapped}
	if err := g.unprotect(d); err != nil || !bytes.Equal(d.b, args) {
		t.Fatalf("round trip: %v", err)
	}
	for _, mode := range []string{"old-sequence", "truncated", "oversize", "trailing", "empty", "unaligned", "unseal-error", "missing-unsealer"} {
		t.Run(mode, func(t *testing.T) {
			wire := append(encoder(nil), wrapped...)
			g.context = testPrivacy{}
			switch mode {
			case "old-sequence":
				wire[7] = 6
			case "truncated":
				wire = wire[:len(wire)-1]
			case "oversize":
				binary.BigEndian.PutUint32(wire, maxRecord+1)
			case "trailing":
				wire = append(wire, 0, 0, 0, 0)
			case "empty":
				wire = encoder{0, 0, 0, 0}
			case "unaligned":
				wire = nil
				wire.opaque([]byte{0, 0, 0, 7, 42})
			case "unseal-error":
				g.context = testPrivacy{fail: true}
			case "missing-unsealer":
				g.context = testMIC{}
			}
			if err := g.unprotect(&decoder{b: wire}); err == nil {
				t.Fatal("invalid privacy frame accepted")
			}
		})
	}
	for _, ctx := range []micContext{testPrivacy{fail: true}, testMIC{}} {
		g.context = ctx
		if _, err := g.protect(args); err == nil {
			t.Fatal("privacy silently bypassed")
		}
	}
	g.context = testPrivacy{}
	if _, err := g.protect(make(encoder, maxRecord)); err == nil {
		t.Fatal("oversized arguments accepted")
	}
}
