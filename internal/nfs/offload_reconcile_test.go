package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestOffloadReconcileEvidence(t *testing.T) {
	sum := sha256.Sum256([]byte("expected"))
	base := OffloadRecord{Sequence: 1, Pending: true, Phase: "prepared", Operation: "copyrange", Source: []byte("source"), Length: 8}
	evidence := OffloadReconcileEvidence{ExpectedSHA256: hex.EncodeToString(sum[:]), RecoveryProfile: strings.Repeat("a", 64), Size: 8}
	for _, mode := range []string{"prepared", "issued", "receipt", "retired", "bad-digest", "uppercase", "bad-profile", "zero", "too-large", "partial", "source-offset", "destination-offset", "async", "writesame", "no-source", "prepared-receipt", "late-intent", "changed-digest", "changed-file-id", "removed-intent", "removed-receipt"} {
		t.Run(mode, func(t *testing.T) {
			prev, record := base, base
			e := evidence
			record.Reconcile = &e
			valid := false
			switch mode {
			case "prepared":
				valid = true
			case "issued":
				prev.Reconcile = &evidence
				record.Phase = "issued"
				valid = true
			case "receipt":
				prev.Reconcile = &evidence
				prev.Phase = "issued"
				record.Phase = "issued"
				e.Receipt = true
				valid = true
			case "retired":
				prev.Reconcile = &evidence
				prev.Phase = "issued"
				record.Phase = "issued"
				e.Receipt = true
				record.Pending = false
				valid = true
			case "bad-digest":
				e.ExpectedSHA256 = strings.Repeat("z", 64)
			case "uppercase":
				e.ExpectedSHA256 = strings.ToUpper(e.ExpectedSHA256)
			case "bad-profile":
				e.RecoveryProfile = strings.Repeat("z", 64)
			case "zero":
				e.Size = 0
			case "too-large":
				e.Size = maxReconcileBytes + 1
				record.Length = e.Size
			case "partial":
				e.Size = 7
			case "source-offset":
				record.SourceOffset = 1
			case "destination-offset":
				record.Offset = 1
			case "async":
				record.Operation = "copyasync"
			case "writesame":
				record.Operation = "writesame"
			case "no-source":
				record.Source = nil
			case "prepared-receipt":
				e.Receipt = true
			case "late-intent":
				prev.Phase = "issued"
				record.Phase = "issued"
			case "changed-digest":
				prev.Reconcile = &evidence
				e.ExpectedSHA256 = strings.Repeat("b", 64)
			case "changed-file-id":
				prev.Reconcile = &evidence
				e.FileID++
			case "removed-intent":
				prev.Reconcile = &evidence
				record.Reconcile = nil
			case "removed-receipt":
				old := evidence
				old.Receipt = true
				prev.Phase = "issued"
				prev.Reconcile = &old
				record.Phase = "issued"
			}
			if err := validateOffloadReconcile(record, prev); (err == nil) != valid {
				t.Fatal("evidence validation", err, valid)
			}
		})
	}
}

func TestOffloadReconcileIssueRefusals(t *testing.T) {
	for _, mode := range []string{"held-locks", "source-offset", "destination-offset", "too-large", "async", "missing-journal", "missing-offload"} {
		t.Run(mode, func(t *testing.T) {
			cfg := Config{Version: "4.2", Offload: true, OffloadReconcile: true}
			if mode == "missing-journal" || mode == "missing-offload" {
				if mode == "missing-offload" {
					cfg.Offload = false
				}
				if _, err := Connect(context.Background(), cfg); err == nil {
					t.Fatal("incomplete recording profile connected")
				}
				return
			}
			calls := 0
			c := copyPeer(t, func(uint32, *decoder) (encoder, Status, error) { calls++; return nil, 0, nil })
			c.config = &cfg
			if mode != "held-locks" {
				c.v4.locks = nil
			}
			var sourceOffset, destinationOffset uint64
			length := uint64(8)
			var wait time.Duration
			switch mode {
			case "source-offset":
				sourceOffset = 1
			case "destination-offset":
				destinationOffset = 1
			case "too-large":
				length = maxReconcileBytes + 1
			case "async":
				wait = time.Second
			}
			if _, err := c.copyRange42(context.Background(), []byte("source"), []byte("destination"), sourceOffset, destinationOffset, length, false, wait); err == nil || calls != 0 {
				t.Fatal("unsupported profile issued RPC", err, calls)
			}
		})
	}
}

func TestOffloadReconcileDigestBounds(t *testing.T) {
	for _, mode := range []string{"exact", "short", "oversized", "split"} {
		t.Run(mode, func(t *testing.T) {
			data := []byte("expected")
			d := &boundedOffloadDigest{h: sha256.New(), remaining: uint64(len(data))}
			switch mode {
			case "exact":
				if n, err := d.Write(data); err != nil || n != len(data) || d.remaining != 0 {
					t.Fatal(n, err, d.remaining)
				}
			case "short":
				d.Write(data[:2])
				if d.remaining != 6 {
					t.Fatal("lost short-read bound")
				}
			case "oversized":
				before := d.h.Sum(nil)
				if n, err := d.Write(append(data, 0)); err == nil || n != 0 || d.remaining != 8 || !bytes.Equal(before, d.h.Sum(nil)) {
					t.Fatal("oversized input altered digest")
				}
			case "split":
				d.Write(data[:2])
				d.Write(data[2:])
				sum := sha256.Sum256(data)
				if d.remaining != 0 || !bytes.Equal(sum[:], d.h.Sum(nil)) {
					t.Fatal("split digest mismatch")
				}
			}
		})
	}
}
