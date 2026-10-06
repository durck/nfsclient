package nfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestOffloadADBExpectedBytes(t *testing.T) {
	first := uint32(2)
	b := ApplicationDataBlock{BlockSize: 16, BlockCount: 2, FirstNumber: &first, PatternOffset: 12, Pattern: []byte{0xfe, 0xed, 0xfa, 0xce}}
	// RFC 7862 8.2/15.12: zero-filled blocks, monotonic big-endian ADBN,
	// and the literal guard pattern at its independent relative offset.
	want := []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0xfe, 0xed, 0xfa, 0xce}
	h := sha256.Sum256(want)
	got, err := adbDigest(context.Background(), b)
	if err != nil || got != hex.EncodeToString(h[:]) {
		t.Fatal(got, err)
	}
	// A range beyond the older 16 MiB reconciliation bound is streamed.
	b = ApplicationDataBlock{BlockSize: 1 << 20, BlockCount: 17}
	got, err = adbDigest(context.Background(), b)
	h = sha256.Sum256(make([]byte, 17<<20))
	if err != nil || got != hex.EncodeToString(h[:]) {
		t.Fatal("large range", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adbDigest(ctx, b); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation", err)
	}
}

func TestOffloadExpectedContentImmutable(t *testing.T) {
	j, err := openOffloadJournal(filepath.Join(t.TempDir(), "state"), "profile", offloadIntent{Operation: "copyasync", Source: []byte("src"), Destination: []byte("dst"), Offset: 3, SourceOffset: 5, Length: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	r := j.record
	r.Expectation = &OffloadExpectation{SHA256: hex.EncodeToString(make([]byte, 32)), Size: 30, FSID: 7, FileID: 8, Parent: []byte("root"), Name: "file"}
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	if err := j.issue(); err != nil {
		t.Fatal(err)
	}
	r = j.record
	e := *r.Expectation
	e.FileID++
	r.Expectation = &e
	if err := j.append(r); err == nil {
		t.Fatal("changed destination accepted")
	}
	r.Expectation = nil
	if err := j.append(r); err == nil {
		t.Fatal("expected content removed")
	}
}

func TestOffloadSourceGrantExpirationProof(t *testing.T) {
	now := time.Now()
	var e encoder
	e.u64(172800)
	e.u32(0)
	e = append(e, bytes.Repeat([]byte{1}, 16)...)
	e.u32(1)
	e = append(e, copyNetaddr("192.0.2.1:2049")...)
	d := &decoder{b: e}
	g := decodeCopyGrant(d, now)
	if d.err != nil || !g.proofExpires.After(g.expires.Add(23*time.Hour)) {
		t.Fatal("operation deadline shortened authorization proof", d.err)
	}
	r := OffloadRecord{Operation: "copyfrom", SourceGrant: &OffloadSourceGrant{ID: g.id, Recorded: g.recorded, Expires: g.proofExpires}}
	if sourceGrantClosed(r, now.Add(25*time.Hour)) || !sourceGrantClosed(r, now.Add(49*time.Hour)) {
		t.Fatal("grant expiry proof incorrect")
	}
	r.SourceGrant.Expires = time.Time{}
	if sourceGrantClosed(r, now.Add(100*24*time.Hour)) {
		t.Fatal("infinite grant guessed expired")
	}
	r.SourceGrant.Revoked = true
	if !sourceGrantClosed(r, now) {
		t.Fatal("confirmed revocation ignored")
	}
}

func TestOffloadRecoveredStatusRequiresContentVerification(t *testing.T) {
	for _, outcome := range []string{"ok", "partial", "failed", "malformed", "lost"} {
		t.Run(outcome, func(t *testing.T) {
			v, j, closeFixture := sessionOffloadFixture(t, func(request []byte) []byte {
				if outcome == "lost" {
					return nil
				}
				count, status, present := uint32(6), uint32(0), uint32(1)
				if outcome == "partial" {
					count = 5
				}
				if outcome == "failed" {
					status = 5
				}
				if outcome == "malformed" {
					present = 2
				}
				return channelReply(request, channelWords(67, 0, 0, count, present, status))
			})
			defer closeFixture()
			// Seed a validated asynchronous receipt as if the previous process
			// synced it, then died before any callback reached the client.
			s, err := v.saveSession()
			if err != nil {
				t.Fatal(err)
			}
			r := j.record
			profile, _ := offloadRecoveryProfile(*v.c.config)
			r.Recovery = &OffloadSessionEvidence{Profile: profile, Session: s, Result: &OffloadCompletion{ID: bytes.Repeat([]byte{1}, 16)}}
			// The test expectation is seeded in memory before appending a
			// consistent prepared history; production records it pre-issue.
			j.record.Phase = "prepared"
			r.Phase = "prepared"
			r.Expectation = &OffloadExpectation{SHA256: hex.EncodeToString(make([]byte, 32)), Size: 13, Parent: []byte("root"), Name: "file"}
			if err := j.append(r); err != nil {
				t.Fatal(err)
			}
			if err := j.issue(); err != nil {
				t.Fatal(err)
			}
			err = pollRecoveredOffload(context.Background(), v, j)
			ok := outcome != "lost" && outcome != "malformed"
			if (err == nil) != ok || j.record.Recovery.Committed || j.record.Recovery.Verified || !j.record.Pending {
				t.Fatal("status falsely certified durability", err)
			}
			if ok && (!j.record.Recovery.Quiescent || !j.record.Recovery.Result.Complete || j.record.Recovery.Request != nil) {
				t.Fatal("quiescence not durable")
			}
			if !ok && j.record.Recovery.Request == nil {
				t.Fatal("unknown status slot lost")
			}
		})
	}
}
