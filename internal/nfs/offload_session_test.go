package nfs

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

func sessionOffloadFixture(t *testing.T, reply func([]byte) []byte, prepared ...bool) (*v4Client, *offloadJournal, func()) {
	t.Helper()
	v, _ := channelWirePeer(t, sessionChannelLimits{8192, 1024, 1024, 8}, reply)
	v.minor = 2
	v.c.v4 = v
	v.c.version = "4.2"
	v.c.security = "sys"
	v.c.config = &Config{Host: "fixture.test", Version: "4.2", Security: "sys", TLS: TLSConfig{Enabled: true, ServerName: "fixture.test"}, Offload: true, OffloadSessionRecovery: true}
	v.recall = &layoutRecall{offloadEnabled: true}
	v.clientID = 5
	v.clientNonce = bytes.Repeat([]byte{4}, 16)
	v.root = []byte("root")
	v.leaseSeconds = 90
	v.serverIdentity = &createSessionKey{owner: "server", scope: "scope", clientID: 5, minor: 2}
	now := time.Now()
	v.lastLease.Store(&now)
	j, err := openOffloadJournal(filepath.Join(t.TempDir(), "state"), "profile", offloadIntent{Operation: "writesame", Destination: []byte("file"), Offset: 7, Length: 6}, true)
	if err != nil {
		t.Fatal(err)
	}
	v.recall.offload = &offloadPending{fh: []byte("file"), length: 6, journal: j}
	restore, err := v.installOffloadRecovery(j)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) == 0 || !prepared[0] {
		if err = j.issue(); err != nil {
			t.Fatal(err)
		}
	}
	return v, j, func() { restore(); j.file.Close() }
}

func recoveryADBArgs() encoder {
	e := encoder(bytes.Repeat([]byte{1}, 16))
	e.u32(2)
	e.u64(7)
	e.u64(2)
	e.u64(3)
	e.u64(^uint64(0))
	e.u32(0)
	e.u64(0)
	e.opaque([]byte("ab"))
	return e
}

func TestOffloadRecoveredReceiptCannotClaimOriginalCleanup(t *testing.T) {
	v, j, closeFixture := sessionOffloadFixture(t, func(request []byte) []byte {
		return channelReply(request, channelWords(70, 0, 0, 0, 6, 2, 0, 0))
	})
	defer closeFixture()
	if err := v.compound(context.Background(), fh4([]byte("file")), op4(70, recoveryADBArgs(), func(d *decoder) { decodeOffloadReply(d) })); err != nil {
		t.Fatal(err)
	}
	r := j.record
	r.Pending, r.Outcome = false, "completed-data-state-unverified"
	r.Recovery = cloneOffloadSession(r.Recovery)
	if err := j.append(r); err == nil {
		t.Fatal("missing state disposition accepted")
	}
	r.Recovery.StateCleanup = "confirmed"
	if err := j.append(r); err == nil {
		t.Fatal("invented cleanup confirmation accepted")
	}
	r.Recovery.StateCleanup = "unverified"
	r.Outcome = "completed"
	if err := j.append(r); err == nil {
		t.Fatal("retained original state hidden as full completion")
	}
	r.Outcome = "completed-data-state-unverified"
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	j.file.Close()
	stored, err := InspectOffloadJournal(j.file.Name())
	if err != nil || stored.Pending || stored.Recovery.StateCleanup != "unverified" {
		t.Fatal("data receipt did not survive restart", err)
	}
}

func TestOffloadSessionDurableBeforeSendAndReceipt(t *testing.T) {
	var j *offloadJournal
	v, journal, closeFixture := sessionOffloadFixture(t, func(request []byte) []byte {
		if j.record.Recovery == nil || j.record.Recovery.Request == nil || !bytes.Equal(j.record.Recovery.Request.Inner, request[72:]) {
			t.Error("offload was sent without durable exact request")
		}
		return channelReply(request, channelWords(70, 0, 0, 0, 6, 2, 0, 0))
	})
	j = journal
	defer closeFixture()
	if err := v.compound(context.Background(), fh4([]byte("file")), op4(70, recoveryADBArgs(), func(d *decoder) { decodeOffloadReply(d) })); err != nil {
		t.Fatal(err)
	}
	x := j.record.Recovery
	if x.Request != nil || x.Session.Sequence != 2 || x.Result == nil || x.Result.Count != 6 || !x.Committed {
		t.Fatalf("missing confirmed response: %+v", x)
	}
	path := j.file.Name()
	j.file.Close()
	r, err := InspectOffloadJournal(path)
	if err != nil || r.Recovery == nil || !r.Recovery.Committed {
		t.Fatal(r, err)
	}
}

func TestOffloadSessionLostReplyExactReplay(t *testing.T) {
	v, j, closeFixture := sessionOffloadFixture(t, func([]byte) []byte { return nil })
	defer closeFixture()
	ops := []v4Op{fh4([]byte("file")), op4(70, recoveryADBArgs(), func(d *decoder) { decodeOffloadReply(d) })}
	if err := v.compound(context.Background(), ops...); err == nil {
		t.Fatal("lost reply accepted")
	}
	saved := j.record.Recovery.Request
	if saved == nil || j.record.Recovery.Result != nil {
		t.Fatal("unknown result lost its replay evidence")
	}
	bound, _ := channelWirePeer(t, v.channel, func(request []byte) []byte {
		if !bytes.Equal(request[72:], saved.Inner) {
			t.Error("replay changed exact payload")
		}
		return channelReply(request, channelWords(70, 0, 0, 0, 6, 2, 0, 0))
	})
	bound.minor = 2
	bound.clientID = v.clientID
	bound.clientNonce = v.clientNonce
	bound.root = v.root
	bound.serverIdentity = v.serverIdentity
	bound.leaseSeconds = v.leaseSeconds
	bound.lastLease.Store(v.lastLease.Load())
	bound.c.version = "4.2"
	bound.c.security = "sys"
	bound.afterCached = func(s SavedCompound, b []byte) error { return bound.recordOffloadResponse(j, s, b) }
	if err := bound.replaySavedCompound(context.Background(), *saved, ops...); err != nil {
		t.Fatal(err)
	}
	if !j.record.Recovery.Committed || j.record.Recovery.Request != nil {
		t.Fatal("recovered cached response not synced")
	}
}

func TestOffloadSessionRejectsMalformedReplyAndChangedIntent(t *testing.T) {
	v, j, closeFixture := sessionOffloadFixture(t, func(request []byte) []byte {
		return append(channelReply(request, channelWords(70, 0, 0, 0, 6, 2, 0, 0)), 0)
	})
	defer closeFixture()
	if err := v.compound(context.Background(), fh4([]byte("file")), op4(70, recoveryADBArgs(), func(d *decoder) { decodeOffloadReply(d) })); err == nil {
		t.Fatal("trailing response accepted")
	}
	if j.record.Recovery.Request == nil || j.record.Recovery.Result != nil {
		t.Fatal("malformed response recorded as receipt")
	}
	bad := j.record
	bad.Offset++
	if validateOffloadSession(bad, OffloadRecord{}) == nil {
		t.Fatal("request moved to another range")
	}
}

func TestOffloadSessionCallbackIsDurableAndCommitVerifierBound(t *testing.T) {
	v, j, closeFixture := sessionOffloadFixture(t, func(request []byte) []byte { return channelReply(request, channelWords(70, 0, 0, 0, 6, 1, 4, 5)) })
	defer closeFixture()
	if err := v.compound(context.Background(), fh4([]byte("file")), op4(70, recoveryADBArgs(), func(d *decoder) { decodeOffloadReply(d) })); err != nil {
		t.Fatal(err)
	}
	if j.record.Recovery.Committed {
		t.Fatal("DATA_SYNC became FILE_SYNC")
	}
	p := &offloadReply{count: 6, stable: 1, verifier: channelWords(4, 5)}
	if err := j.recordCallback(p); err != nil {
		t.Fatal(err)
	}
	r := j.record
	r.Recovery = cloneOffloadSession(r.Recovery)
	d := &decoder{b: channelWords(4, 6)}
	offloadRecoveryDecoder(&r, SavedCompoundOperation{Code: 5})(d)
	if d.err == nil || r.Recovery.Committed {
		t.Fatal("changed verifier accepted")
	}
	j.file.Close()
	if err := j.recordCallback(p); err == nil || j.record.Recovery.Committed {
		t.Fatal("failed callback sync certified data", err)
	}
}
