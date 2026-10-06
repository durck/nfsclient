package nfs

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestOffloadPollingRenewsDurableLeaseAcrossRestart(t *testing.T) {
	var received []time.Time
	v, j, closeFixture := sessionOffloadFixture(t, func(request []byte) []byte {
		received = append(received, time.Now())
		return channelReply(request, channelWords(67, 0, 0, 0, 0))
	}, true)
	defer closeFixture()
	v.leaseSeconds = 1
	initial := time.Now()
	v.lastLease.Store(&initial)
	s, err := v.saveSession()
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := offloadRecoveryProfile(*v.c.config)
	r := j.record
	r.Expectation = offloadExpectedFixture()
	r.Recovery = &OffloadSessionEvidence{Profile: profile, Session: s, Result: &OffloadCompletion{ID: bytes.Repeat([]byte{1}, 16)}}
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	if err := j.issue(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if err := pollRecoveredOffload(ctx, v, j); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	j.file.Close()
	stored, err := InspectOffloadJournal(j.file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if len(received) < 4 || !time.Now().After(initial.Add(time.Second)) || !stored.Recovery.Session.Confirmed.After(initial.Add(time.Second)) || stored.Recovery.Session.Confirmed.After(received[len(received)-1]) {
		t.Fatalf("lease did not advance conservatively: polls=%d old=%v confirmed=%v", len(received), initial, stored.Recovery.Session.Confirmed)
	}
	// A restarted process has only the durable record. Authenticate a fresh
	// protected transport and BIND the original incarnation after the old deadline.
	saved := stored.Recovery.Session
	binds := 0
	peer := peer4(t, 2, func(code uint32, d *decoder) (encoder, Status, error) {
		var e encoder
		switch code {
		case 42:
			d.take(8)
			d.str()
			d.take(12)
			e.u64(saved.ClientID)
			e.u32(1)
			e.u32(0x80010000)
			e.u32(0)
			e.u64(saved.ServerMinor)
			e.opaque(saved.Owner)
			e.opaque(saved.Scope)
			e.u32(0)
		case 41:
			if !bytes.Equal(d.take(16), saved.Session) || d.u32() != 1 || d.boolean() {
				return nil, 0, errors.New("wrong restored BIND")
			}
			binds++
			e = append(e, saved.Session...)
			e.u32(1)
			e.u32(0)
		default:
			return nil, 0, errors.New("restart created or consumed original session")
		}
		return e, 0, nil
	})
	policy, servers := pnfsTLSFixture(t, "data")
	endpoint := pnfsTLSPeerEndpoint(t, peer, servers(0), "")
	host, port, _ := net.SplitHostPort(endpoint)
	number, _ := strconv.Atoi(port)
	cfg := Config{Host: host, NFSPort: number, Version: "4.2", Transport: "tcp", Security: "sys", Timeout: time.Second, TLS: policy}
	cfg.TLS.ServerName = "127.0.0.1"
	recovered, err := connectSavedSession(context.Background(), cfg, saved)
	if err != nil {
		t.Fatal("durable lease could not restore original session", err)
	}
	recovered.Close()
	if binds != 1 {
		t.Fatal("original session was not bound")
	}
}
