package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOffloadSourceLedgerPreservesConcurrentDestinationCallback(t *testing.T) {
	main, _, initialClose := sessionOffloadFixture(t, func([]byte) []byte { t.Error("source cleanup used destination connection"); return nil }, true)
	initialClose()
	j, err := openOffloadJournal(filepath.Join(t.TempDir(), "copy.state"), "profile", offloadIntent{Operation: "copyfrom", Source: []byte("file"), Destination: []byte("dest"), Length: 6}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer j.file.Close()
	r := j.record
	r.Resources = &OffloadResources{Version: 1, Complete: true}
	saved, err := main.saveSession()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := offloadRecoveryProfile(*main.c.config)
	if err != nil {
		t.Fatal(err)
	}
	r.Recovery = &OffloadSessionEvidence{Profile: profile, Session: saved, Result: &OffloadCompletion{ID: bytes.Repeat([]byte{2}, 16)}}
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	main.recall.offload = &offloadPending{journal: j, fh: []byte("dest"), length: 6}
	restore, err := main.installOffloadRecovery(j)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	source, _, sourceDone := resourceFixture(t, func(request []byte) []byte { return resourceReply(t, request, "") })
	sourceDone()
	source.recall = nil
	source.session = bytes.Repeat([]byte{8}, 16)
	source.c.config.OffloadSessionRecovery = false
	ctx, restoreSource, err := main.trackOffloadEndpoint(context.Background(), source, "source")
	if err != nil {
		t.Fatal(err)
	}
	defer restoreSource()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 40 {
			main.recall.mu.Lock()
			err := j.recordCallback(&offloadReply{count: 6, stable: 2, verifier: make([]byte, 8)})
			main.recall.mu.Unlock()
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	_, closeIO, err := source.offloadOpenIO(ctx, []byte("file"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := closeIO(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	r = j.record
	e := r.Endpoints["source"]
	if e.Recovery == nil || e.Recovery.Session.Sequence != 3 || !bytes.Equal(e.Recovery.Session.Session, source.session) || r.Recovery.Session.Sequence != saved.Sequence || !r.Recovery.Committed || !offloadOwnResourcesReleased(endpointRecord(r, "source")) {
		t.Fatal("source session or destination callback evidence lost")
	}
	path := j.file.Name()
	j.file.Close()
	read, err := InspectOffloadJournal(path)
	if err != nil || read.Endpoints["source"].Recovery == nil || !read.Recovery.Committed {
		t.Fatal("endpoint checkpoint restart", err)
	}
}

func TestOffloadSourceAuthorizationExactReplay(t *testing.T) {
	for _, mode := range []string{"before-notify", "notify-loss", "cancel-loss", "denied"} {
		t.Run(mode, func(t *testing.T) {
			main, _, end := sessionOffloadFixture(t, func([]byte) []byte { t.Error("source request on destination"); return nil }, true)
			end()
			j, err := openOffloadJournal(filepath.Join(t.TempDir(), "source.state"), "profile", offloadIntent{Operation: "copyfrom", Source: []byte("file"), Destination: []byte("dest"), Length: 6}, true)
			if err != nil {
				t.Fatal(err)
			}
			defer j.file.Close()
			r := j.record
			r.Resources = &OffloadResources{Version: 1, Complete: true}
			if err := j.append(r); err != nil {
				t.Fatal(err)
			}
			main.recall.offload = &offloadPending{journal: j}
			restore, err := main.installOffloadRecovery(j)
			if err != nil {
				t.Fatal(err)
			}
			defer restore()
			var lose = true
			grant := bytes.Repeat([]byte{6}, 16)
			reply := func(request []byte) []byte {
				op := binary.BigEndian.Uint32(request[132:])
				if op == 61 {
					if mode == "denied" {
						b := channelReply(request, channelWords(61, 13))
						binary.BigEndian.PutUint32(b[24:], 13)
						return b
					}
					var e encoder
					e.u32(61)
					e.u32(0)
					e.u64(60)
					e.u32(0)
					e = append(e, grant...)
					e.u32(1)
					e.u32(3)
					e.str("tcp")
					e.str("127.0.0.1.8.1")
					return channelReply(request, e)
				}
				if op == 66 {
					return channelReply(request, channelWords(66, 0))
				}
				return resourceReply(t, request, "")
			}
			source, _, sourceEnd := resourceFixture(t, func(request []byte) []byte {
				op := binary.BigEndian.Uint32(request[132:])
				if lose && (mode == "notify-loss" && op == 61 || mode == "cancel-loss" && op == 66) {
					lose = false
					return nil
				}
				return reply(request)
			})
			sourceEnd()
			source.recall = nil
			source.c.config.OffloadSessionRecovery = false
			ctx, sourceRestore, err := main.trackOffloadEndpoint(context.Background(), source, "source")
			if err != nil {
				t.Fatal(err)
			}
			defer sourceRestore()
			view := ctx.Value(offloadResourceContextKey{}).(offloadResourceContext).journal
			sid, closeSource, err := source.offloadOpenIO(ctx, []byte("file"), 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := j.issue(); err != nil {
				t.Fatal(err)
			}
			if mode == "before-notify" {
				if err := closeSource(); err != nil {
					t.Fatal(err)
				}
				if !sourceGrantClosed(j.record, time.Now()) || view.record.Recovery.NotifyIssued {
					t.Fatal("unissued source grant invented")
				}
				return
			}
			args := encoder(bytes.Clone(sid))
			args = append(args, copyNetaddr("127.0.0.1:2049")...)
			err = source.compound(ctx, fh4([]byte("file")), op4(61, args, func(d *decoder) { decodeCopyGrant(d, time.Now()) }))
			if mode == "denied" {
				if err == nil || !sourceGrantClosed(j.record, time.Now()) || view.record.Recovery.Request != nil {
					t.Fatal("known grant denial lost", err)
				}
				return
			}
			if mode == "cancel-loss" {
				if err != nil {
					t.Fatal(err)
				}
				err = source.compound(ctx, fh4([]byte("file")), op4(66, encoder(grant), nil))
			}
			if err == nil || view.record.Recovery.Request == nil {
				t.Fatal("lost grant request not durable")
			}
			saved := *view.record.Recovery.Request
			path := j.file.Name()
			j.file.Close()
			reopened, err := loadOffloadJournal(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.file.Close()
			view = endpointJournal(reopened, "source")
			bound := resourceBoundFixture(t, source, view, func(request []byte) []byte {
				if !bytes.Equal(request[72:], saved.Inner) {
					t.Error("source replay changed cached slot")
				}
				return reply(request)
			})
			if err := bound.replayOffloadRequest(ctx, view); err != nil {
				t.Fatal(err)
			}
			if reopened.record.SourceGrant == nil || !bytes.Equal(reopened.record.SourceGrant.ID, grant) || reopened.record.SourceGrant.Revoked != (mode == "cancel-loss") {
				t.Fatal("source grant receipt not persisted")
			}
		})
	}
}

func TestOffloadCrashBeforeSourceLedgerHasNoAcquiredState(t *testing.T) {
	v, _, end := sessionOffloadFixture(t, func([]byte) []byte { t.Error("pre-source crash sent an RPC"); return nil }, true)
	end()
	j, err := openOffloadJournal(filepath.Join(t.TempDir(), "unused.state"), "profile", offloadIntent{Operation: "copyfrom", Source: []byte("file"), Destination: []byte("dest"), Length: 6}, true)
	if err != nil {
		t.Fatal(err)
	}
	r := j.record
	r.Resources = &OffloadResources{Version: 1, Complete: true}
	session, err := v.saveSession()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := offloadRecoveryProfile(*v.c.config)
	if err != nil {
		t.Fatal(err)
	}
	r.Recovery = &OffloadSessionEvidence{Profile: profile, Session: session}
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	path, id := j.file.Name(), j.record.ID
	j.file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err = RecoverOffload(ctx, *v.c.config, path, id)
	if err != nil || r.Pending || r.Outcome != "not-issued" || r.Recovery.StateCleanup != "confirmed" {
		t.Fatal("unused source state was not safely retired", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("recovery contacted an unnecessary server")
	}
}
