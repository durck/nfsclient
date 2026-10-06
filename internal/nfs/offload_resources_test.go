package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// This peer constructs RFC 8881 OPEN/CLOSE replies independently and checks
// actual on-wire owners, stateids and WANT_NO_DELEG, rather than intentOps.
func resourceReply(t *testing.T, request []byte, mode string) []byte {
	t.Helper()
	op := binary.BigEndian.Uint32(request[132:]) // four-byte PUTFH
	if binary.BigEndian.Uint32(request[120:]) == 45 {
		b := channelReply(request, channelWords(45, 0))
		b = append(b[:80], b[88:]...)
		binary.BigEndian.PutUint32(b[32:], 2)
		return b
	}
	switch op {
	case 18:
		if binary.BigEndian.Uint32(request[140:])&0x400 == 0 {
			t.Error("durable OPEN requested a delegation")
		}
		if mode == "deny" {
			b := channelReply(request, channelWords(18, 13))
			binary.BigEndian.PutUint32(b[24:], 13)
			return b
		}
		last := channelWords(18, 0)
		last = append(last, bytes.Repeat([]byte{9}, 16)...)
		last = append(last, channelWords(0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 4)...)
		last = append(last, []byte("file")...)
		b := channelReply(request, last)
		binary.BigEndian.PutUint32(b[32:], 4)
		return b
	case 4:
		if !bytes.Equal(request[140:156], bytes.Repeat([]byte{9}, 16)) {
			t.Error("CLOSE changed the owned OPEN stateid")
		}
		return channelReply(request, append(channelWords(4, 0), bytes.Repeat([]byte{9}, 16)...))
	case 12, 14:
		return channelReply(request, append(channelWords(op, 0), bytes.Repeat([]byte{8}, 16)...))
	}
	t.Errorf("unexpected resource opcode %d", op)
	return nil
}

func resourceBoundFixture(t *testing.T, original *v4Client, j *offloadJournal, reply func([]byte) []byte) *v4Client {
	v, _ := channelWirePeer(t, original.channel, reply)
	v.minor = 2
	v.c.Auth = original.c.Auth
	v.sequence = j.record.Recovery.Session.Sequence
	v.clientID = original.clientID
	v.clientNonce = original.clientNonce
	v.root = original.root
	v.leaseSeconds = original.leaseSeconds
	v.serverIdentity = original.serverIdentity
	v.c.security = original.c.security
	v.c.version = original.c.version
	confirmed := j.record.Recovery.Session.Confirmed
	v.lastLease.Store(&confirmed)
	return v
}

func TestOffloadOwnedLockCleanupAcrossSecondCrash(t *testing.T) {
	for _, phase := range []uint32{12, 14, 45, 4} {
		t.Run(fmt.Sprint(phase), func(t *testing.T) {
			lost := false
			v, j, done := resourceFixture(t, func(request []byte) []byte {
				op := binary.BigEndian.Uint32(request[132:])
				if binary.BigEndian.Uint32(request[120:]) == 45 {
					op = 45
				}
				if op == phase && !lost {
					lost = true
					return nil
				}
				return resourceReply(t, request, "")
			})
			defer done()
			ctx := context.WithValue(context.Background(), offloadResourceContextKey{}, offloadResourceContext{v, j})
			_, err := v.ownedOffloadReadLock(ctx, j, []byte("file"))
			if phase != 12 {
				if err != nil {
					t.Fatal(err)
				}
				err = v.cleanupOffloadResources(ctx, j)
			}
			if err == nil || j.record.Recovery.Request == nil {
				t.Fatal("state loss not journaled")
			}
			path := j.file.Name()
			j.file.Close()
			reopened, err := loadOffloadJournal(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.file.Close()
			pending := *reopened.record.Recovery.Request
			calls := 0
			bound := resourceBoundFixture(t, v, reopened, func(request []byte) []byte {
				calls++
				if calls == 1 && !bytes.Equal(request[72:], pending.Inner) {
					t.Error("cleanup replay changed original slot")
				}
				if calls == 2 {
					return nil
				}
				return resourceReply(t, request, "")
			})
			if err := bound.replayOffloadRequest(ctx, reopened); err != nil {
				t.Fatal(err)
			}
			err = bound.cleanupOffloadResources(ctx, reopened)
			if phase != 4 {
				if err == nil || reopened.record.Recovery.Request == nil {
					t.Fatal("second cleanup loss not retained")
				}
				pending = *reopened.record.Recovery.Request
				reopened.file.Close()
				reopened, err = loadOffloadJournal(path, false)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.file.Close()
				calls = 0
				last := resourceBoundFixture(t, v, reopened, func(request []byte) []byte {
					calls++
					if calls == 1 && !bytes.Equal(request[72:], pending.Inner) {
						t.Error("second recovery changed saved cleanup")
					}
					return resourceReply(t, request, "")
				})
				if err := last.replayOffloadRequest(ctx, reopened); err != nil {
					t.Fatal(err)
				}
				if err := last.cleanupOffloadResources(ctx, reopened); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !offloadResourcesReleased(reopened.record) {
				t.Fatal("confirmed owned lock cleanup incomplete")
			}
		})
	}
}

func TestOffloadPartialOpenAndForgedReleaseStayUnverified(t *testing.T) {
	v, j, done := resourceFixture(t, func(request []byte) []byte {
		b := resourceReply(t, request, "")
		binary.BigEndian.PutUint32(b[24:], 13)
		b = b[:len(b)-8]
		binary.BigEndian.PutUint32(b[len(b)-4:], 13)
		return b
	})
	defer done()
	if _, _, err := v.offloadOpenIO(context.Background(), []byte("file"), 1); err == nil {
		t.Fatal("partial OPEN reported success")
	}
	if j.record.Resources.Entries[0].State != "unknown" || j.record.Recovery.Request != nil || len(j.record.Resources.Entries[0].Intent.Lock.OpenState) != 16 {
		t.Fatal("partial OPEN evidence discarded")
	}
	r := j.record
	r.Pending, r.Outcome = false, "not-issued"
	if err := j.append(r); err == nil {
		t.Fatal("orphaned OPEN reported released")
	}
	if err := v.cleanupOffloadResources(context.Background(), j); err == nil {
		t.Fatal("unknown file binding was closed")
	}
}

func resourceFixture(t *testing.T, reply func([]byte) []byte) (*v4Client, *offloadJournal, func()) {
	v, j, closeFixture := sessionOffloadFixture(t, reply, true)
	v.parents = map[string]v4Name{"file": {dir: []byte("root"), name: "file"}}
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
	return v, j, closeFixture
}

func TestOffloadUnsentIntentAndLeaseCannotInventCleanup(t *testing.T) {
	v, j, done := resourceFixture(t, func(request []byte) []byte { return resourceReply(t, request, "") })
	defer done()
	if _, _, err := v.offloadOpenIO(context.Background(), []byte("file"), 1); err != nil {
		t.Fatal(err)
	}
	r := j.record
	r.Resources = cloneOffloadResources(r.Resources)
	r.Resources.Active = 1
	r.Resources.Entries[0].State = "closing"
	r.Resources.Entries[0].Intent.Phase = "close"
	if err := j.append(r); err != nil {
		t.Fatal(err)
	}
	sequence := v.sequence
	if err := v.compound(context.Background()); !channelNotSent(err) || !errors.Is(err, errOffloadResourceBusy) {
		t.Fatal("lease-only request escaped resource barrier", err)
	}
	if v.sequence != sequence || v.stateLost.Load() || j.record.Resources.Entries[0].State != "closing" || j.record.Recovery.Request != nil {
		t.Fatal("unrelated request changed cleanup evidence")
	}
	var inner encoder
	inner.str("")
	inner.u32(2)
	inner.u32(1)
	inner.u32(53)
	inner = append(inner, v.session...)
	inner.u32(v.sequence)
	inner.u32(0)
	inner.u32(0)
	inner.u32(1)
	saved := saveCompound(v, v.c.Auth, inner, []v4Op{op4(53, nil, nil)})
	var reply encoder
	reply.u32(0)
	reply.str("")
	reply.u32(1)
	reply.u32(53)
	reply.u32(0)
	reply = append(reply, v.session...)
	reply.u32(v.sequence)
	reply = append(reply, make([]byte, 16)...)
	trial := j.record
	trial.Resources = cloneOffloadResources(trial.Resources)
	if consumeOffloadResponse(&trial, saved, reply) == nil || trial.Resources.Entries[0].State != "closing" {
		t.Fatal("independent response parser forged cleanup")
	}
	path := j.file.Name()
	j.file.Close()
	reopened, err := loadOffloadJournal(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.file.Close()
	if err := reopened.cancelUnsentResource(); err != nil {
		t.Fatal(err)
	}
	if reopened.record.Resources.Active != 0 || reopened.record.Resources.Entries[0].State != "open" {
		t.Fatal("pre-send CLOSE was not safely cancelled")
	}
	bound := resourceBoundFixture(t, v, reopened, func(request []byte) []byte { return resourceReply(t, request, "") })
	if err := bound.cleanupOffloadResources(context.Background(), reopened); err != nil {
		t.Fatal(err)
	}
	if !offloadResourcesReleased(reopened.record) {
		t.Fatal("cleanup after pre-send crash incomplete")
	}
}

func TestOffloadChildPrivilegeClassifier(t *testing.T) {
	for _, code := range []uint32{4, 9, 10, 12, 14, 18, 25, 45, 60, 61, 66, 67} {
		got := offloadRequestUsesChild(&SavedCompound{Operations: []SavedCompoundOperation{{Code: 22}, {Code: code}}})
		want := code == 60 || code == 61 || code == 66 || code == 67
		if got != want {
			t.Fatalf("opcode %d child=%t", code, got)
		}
	}
}

func TestOffloadCrashAfterIntentBeforeSendBarrier(t *testing.T) {
	for _, phase := range []string{"open", "lock", "unlock", "free", "close"} {
		t.Run(phase, func(t *testing.T) {
			v, j, done := resourceFixture(t, func(request []byte) []byte {
				if phase == "open" {
					t.Error("OPEN sent before its durable request")
					return nil
				}
				return resourceReply(t, request, "")
			})
			defer done()
			ctx := context.WithValue(context.Background(), offloadResourceContextKey{}, offloadResourceContext{v, j})
			if phase != "open" {
				if phase == "unlock" || phase == "free" {
					if _, err := v.ownedOffloadReadLock(ctx, j, []byte("file")); err != nil {
						t.Fatal(err)
					}
				} else if _, _, err := v.offloadOpenIO(ctx, []byte("file"), 1); err != nil {
					t.Fatal(err)
				}
				if phase == "free" {
					if err := v.offloadResourceTransition(ctx, j, 1, "unlock", "unlocking"); err != nil {
						t.Fatal(err)
					}
				}
			}
			j.checkpointFault = func(stage string) error {
				if stage == "committed" {
					return errors.New("process stopped after intent sync")
				}
				return nil
			}
			var err error
			switch phase {
			case "open":
				_, _, err = v.offloadOpenIO(ctx, []byte("file"), 1)
			case "close":
				err = v.closeOffloadResource(ctx, j, 1)
			default:
				state := map[string]string{"lock": "locking", "unlock": "unlocking", "free": "freeing"}[phase]
				err = v.offloadResourceTransition(ctx, j, 1, phase, state)
			}
			if err == nil {
				t.Fatal("crash not injected")
			}
			path := j.file.Name()
			j.file.Close()
			reopened, err := loadOffloadJournal(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.file.Close()
			if reopened.record.Resources.Active != 1 || reopened.record.Recovery == nil || reopened.record.Recovery.Request != nil {
				t.Fatal("pre-send crash evidence incorrect")
			}
			if err := reopened.cancelUnsentResource(); err != nil {
				t.Fatal(err)
			}
			if phase == "open" {
				if !offloadResourcesReleased(reopened.record) {
					t.Fatal("unsent OPEN created cleanup debt")
				}
				return
			}
			bound := resourceBoundFixture(t, v, reopened, func(request []byte) []byte { return resourceReply(t, request, "") })
			if err := bound.cleanupOffloadResources(ctx, reopened); err != nil {
				t.Fatal(err)
			}
			if !offloadResourcesReleased(reopened.record) {
				t.Fatal("pre-send state intent prevented cleanup")
			}
		})
	}
}

func TestOffloadKnownDataDenialRetainsFailureAndCleansOwnedState(t *testing.T) {
	v, j, done := resourceFixture(t, func(request []byte) []byte {
		if binary.BigEndian.Uint32(request[132:]) == 70 {
			b := channelReply(request, channelWords(70, 13))
			binary.BigEndian.PutUint32(b[24:], 13)
			return b
		}
		return resourceReply(t, request, "")
	})
	defer done()
	sid, _, err := v.offloadOpenIO(context.Background(), []byte("file"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.issue(); err != nil {
		t.Fatal(err)
	}
	args := recoveryADBArgs()
	copy(args[:16], sid)
	if err := v.compound(context.Background(), fh4([]byte("file")), op4(70, args, func(d *decoder) { decodeOffloadReply(d) })); err == nil {
		t.Fatal("denial accepted")
	}
	if j.record.Recovery.Failure == nil || j.record.Recovery.Failure.Status != 13 || j.record.Recovery.Request != nil || j.record.Recovery.Committed {
		t.Fatal("known data failure evidence lost")
	}
	if err := v.cleanupOffloadResources(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if !offloadResourcesReleased(j.record) || !j.record.Pending || j.record.Recovery.Committed {
		t.Fatal("data denial became success or leaked owned OPEN")
	}
}

func TestOffloadOwnedOpenClosesAndBorrowedLockSurvives(t *testing.T) {
	v, j, done := resourceFixture(t, func(request []byte) []byte { return resourceReply(t, request, "") })
	defer done()
	sid, closeIO, err := v.offloadOpenIO(context.Background(), []byte("file"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sid, bytes.Repeat([]byte{9}, 16)) || j.record.Resources.Entries[0].State != "open" || offloadResourcesReleased(j.record) {
		t.Fatal("OPEN ownership not persisted")
	}
	if err := closeIO(); err != nil {
		t.Fatal(err)
	}
	if !offloadResourcesReleased(j.record) {
		t.Fatal("confirmed CLOSE did not release inventory")
	}
	v.locks = map[uint64]*v4Lock{1: {info: LockInfo{ID: 1, Length: LockToEOF}, file: &v4Open{fh: []byte("file")}, sid: bytes.Repeat([]byte{3}, 16)}}
	sid, closeIO, err = v.offloadOpenIO(context.Background(), []byte("file"), 1)
	if err != nil || !bytes.Equal(sid, bytes.Repeat([]byte{3}, 16)) {
		t.Fatal("borrowed lock unavailable", err)
	}
	if err := closeIO(); err != nil {
		t.Fatal(err)
	}
	if err := v.cleanupOffloadResources(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if len(v.locks) != 1 || j.record.Resources.Entries[1].State != "borrowed" {
		t.Fatal("cleanup touched caller-owned state")
	}
}

func TestOffloadDeniedOpenConsumesSlotWithoutInventingState(t *testing.T) {
	v, j, done := resourceFixture(t, func(request []byte) []byte { return resourceReply(t, request, "deny") })
	defer done()
	_, _, err := v.offloadOpenIO(context.Background(), []byte("file"), 1)
	if err == nil || j.record.Recovery == nil || j.record.Recovery.Request != nil || j.record.Recovery.Session.Sequence != 2 || !offloadResourcesReleased(j.record) {
		t.Fatalf("denied OPEN disposition err=%v record=%+v", err, j.record)
	}
}

func TestOffloadLostOpenAndCloseReplayOwnershipAcrossRestart(t *testing.T) {
	for _, lost := range []string{"open", "close"} {
		t.Run(lost, func(t *testing.T) {
			v, j, done := resourceFixture(t, func(request []byte) []byte {
				op := binary.BigEndian.Uint32(request[132:])
				if op == 18 && lost == "open" || op == 4 && lost == "close" {
					return nil
				}
				return resourceReply(t, request, "")
			})
			defer done()
			_, closeIO, err := v.offloadOpenIO(context.Background(), []byte("file"), 1)
			if lost == "close" {
				if err != nil {
					t.Fatal(err)
				}
				err = closeIO()
			}
			if err == nil || j.record.Recovery.Request == nil {
				t.Fatal("lost state operation has no exact durable request")
			}
			saved := *j.record.Recovery.Request
			path := j.file.Name()
			j.file.Close()
			reopened, err := loadOffloadJournal(path, false)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.file.Close()
			bound, _ := channelWirePeer(t, v.channel, func(request []byte) []byte {
				if !bytes.Equal(request[72:], saved.Inner) {
					t.Error("resource replay changed exact compound")
				}
				return resourceReply(t, request, "")
			})
			bound.minor = 2
			bound.c.Auth = v.c.Auth
			bound.sequence = saved.Sequence
			bound.clientID = v.clientID
			bound.clientNonce = v.clientNonce
			bound.root = v.root
			bound.leaseSeconds = v.leaseSeconds
			bound.serverIdentity = v.serverIdentity
			bound.c.security = v.c.security
			bound.c.version = v.c.version
			bound.lastLease.Store(v.lastLease.Load())
			trial := reopened.record
			trial.Resources = cloneOffloadResources(trial.Resources)
			trial.Recovery = cloneOffloadSession(trial.Recovery)
			var ops []v4Op
			for _, op := range saved.Operations {
				ops = append(ops, op4(op.Code, encoder(op.Args), offloadRecoveryDecoder(&trial, op)))
			}
			installRecoveryJournal(bound, reopened)
			if err := bound.replaySavedCompound(context.Background(), saved, ops...); err != nil {
				t.Fatal(err)
			}
			want := "open"
			if lost == "close" {
				want = "closed"
			}
			if reopened.record.Resources.Entries[0].State != want || reopened.record.Recovery.Request != nil {
				t.Fatal("replay did not durably finish resource transition")
			}
		})
	}
}
