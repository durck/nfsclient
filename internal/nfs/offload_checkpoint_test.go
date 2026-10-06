package nfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func offloadPollingCheckpointFixture(t *testing.T) (*v4Client, *offloadJournal, func(), *int) {
	t.Helper()
	calls := 0
	v, j, closeFixture := sessionOffloadFixture(t, func(request []byte) []byte { calls++; return channelReply(request, channelWords(67, 0, 0, 0, 0)) }, true)
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
	installRecoveryJournal(v, j)
	return v, j, closeFixture, &calls
}

func pollCheckpointOnce(v *v4Client, j *offloadJournal) error {
	return v.compound(context.Background(), fh4(j.record.Destination), op4(67, encoder(j.record.Recovery.Result.ID), func(d *decoder) {
		d.u64()
		if d.u32() != 0 {
			d.err = errors.New("expected ongoing STATUS")
		}
	}))
}

func TestOffloadCheckpointWaitingRemainsBoundedAndRecoverable(t *testing.T) {
	v, j, closeFixture, calls := offloadPollingCheckpointFixture(t)
	defer closeFixture()
	original, err := j.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if other, err := loadOffloadJournal(j.file.Name(), false); err == nil {
		other.file.Close()
		t.Fatal("checkpoint lost process exclusivity")
	}
	logical := 0
	for logical <= maxOffloadJournal+65536 {
		if err := pollCheckpointOnce(v, j); err != nil {
			t.Fatal("normal waiting exhausted evidence", logical, err)
		}
		b, _ := json.Marshal(j.record)
		logical += 2 * (len(b) + 36)
	}
	if *calls < 1000 {
		t.Fatal("insufficient repeated status transitions", *calls)
	}
	info, err := j.file.Stat()
	if err != nil || info.Size() != int64(offloadCheckpointSize) || !os.SameFile(original, info) {
		t.Fatal("unbounded/replaced checkpoint inode", err)
	}
	prior := j.record
	invalid := prior
	invalid.Error = strings.Repeat("x", 65537)
	if err := j.append(invalid); err == nil {
		t.Fatal("oversized checkpoint accepted")
	}
	j.file.Close()
	recovered, err := loadOffloadJournal(j.file.Name(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.file.Close()
	if recovered.record.Sequence != prior.Sequence || recovered.record.Recovery.Request != nil || !recovered.record.Pending {
		t.Fatal("latest waiting state lost")
	}
	t.Logf("STATUS polls=%d equivalent legacy bytes=%d fixed bytes=%d", *calls, logical, info.Size())
}

func TestOffloadCheckpointInterruptedTransitions(t *testing.T) {
	for _, phase := range []string{"before-request", "after-reply"} {
		for _, stage := range []string{"before-write", "invalidated", "partial-body", "before-body-sync", "body-synced", "before-commit-sync", "committed"} {
			t.Run(phase+"/"+stage, func(t *testing.T) {
				v, j, closeFixture, calls := offloadPollingCheckpointFixture(t)
				defer closeFixture()
				original := j.record.Sequence
				j.checkpointFault = func(point string) error {
					if point == stage && (j.record.Recovery.Request != nil) == (phase == "after-reply") {
						return errors.New("injected checkpoint interruption")
					}
					return nil
				}
				if err := pollCheckpointOnce(v, j); err == nil {
					t.Fatal("fault did not gate operation")
				}
				if phase == "before-request" && *calls != 0 || phase == "after-reply" && *calls != 1 {
					t.Fatal("request crossed durability gate", *calls)
				}
				j.file.Close()
				recovered, err := loadOffloadJournal(j.file.Name(), false)
				if err != nil {
					t.Fatal("lost recoverable interrupted state", err)
				}
				defer recovered.file.Close()
				receiptCommitted := stage == "before-commit-sync" || stage == "committed"
				want := original
				if phase == "after-reply" {
					want++
				}
				if receiptCommitted {
					want++
				}
				if recovered.record.Sequence != want {
					t.Fatal("wrong surviving generation", recovered.record.Sequence, want)
				}
				wantRequest := phase == "after-reply" && !receiptCommitted || phase == "before-request" && receiptCommitted
				if (recovered.record.Recovery.Request != nil) != wantRequest {
					t.Fatal("exact pending request was lost or invented")
				}
				if recovered.record.Recovery.Committed || recovered.record.Recovery.Quiescent || !recovered.record.Pending {
					t.Fatal("waiting became completed")
				}
			})
		}
	}
}

func TestOffloadCheckpointCommittedCorruptionQuarantines(t *testing.T) {
	for _, mode := range []string{"active-body", "old-body", "footer", "partial-invalidation", "partial-commit", "extra", "truncate"} {
		t.Run(mode, func(t *testing.T) {
			_, j, closeFixture, _ := offloadPollingCheckpointFixture(t)
			defer closeFixture()
			path := j.file.Name()
			j.file.Close()
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			bank := j.bank
			if mode == "old-body" {
				bank = 1 - bank
			}
			start := len(offloadCheckpointMagic) + bank*offloadCheckpointBank
			switch mode {
			case "active-body", "old-body":
				data[start+8] ^= 1
			case "footer":
				data[start+offloadCheckpointBank-1] ^= 1
			case "partial-invalidation":
				clear(data[start+offloadCheckpointBank-offloadCheckpointFooter : start+offloadCheckpointBank-offloadCheckpointFooter+5])
			case "partial-commit":
				clear(data[start+offloadCheckpointBank-offloadCheckpointFooter+5 : start+offloadCheckpointBank])
			case "extra":
				data = append(data, 0)
			case "truncate":
				data = data[:len(data)-1]
			}
			j.file.Close()
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectOffloadJournal(path); err == nil {
				t.Fatal("committed corruption treated as interrupted update")
			}
		})
	}
}

func TestOffloadCheckpointReusesResolvedJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	intent := offloadIntent{Operation: "copyasync", Destination: []byte("file"), Length: 6}
	var last string
	for range 3 {
		j, err := openOffloadJournal(path, "profile", intent, true)
		if err != nil {
			t.Fatal(err)
		}
		if j.record.ID == last {
			t.Fatal("new operation reused identity")
		}
		last = j.record.ID
		if err := j.issue(); err != nil {
			t.Fatal(err)
		}
		if err := j.finish(nil); err != nil {
			t.Fatal(err)
		}
		stored, err := InspectOffloadJournal(path)
		if err != nil || stored.Pending || stored.ID != last {
			t.Fatal("completed checkpoint not reopenable", err)
		}
	}
}

func TestOffloadRecoverySessionIncarnationImmutable(t *testing.T) {
	changes := map[string]func(*SavedSession){
		"minor": func(s *SavedSession) { s.Minor = 1 }, "server-minor": func(s *SavedSession) { s.ServerMinor++ }, "nonce": func(s *SavedSession) { s.Nonce[0] ^= 1 }, "auth": func(s *SavedSession) { s.Auth.UID++ }, "groups": func(s *SavedSession) { s.Auth.Groups = []uint32{99} }, "principal": func(s *SavedSession) { s.Principal = "other@EXAMPLE.TEST" }, "identity": func(s *SavedSession) { s.Identity = "other" }, "channel": func(s *SavedSession) { s.Channel.Request++ }, "root": func(s *SavedSession) { s.Root = []byte("other") }, "lease": func(s *SavedSession) { s.LeaseSeconds++ }, "read-size": func(s *SavedSession) { s.ReadSize++ }, "write-size": func(s *SavedSession) { s.WriteSize++ }, "clock": func(s *SavedSession) { s.Confirmed = s.Confirmed.Add(-1) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			_, j, closeFixture, _ := offloadPollingCheckpointFixture(t)
			defer closeFixture()
			body, _ := json.Marshal(j.record)
			var altered OffloadRecord
			if err := json.Unmarshal(body, &altered); err != nil {
				t.Fatal(err)
			}
			change(&altered.Recovery.Session)
			if err := j.append(altered); err == nil {
				t.Fatal("saved original incarnation changed")
			}
		})
	}
}

func TestOffloadCheckpointRefusesLegacyConversion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy")
	intent := offloadIntent{Operation: "copyasync", Destination: []byte("file"), Length: 6}
	j, err := openOffloadJournal(path, "profile", intent)
	if err != nil {
		t.Fatal(err)
	}
	j.file.Close()
	before, _ := os.ReadFile(path)
	if j, err := openOffloadJournal(path, "profile", intent, true); err == nil {
		j.file.Close()
		t.Fatal("converted active legacy evidence")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("legacy evidence was changed")
	}
}
