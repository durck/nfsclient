package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestV4SequenceRecoveryFlags(t *testing.T) {
	// Wire values are independent of production constants (RFC 8881 18.46.2).
	for _, minor := range []uint32{1, 2} {
		for _, tc := range []struct {
			name                               string
			flags                              uint32
			reclaiming, moved, lost, forbidden bool
		}{
			{name: "lease-moved", flags: 0x80, moved: true},
			{name: "restart", flags: 0x100, lost: true},
			{name: "revoked", flags: 0x10, lost: true, forbidden: true},
			{name: "moved-and-revoked", flags: 0x90, moved: true, lost: true, forbidden: true},
			{name: "restart-during-reclaim", flags: 0x100, reclaiming: true},
			{name: "revoked-during-reclaim", flags: 0x110, reclaiming: true, lost: true, forbidden: true},
		} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, tc.name), func(t *testing.T) {
				p := &lockPeerState{}
				v := lockPeer4(t, minor, p)
				if _, err := v.c.Lock(context.Background(), []byte("file"), false); err != nil {
					t.Fatal(err)
				}
				p.sequenceFlags, v.reclaiming = tc.flags, tc.reclaiming
				if err := v.compound(context.Background()); err != nil {
					t.Fatal(err)
				}
				if v.leaseMoved.Load() != tc.moved || v.stateLost.Load() != tc.lost || v.reclaimForbidden.Load() != tc.forbidden {
					t.Fatalf("flag %#x: moved=%v lost=%v reclaim-forbidden=%v", tc.flags, v.leaseMoved.Load(), v.stateLost.Load(), v.reclaimForbidden.Load())
				}
				_, err := v.c.MigrationLocks()
				if (err != nil) != tc.lost {
					t.Fatalf("wrong migration eligibility for flag %#x: %v", tc.flags, err)
				}
			})
		}
	}
}

func compoundStateReply(minor uint32, status, count uint32, failed bool) encoder {
	var e encoder
	e.u32(status)
	e.str("")
	e.u32(count)
	if count == 0 {
		return e
	}
	if minor > 0 {
		e.u32(53)
		e.u32(0)
		e = append(e, bytes.Repeat([]byte{9}, 16)...)
		e.u32(1)
		for range 4 {
			e.u32(0)
		}
		count--
	}
	if count > 0 {
		e.u32(22)
		if failed {
			e.u32(status)
		} else {
			e.u32(0)
		}
	}
	return e
}

func TestV4CompoundErrorFraming(t *testing.T) {
	for _, minor := range []uint32{0, 1, 2} {
		for _, mode := range []string{"empty-moved", "empty-moved-trailing", "success-ops-error-header", "truncated-header", "truncated-count", "empty-legal-trailing", "valid-moved", "valid-success", "valid-empty-error"} {
			t.Run(fmt.Sprintf("4.%d/%s", minor, mode), func(t *testing.T) {
				count := uint32(1)
				if minor > 0 {
					count++
				}
				status := uint32(10019)
				switch mode {
				case "valid-success":
					status = 0
				case "valid-empty-error", "empty-legal-trailing":
					status = 10021
				}
				if mode == "empty-moved" || mode == "empty-moved-trailing" || mode == "valid-empty-error" || mode == "empty-legal-trailing" {
					count = 0
				}
				wire := compoundStateReply(minor, status, count, mode == "valid-moved")
				switch mode {
				case "empty-moved-trailing", "empty-legal-trailing":
					wire.u32(0xabcdef)
				case "truncated-header":
					wire = wire[:4]
				case "truncated-count":
					wire = wire[:10]
				}
				c := scriptedClient(t, func(_, _ uint32, _ *decoder) (encoder, error) { return wire, nil })
				v := &v4Client{c: c, minor: minor}
				c.v4 = v
				if minor > 0 {
					v.session, v.sequence = bytes.Repeat([]byte{9}, 16), 1
					j, err := loadLockJournal(filepath.Join(t.TempDir(), "state"), true)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { j.file.Close() })
					if err := j.append(validSavedLockRecord()); err != nil {
						t.Fatal(err)
					}
					v.journal = j
				}
				err := v.compound(context.Background(), fh4([]byte("file")))
				valid := mode == "valid-moved" || mode == "valid-success" || mode == "valid-empty-error"
				var s Status
				if valid {
					if status == 0 && err != nil || status != 0 && (!errors.As(err, &s) || uint32(s) != status) || v.stateLost.Load() {
						t.Fatalf("valid response refused: %v", err)
					}
				} else if err == nil || errors.As(err, &s) || !v.stateLost.Load() || !c.nfs.closed {
					t.Fatalf("malformed reply trusted: err=%v lost=%v closed=%v", err, v.stateLost.Load(), c.nfs.closed)
				}
				if v.journal != nil {
					wantPending := !valid || count == 0
					if v.journal.record.Pending != wantPending {
						t.Fatalf("journal pending=%v, want %v", v.journal.record.Pending, wantPending)
					}
				}
			})
		}
	}
}

func TestV4CompoundEmptyErrors(t *testing.T) {
	// RFC 8881 16.2.4, Table 15. None conveys filesystem migration authority.
	for _, status := range []uint32{22, 10006, 10008, 10021, 10036, 10040, 10065, 10066, 10067, 10070} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c := scriptedClient(t, func(_, _ uint32, _ *decoder) (encoder, error) {
				return compoundStateReply(1, status, 0, false), nil
			})
			v := &v4Client{c: c, minor: 1, session: bytes.Repeat([]byte{9}, 16), sequence: 1}
			c.v4 = v
			if err := v.compound(context.Background(), fh4([]byte("file"))); err != Status(status) || v.stateLost.Load() || v.sequence != 1 {
				t.Fatalf("legal compound-level error changed: %v", err)
			}
		})
	}
}

func savedLockPeer(t *testing.T) (*v4Client, *lockPeerState, uint64) {
	t.Helper()
	p := &lockPeerState{}
	v := lockPeer4(t, 1, p)
	id, err := v.c.Lock(context.Background(), []byte("file"), true)
	if err != nil {
		t.Fatal(err)
	}
	v.c.config = &Config{Host: "127.0.0.1", Version: "4.1", Security: "sys", TLS: TLSConfig{Enabled: true, ServerName: "fixture.test"}}
	v.clientNonce = bytes.Repeat([]byte{1}, 16)
	v.serverIdentity = &createSessionKey{owner: "owner", scope: "scope"}
	v.leaseSeconds = 60
	ns := LockNamespace{Export: "/data", CWD: "/", Root: []byte("/data"), Paths: map[uint64]string{id: "/file"}}
	if err := v.c.SaveLocks(filepath.Join(t.TempDir(), "state"), ns); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.journal.file.Close() })
	return v, p, id
}

func TestSavedLockPolicyRefusalPreservesState(t *testing.T) {
	for _, mode := range []string{"mutation", "credentials", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			v, p, id := savedLockPeer(t)
			slot, serial := v.sequence, v.journal.record.Serial
			ctx := context.Background()
			var err error
			switch mode {
			case "mutation":
				err = v.chmod(ctx, []byte("file"), 0600)
			case "credentials":
				auth := v.c.Auth
				auth.UID++
				err = v.compoundAuth(ctx, auth, fh4([]byte("file")))
			case "cleanup":
				err = v.compound(ctx, op4(4, nil, nil))
			}
			if err == nil || v.stateLost.Load() || v.sequence != slot || v.journal.record.Serial != serial || v.journal.record.Pending {
				t.Fatalf("local refusal changed confirmed state: %v", err)
			}
			var data bytes.Buffer
			if _, err := v.c.ReadTo(ctx, []byte("file"), &data); err != nil || data.String() != "locked" {
				t.Fatalf("read after policy refusal: %v", err)
			}
			if err := v.c.Unlock(ctx, id); err != nil || p.unlocks != 1 || !v.journal.record.Retired {
				t.Fatalf("unlock after policy refusal: %v", err)
			}
		})
	}
}

func TestSavedLockPersistenceFailureQuarantinesState(t *testing.T) {
	for _, mode := range []string{"closed", "changed-size", "full"} {
		t.Run(mode, func(t *testing.T) {
			v, p, id := savedLockPeer(t)
			j := v.journal
			switch mode {
			case "closed":
				if err := j.file.Close(); err != nil {
					t.Fatal(err)
				}
			case "changed-size":
				if _, err := j.file.WriteAt([]byte{1}, j.size); err != nil {
					t.Fatal(err)
				}
			case "full":
				if err := j.file.Truncate(maxLockJournal); err != nil {
					t.Fatal(err)
				}
				j.size = maxLockJournal
			}
			slot := v.sequence
			if err := v.compound(context.Background(), fh4([]byte("file"))); err == nil || !v.stateLost.Load() || v.sequence != slot {
				t.Fatalf("journal failure was not quarantined: %v", err)
			}
			if err := v.c.Unlock(context.Background(), id); !errors.Is(err, ErrLockUncertain) || p.unlocks != 0 {
				t.Fatalf("journal failure allowed unlock: %v", err)
			}
		})
	}
}
