package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func multiRangeFlow(t *testing.T, s *session.Session) {
	t.Helper()
	ctx := context.Background()
	root, _, err := s.Resolve(ctx, ".", true)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 96)
	for i := range payload {
		payload[i] = byte(i)
	}
	node, err := s.Client.Create(ctx, root.Handle, "ranges", 0600, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Client.WriteFrom(ctx, node.Handle, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	other, err := s.Client.Reconnect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	// Bind the pathname on the second client, including its OPEN parent cache.
	otherSession := session.New(other, s.Host, false, false, nil)
	if err := otherSession.Use(ctx, s.Export); err != nil {
		t.Fatal(err)
	}
	if err := otherSession.CD(ctx, s.CWD); err != nil {
		t.Fatal(err)
	}
	otherNode, _, err := otherSession.Resolve(ctx, "ranges", false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Client.LockRange(ctx, node.Handle, true, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Client.LockRange(ctx, node.Handle, true, 32, 16)
	if err != nil {
		t.Fatal("second disjoint range", err)
	}
	if first == second || len(s.Client.Locks()) != 2 {
		t.Fatal("range IDs collapsed")
	}
	local := t.TempDir()
	sh := &Shell{Session: s, Out: io.Discard, Err: io.Discard, LocalDir: local}
	if _, err := sh.Execute(ctx, "getrange ranges part 4 8"); err != nil {
		t.Fatal("locked partial read", err)
	}
	if got, err := os.ReadFile(filepath.Join(local, "part")); err != nil || !bytes.Equal(got, payload[4:12]) {
		t.Fatal("partial bytes", got, err)
	}
	if _, err := sh.Execute(ctx, "getrange ranges outside 8 32"); err == nil {
		t.Fatal("read crossed a lock boundary")
	}
	if _, err := os.Stat(filepath.Join(local, "outside")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published out-of-range read", err)
	}
	patch := bytes.Repeat([]byte{255}, 16)
	if err := os.WriteFile(filepath.Join(local, "patch"), patch, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(ctx, "putrange patch ranges 32"); err != nil {
		t.Fatal("locked partial write", err)
	}
	copy(payload[32:48], patch)
	if _, err := sh.Execute(ctx, "putrange patch ranges 40"); err == nil {
		t.Fatal("write crossed a lock boundary")
	}
	readOnly, err := s.Client.LockRange(ctx, node.Handle, false, 64, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Execute(ctx, "putrange patch ranges 64"); err == nil {
		t.Fatal("wrote under a read lock")
	}
	if err := s.Client.Unlock(ctx, readOnly); err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	if _, err := s.GetRange(cancelCtx, "ranges", filepath.Join(local, "cancelled"), 0, 16, func(done, total uint64) {
		if done > 0 {
			cancel()
		}
	}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled range download", err)
	}
	cancel()
	if _, err := os.Stat(filepath.Join(local, "cancelled")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published cancelled range", err)
	}
	if _, err := s.Client.LockRange(ctx, node.Handle, false, 8, 32); err == nil {
		t.Fatal("overlapping local ranges accepted")
	}
	if _, err := s.Client.ReadTo(ctx, node.Handle, io.Discard); !errors.Is(err, nfs.ErrPartialLockIO) {
		t.Fatal("whole-file I/O bypass", err)
	}
	gap, err := other.LockRange(ctx, otherNode.Handle, true, 16, 16)
	if err != nil {
		t.Fatal("adjacent range conflict", err)
	}
	if _, err := other.LockRange(ctx, otherNode.Handle, true, 32, 16); !errors.Is(err, nfs.Status(10010)) {
		t.Fatal("missing second-range contention", err)
	}
	if err := s.Client.Unlock(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := other.LockRange(ctx, otherNode.Handle, true, 32, 16); !errors.Is(err, nfs.Status(10010)) {
		t.Fatal("unlock dropped the other range", err)
	}
	freed, err := other.LockRange(ctx, otherNode.Handle, true, 0, 16)
	if err != nil {
		t.Fatal("first range remains locked", err)
	}
	if err := s.Client.Unlock(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := other.Unlock(ctx, gap); err != nil {
		t.Fatal(err)
	}
	if err := other.Unlock(ctx, freed); err != nil {
		t.Fatal(err)
	}
	var complete bytes.Buffer
	if _, err := s.Client.ReadTo(ctx, node.Handle, &complete); err != nil || !bytes.Equal(complete.Bytes(), payload) {
		t.Fatal("range write changed outside bytes", err)
	}
	if err := s.Remove(ctx, "ranges"); err != nil {
		t.Fatal(err)
	}
}
