package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"nfs-viewer/internal/nfs"
)

// Reclaim restores only previously confirmed server-restart locks and validates
// their original namespace bindings before publishing the recovered session.
func (s *Session) Reclaim(ctx context.Context) error {
	if s.Escaped {
		return errors.New("reset the discovered root before reclaiming state")
	}
	if (s.Client.Version() == "2" || s.Client.Version() == "3") && (s.AutoUID || s.AutoEscape) {
		return errors.New("NLM reclaim requires a fixed identity/export")
	}
	expectedLocks := s.Client.Locks()
	for _, l := range expectedLocks {
		if s.LockPaths[l.ID] == "" {
			return errors.New("reclaim requires the original path for every held lock")
		}
	}
	fresh, err := s.Client.ReclaimLocks(ctx)
	if err != nil {
		return err
	}
	ready := false
	defer func() {
		if !ready {
			fresh.Close()
		}
	}()
	next := New(fresh, s.Host, s.AutoUID, false, s.Notice)
	next.BaseAuth = s.BaseAuth
	root, err := fresh.Mount(ctx, s.Export)
	if err != nil {
		return fmt.Errorf("reclaim export: %w", err)
	}
	a, b := s.ExportRoot.Attr, root.Attr
	if a.HasFSID && (!b.HasFSID || a.FSID != b.FSID || a.FSIDMinor != b.FSIDMinor) || a.HasFileID && (!b.HasFileID || a.FileID != b.FileID) {
		return errors.New("reclaimed export changed identity")
	}
	next.Root, next.ExportRoot, next.Export = root, cloneRoot(root), s.Export
	if err := next.CD(ctx, s.CWD); err != nil {
		return fmt.Errorf("reclaim working directory: %w", err)
	}
	next.LockPaths = make(map[uint64]string)
	for _, l := range fresh.Locks() {
		path := s.LockPaths[l.ID]
		n, _, err := next.Resolve(ctx, path, false)
		if err != nil {
			return fmt.Errorf("reclaim lock %d path: %w", l.ID, err)
		}
		fh, err := fresh.LockedFileHandle(l.ID)
		if err != nil || n.Attr.Type != 1 || !bytes.Equal(fh, n.Handle) {
			return fmt.Errorf("reclaimed lock %d pathname changed", l.ID)
		}
		next.LockPaths[l.ID] = path
	}
	// Namespace validation also renews the lease and can report revocation in
	// an otherwise successful SEQUENCE. Publish only the full confirmed set.
	held := fresh.Locks()
	if len(held) != len(expectedLocks) {
		return fmt.Errorf("reclaimed lock inventory changed: %w", nfs.ErrLockUncertain)
	}
	for i, l := range held {
		want := expectedLocks[i]
		want.Uncertain = false
		if l != want {
			return fmt.Errorf("reclaimed lock %d changed or became uncertain: %w", l.ID, nfs.ErrLockUncertain)
		}
	}
	next.AutoEscape = s.AutoEscape
	old := s.Client
	*s = *next
	ready = true
	old.Close()
	return nil
}

// Reconnect restores the export and working directory by name on fresh state.
// No failed command is replayed. Discovered roots require an explicit reset
// first: silently changing their interpretation would redirect relative paths.
func (s *Session) Reconnect(ctx context.Context) error {
	if s.Escaped {
		return errors.New("reset the discovered root with root reset before reconnecting")
	}
	fresh, err := s.Client.Reconnect(ctx)
	if err != nil {
		return err
	}
	return s.installReconnect(ctx, fresh, s.Host)
}

func (s *Session) installReconnect(ctx context.Context, fresh *nfs.Client, host string) error {
	ready := false
	defer func() {
		if !ready {
			fresh.Close()
		}
	}()
	next := New(fresh, host, s.AutoUID, false, s.Notice)
	next.BaseAuth = s.BaseAuth
	if s.Export != "" {
		if err := next.Use(ctx, s.Export); err != nil {
			return fmt.Errorf("reconnect export: %w", err)
		}
		a, b := s.ExportRoot.Attr, next.ExportRoot.Attr
		if a.HasFSID && (!b.HasFSID || a.FSID != b.FSID || a.FSIDMinor != b.FSIDMinor) ||
			a.HasFileID && (!b.HasFileID || a.FileID != b.FileID) {
			return errors.New("reconnected export changed identity; start a new session to select it explicitly")
		}
		if err := next.CD(ctx, s.CWD); err != nil {
			return fmt.Errorf("reconnect working directory: %w", err)
		}
	}
	next.AutoEscape = s.AutoEscape
	old := s.Client
	*s = *next
	ready = true
	old.Close()
	return nil
}
