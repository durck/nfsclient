package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"nfs-viewer/internal/nfs"
)

// Migrate transfers one whole-export namespace with its confirmed retained
// OPEN/LOCK state. The source must report MOVED; location and exact namespace
// checks precede publication. No interrupted command is repeated.
func (s *Session) Migrate(ctx context.Context, approval ReferralTarget) error {
	return s.migrate(ctx, approval, false)
}

// FailoverLocks continues a confirmed live session at one explicitly approved
// protected replica without requiring the unavailable source to report MOVED.
// It requires a known slot and confirmed retained locks; it cannot resolve an
// interrupted request or revive expired/revoked state.
func (s *Session) FailoverLocks(ctx context.Context, approval ReferralTarget) error {
	return s.migrate(ctx, approval, true)
}

// ArmStatefulFailover keeps the selected namespace and every original stateid;
// only the approved transport may change after cached-session proof.
func (s *Session) ArmStatefulFailover(approval ReferralTarget) error {
	if s.Client == nil || s.AutoUID || s.AutoEscape || s.Escaped || s.Export == "" || !bytes.Equal(s.Root.Handle, s.ExportRoot.Handle) || s.BaseAuth.UID != s.Client.Auth.UID || s.BaseAuth.GID != s.Client.Auth.GID || !slices.Equal(s.BaseAuth.Groups, s.Client.Auth.Groups) {
		return errors.New("automatic stateful failover requires a fixed selected namespace and identity")
	}
	if approval.Server == "" || strings.ContainsAny(approval.Server, " /\\\t\r\n\x00") || len(approval.Server) > 1024 {
		return errors.New("invalid approved failover server")
	}
	return s.Client.EnableStatefulFailover(approval.Target)
}

func (s *Session) migrate(ctx context.Context, approval ReferralTarget, sourceUnavailable bool) error {
	if s.AutoUID || s.AutoEscape || s.Escaped || s.Export == "" || !bytes.Equal(s.Root.Handle, s.ExportRoot.Handle) || len(s.Client.Locks()) == 0 {
		return errors.New("state migration requires fixed export and retained locks")
	}
	if approval.Server == "" || strings.ContainsAny(approval.Server, " /\\\t\r\n\x00") || len(approval.Server) > 1024 {
		return errors.New("invalid advertised migration server")
	}
	if err := s.Client.ValidateReadReplica(approval.Target); err != nil {
		return err
	}
	if s.Client.Version() == "4.0" {
		return errors.New("transferred-session state migration requires NFSv4.1/4.2")
	}
	if s.BaseAuth.UID != s.Client.Auth.UID || s.BaseAuth.GID != s.Client.Auth.GID || !slices.Equal(s.BaseAuth.Groups, s.Client.Auth.Groups) {
		return errors.New("migration requires matching base credentials")
	}
	export, err := referralPath(s.Export)
	if err != nil {
		return err
	}
	paths := map[uint64]string{}
	handles := map[uint64][]byte{}
	inventory, err := s.Client.MigrationLocks()
	if err != nil {
		return err
	}
	for _, l := range inventory {
		if l.Uncertain || s.LockPaths[l.ID] == "" {
			return errors.New("migration requires confirmed lock namespace inventory")
		}
		if _, err := referralPath(s.LockPaths[l.ID]); err != nil {
			return err
		}
		paths[l.ID] = s.LockPaths[l.ID]
		handles[l.ID], err = s.Client.LockedFileHandle(l.ID)
		if err != nil {
			return err
		}
	}
	g := captureReadSession(s)
	target, rootPath := approval.Target, export
	if !sourceUnavailable {
		if _, err = s.Client.GetAttr(ctx, s.ExportRoot.Handle); !referralMovedOnly(err) {
			return errors.New("selected export has not reported a valid MOVED result; state migration refused")
		}
		loc, err := s.Client.Locations(ctx, s.ExportRoot.Handle, "")
		if err != nil {
			return err
		}
		if !slices.Equal(loc.Root, export) {
			return errors.New("state migration requires fs_root to equal the selected export")
		}
		target, rootPath, err = referralDestination(loc, export, []ReferralTarget{approval})
		if err != nil {
			return err
		}
	}
	nextExport := "/" + strings.Join(rootPath, "/")
	if err := g.checkProfile(s); err != nil {
		return err
	}
	var next *Session
	transition := s.Client.MigrateLocks
	if sourceUnavailable {
		transition = s.Client.FailoverLocks
	}
	fresh, err := transition(ctx, target, func(c *nfs.Client) error {
		if err := g.checkProfile(s); err != nil {
			return err
		}
		host, _, _ := net.SplitHostPort(target.Address)
		candidate := New(c, host, false, false, s.Notice)
		candidate.BaseAuth = s.BaseAuth
		root, err := c.Mount(ctx, nextExport)
		if err != nil {
			return err
		}
		if !bytes.Equal(root.Handle, s.ExportRoot.Handle) || !root.Attr.HasFSID || !s.ExportRoot.Attr.HasFSID || root.Attr.FSID != s.ExportRoot.Attr.FSID || root.Attr.FSIDMinor != s.ExportRoot.Attr.FSIDMinor || !root.Attr.HasFileID || !s.ExportRoot.Attr.HasFileID || root.Attr.FileID != s.ExportRoot.Attr.FileID {
			return errors.New("migrated export identity or handle changed")
		}
		candidate.Root, candidate.ExportRoot, candidate.Export = root, cloneRoot(root), nextExport
		cwd, err := resolveSavedLockPath(ctx, candidate, s.CWD)
		if err != nil || cwd.Attr.Type != 2 {
			return errors.New("migrated working directory changed")
		}
		candidate.CWD = s.CWD
		candidate.LockPaths = map[uint64]string{}
		for _, l := range c.Locks() {
			n, err := resolveSavedLockPath(ctx, candidate, paths[l.ID])
			if err != nil || n.Attr.Type != 1 || !bytes.Equal(n.Handle, handles[l.ID]) {
				return fmt.Errorf("migrated lock %d pathname/handle changed", l.ID)
			}
			candidate.LockPaths[l.ID] = paths[l.ID]
		}
		if err := g.checkProfile(s); err != nil {
			return err
		}
		next = candidate
		return nil
	})
	if err != nil {
		return err
	}
	old := s.Client
	next.Client = fresh
	*s = *next
	old.Close()
	return nil
}
