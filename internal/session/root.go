package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"nfs-viewer/internal/nfs"
)

type RootCheck struct{ Name, Result string }
type RootVerification struct {
	Identity  string
	CheckedAt time.Time
	Auth      nfs.Auth
	Checks    []RootCheck
}

func cloneRoot(n nfs.Node) nfs.Node { n.Handle = append([]byte(nil), n.Handle...); return n }

// Object IDs describe the server's namespace, not a host filesystem path.
func RootObjectID(n nfs.Node) string {
	if !rootIdentityKnown(n) {
		return "object identity unavailable (server omitted fsid/fileid)"
	}
	return fmt.Sprintf("fsid %d:%d / fileid %d", n.Attr.FSID, n.Attr.FSIDMinor, n.Attr.FileID)
}
func rootIdentityKnown(n nfs.Node) bool { return n.Attr.HasFSID && n.Attr.HasFileID }
func sameRootObject(a, b nfs.Node) bool {
	return rootIdentityKnown(a) && rootIdentityKnown(b) && a.Attr.FSID == b.Attr.FSID && a.Attr.FSIDMinor == b.Attr.FSIDMinor && a.Attr.FileID == b.Attr.FileID
}

// SelectRoot checks the saved handle before changing any navigation state. It
// never re-runs discovery; reset must actually return to the original export.
func (s *Session) SelectRoot(ctx context.Context, discovered bool) error {
	if s.Export == "" {
		return errors.New("select an export with use first")
	}
	target := s.ExportRoot
	if discovered {
		if s.DiscoveredRoot == nil {
			return errors.New("no discovered directory saved; run root probe first")
		}
		target = *s.DiscoveredRoot
	}
	if len(target.Handle) == 0 {
		return errors.New("original export handle is unavailable; select the export again")
	}
	previous := s.Client.Auth
	s.Client.Auth = s.BaseAuth
	committed := false
	defer func() {
		if !committed {
			s.Client.Auth = previous
		}
	}()
	a, err := s.Client.GetAttr(ctx, target.Handle)
	if err != nil {
		return err
	}
	if a.Type != 2 {
		return errors.New("saved root is no longer a directory")
	}
	target.Attr = a
	s.identity(target)
	if _, err := s.Client.ReadDir(ctx, target.Handle); err != nil {
		return err
	}
	if err := s.Client.Tune(ctx, target.Handle); err != nil {
		return err
	}
	s.Root = cloneRoot(target)
	s.CWD = "/"
	s.Escaped = discovered
	s.RootVerification = nil
	s.ProbeError = nil
	committed = true
	return nil
}

// VerifyRoot gathers observations without changing root, cwd, or identity.
// No observation here proves the server host's /. In particular, LOOKUP("..")
// may stop at an export boundary rather than an underlying filesystem root.
func (s *Session) VerifyRoot(ctx context.Context) (*RootVerification, error) {
	if s.Export == "" {
		return nil, errors.New("select an export with use first")
	}
	report := &RootVerification{CheckedAt: time.Now(), Auth: s.Client.Auth, Identity: s.Client.Identity()}
	report.Auth.Groups = append([]uint32(nil), report.Auth.Groups...)
	s.RootVerification = report
	add := func(name, result string) { report.Checks = append(report.Checks, RootCheck{name, result}) }
	a, err := s.Client.GetAttr(ctx, s.Root.Handle)
	if err != nil {
		add("Directory", "unverified: "+err.Error())
		return report, err
	}
	current := nfs.Node{Handle: s.Root.Handle, Attr: a}
	if a.Type != 2 {
		err = errors.New("selected root is not a directory")
		add("Directory", err.Error())
		return report, err
	}
	add("Directory", "confirmed; "+RootObjectID(current))
	if _, err = s.Client.ReadDir(ctx, current.Handle); err != nil {
		add("Listing", "unavailable: "+err.Error())
		return report, err
	}
	add("Listing", "readable with the recorded identity")
	parent, err := s.Client.Lookup(ctx, current.Handle, "..")
	if err != nil {
		add("Parent", "unverified: "+err.Error())
		var status nfs.Status
		if !errors.As(err, &status) {
			return report, err
		}
	} else if !rootIdentityKnown(current) || !rootIdentityKnown(parent) {
		add("Parent", "resolved; identity comparison unavailable (server omitted fsid/fileid)")
	} else if sameRootObject(current, parent) {
		add("Parent", "same object; NFS boundary only, not proof of host /")
	} else {
		add("Parent", "different object; "+RootObjectID(parent))
	}
	if len(s.ExportRoot.Handle) == 0 {
		add("Export relation", "unverified: original export handle unavailable")
		return report, nil
	}
	original, err := s.Client.GetAttr(ctx, s.ExportRoot.Handle)
	if err != nil {
		add("Export relation", "unverified: "+err.Error())
		var status nfs.Status
		if !errors.As(err, &status) {
			return report, err
		}
		return report, nil
	}
	relation, err := traceRootAncestor(ctx, nfs.Node{Handle: s.ExportRoot.Handle, Attr: original}, current, s.Client.Lookup)
	add("Export relation", relation)
	return report, err
}

// Walking parents can establish ancestry, but inability to walk does not
// disprove it: exports may clamp parent lookup or deny its use. Bound both
// depth and cycles; keep this diagnostic independent from Resolve's root clamp.
func traceRootAncestor(ctx context.Context, original, target nfs.Node, lookup func(context.Context, []byte, string) (nfs.Node, error)) (string, error) {
	current := original
	seen := map[string]bool{}
	for steps := 0; steps <= 64; steps++ {
		if err := ctx.Err(); err != nil {
			return "unverified: " + err.Error(), err
		}
		if !rootIdentityKnown(current) || !rootIdentityKnown(target) {
			return "unverified: server omitted fsid/fileid", nil
		}
		if sameRootObject(current, target) {
			if steps == 0 {
				return "selected directory is the original export object", nil
			}
			return fmt.Sprintf("selected directory is an ancestor of the export (%d parent steps)", steps), nil
		}
		key := RootObjectID(current)
		if seen[key] {
			return "unverified: parent lookup cycle", nil
		}
		seen[key] = true
		if steps == 64 {
			return "unverified: 64-step parent lookup limit", nil
		}
		parent, err := lookup(ctx, current.Handle, "..")
		if err != nil {
			var status nfs.Status
			if errors.As(err, &status) {
				return "unverified: " + err.Error(), nil
			}
			return "unverified: " + err.Error(), err
		}
		if sameRootObject(current, parent) {
			return "unverified: server namespace boundary reached", nil
		}
		if parent.Attr.Type != 2 {
			return "unverified: parent is not a directory", nil
		}
		current = parent
	}
	return "unverified", nil
}
