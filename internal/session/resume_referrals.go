package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"unicode/utf8"

	"nfs-viewer/internal/nfs"
)

// ReferralTarget binds an exact advertised server string to an operator-approved
// protected endpoint. No advertised hostname is resolved automatically.
type ReferralTarget struct {
	Server string
	Target nfs.ReadReplica
}

// Do not hide an independent cleanup, authentication or transport error inside
// a joined MOVED result. Only a fully decoded namespace absence allows a switch.
func referralMovedOnly(err error) bool {
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		children := many.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !referralMovedOnly(child) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return referralMovedOnly(one.Unwrap())
	}
	status, ok := err.(nfs.Status)
	return ok && status == 10019
}

func referralPath(p string) ([]string, error) {
	if len(p) > 16384 || !strings.HasPrefix(p, "/") {
		return nil, errors.New("referral path must be bounded and absolute")
	}
	var out []string
	for _, part := range strings.Split(p, "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." || len(part) > 255 || !utf8.ValidString(part) || strings.ContainsAny(part, "\\\x00\r\n") {
			return nil, errors.New("referral profile refuses dot components and invalid names")
		}
		out = append(out, part)
	}
	if len(out) > 64 {
		return nil, errors.New("referral path exceeds 64 components")
	}
	return out, nil
}

func referralDestination(loc nfs.FileLocations, physical []string, approved []ReferralTarget) (nfs.ReadReplica, []string, error) {
	if len(loc.Root) > len(physical) || !slices.Equal(loc.Root, physical[:len(loc.Root)]) {
		return nfs.ReadReplica{}, nil, errors.New("referral fs_root does not match the requested namespace")
	}
	for _, location := range loc.Locations {
		for _, server := range location.Servers {
			for _, choice := range approved {
				if choice.Server == server {
					p := append(slices.Clone(location.Root), physical[len(loc.Root):]...)
					if _, err := referralPath("/" + strings.Join(p, "/")); err != nil {
						return nfs.ReadReplica{}, nil, err
					}
					return choice.Target, p, nil
				}
			}
		}
	}
	return nfs.ReadReplica{}, nil, errors.New("no explicitly approved fs_locations server; no DNS or fallback")
}

// resolveReferral observes the entire physical path without following symlinks.
// An absent filesystem is queried through its parent when GETFH is refused.
func resolveReferral(ctx context.Context, s *Session, relative []string) (nfs.Node, *nfs.FileLocations, error) {
	base, err := referralPath(s.Export)
	if err != nil {
		return nfs.Node{}, nil, err
	}
	check := func(loc nfs.FileLocations, reached []string, err error) (nfs.Node, *nfs.FileLocations, error) {
		if err == nil && (len(loc.Root) > len(reached) || !slices.Equal(loc.Root, reached[:len(loc.Root)])) {
			err = errors.New("referral fs_root lies outside the encountered filesystem")
		}
		return nfs.Node{}, &loc, err
	}
	n := s.Root
	a, err := s.Client.GetAttr(ctx, n.Handle)
	if errors.Is(err, nfs.Status(10019)) {
		loc, e := s.Client.Locations(ctx, n.Handle, "")
		return check(loc, base, e)
	}
	if err != nil {
		return nfs.Node{}, nil, err
	}
	n.Attr = a
	for i, part := range relative {
		if n.Attr.Type != 2 {
			return nfs.Node{}, nil, errors.New("referral path component is not a directory")
		}
		parent := n
		n, err = s.Client.Lookup(ctx, parent.Handle, part)
		if errors.Is(err, nfs.Status(10019)) {
			loc, e := s.Client.Locations(ctx, parent.Handle, part)
			return check(loc, append(slices.Clone(base), relative[:i+1]...), e)
		}
		if err != nil {
			return nfs.Node{}, nil, err
		}
		if n.Attr.Type == 5 {
			return nfs.Node{}, nil, errors.New("referral profile refuses symbolic links")
		}
	}
	return n, nil, nil
}

// GetResumeReferrals follows up to eight protected, approved MOVED namespace
// transitions. All state on a new server is fresh; held locks forbid this mode.
// Stable IDs/metadata and complete retained-prefix comparison gate migration
// after a source has been observed. The interactive session remains unchanged.
func (s *Session) GetResumeReferrals(ctx context.Context, remote, local string, approved []ReferralTarget, progress TransferProgress) (int64, error) {
	if len(approved) < 1 || len(approved) > 8 || s.AutoUID || s.AutoEscape || s.Escaped || s.Export == "" {
		return 0, errors.New("referrals require 1..8 approved targets and fixed selected namespace")
	}
	approved = slices.Clone(approved)
	seen := map[string]bool{}
	for _, choice := range approved {
		if choice.Server == "" || len(choice.Server) > 1024 || strings.ContainsAny(choice.Server, " /\\\t\r\n\x00") || seen[choice.Server] {
			return 0, errors.New("invalid or duplicate advertised referral server")
		}
		seen[choice.Server] = true
		if err := s.Client.ValidateReadReplica(choice.Target); err != nil {
			return 0, err
		}
	}
	if len(s.Client.Locks()) != 0 {
		return 0, nfs.ErrLocksHeld
	}
	if s.BaseAuth.UID != s.Client.Auth.UID || s.BaseAuth.GID != s.Client.Auth.GID || !slices.Equal(s.BaseAuth.Groups, s.Client.Auth.Groups) {
		return 0, errors.New("referrals require matching base credentials")
	}
	if !strings.HasPrefix(remote, "/") {
		remote = strings.TrimSuffix(s.CWD, "/") + "/" + remote
	}
	relative, err := referralPath(remote)
	if err != nil {
		return 0, err
	}
	export, err := referralPath(s.Export)
	if err != nil {
		return 0, err
	}
	physical := append(slices.Clone(export), relative...)
	if _, err := referralPath("/" + strings.Join(physical, "/")); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	unlock, err := lockResume(local)
	if err != nil {
		return 0, err
	}
	defer unlock()
	original := captureReadSession(s)
	work := s
	var owned []*nfs.Client
	defer func() {
		for _, c := range owned {
			c.Close()
		}
	}()
	var current readSession
	expected := resumeSource{guard: func(_ []byte, _ string, _ bool) error {
		if err := original.check(s); err != nil {
			return err
		}
		return current.check(work)
	}}
	visited := map[string]bool{}
	var count int64
	for hops := 0; ; {
		if err := original.check(s); err != nil {
			return count, err
		}
		if err := ctx.Err(); err != nil {
			return count, err
		}
		n, loc, err := resolveReferral(ctx, work, relative)
		if err != nil {
			return count, err
		}
		if loc == nil {
			if n.Attr.Type != 1 {
				return count, errors.New("referrals download requires a regular file")
			}
			current = captureReadSession(work)
			path := "/" + strings.Join(relative, "/")
			// A remapped physical pathname retains the same observed source
			// identity. Metadata and every retained byte are still checked.
			if expected.set {
				expected.path = path
			}
			count, err = work.getResume(ctx, path, local, progress, &expected)
			if err == nil || !referralMovedOnly(err) {
				return count, err
			}
			if err := original.check(s); err != nil {
				return count, err
			}
			if err := current.check(work); err != nil {
				return count, err
			}
			_, loc, err = resolveReferral(ctx, work, relative)
			if err != nil {
				return count, err
			}
			if loc == nil {
				return count, errors.New("MOVED disappeared before namespace discovery; no replay")
			}
		}
		if hops == 8 {
			return count, errors.New("referral transition budget exhausted")
		}
		target, nextPath, err := referralDestination(*loc, physical, approved)
		if err != nil {
			return count, err
		}
		key := target.Address + "|/" + strings.Join(nextPath, "/")
		if visited[key] {
			return count, errors.New("referral namespace cycle; no reconnect")
		}
		visited[key] = true
		fmt.Fprintf(s.Notice, "Namespace referral %d/8 to %s\n", hops+1, target.Address)
		if err := original.check(s); err != nil {
			return count, err
		}
		fresh, err := s.Client.ConnectReadReplica(ctx, target)
		if err != nil {
			return count, err
		}
		owned = append(owned, fresh)
		root, err := fresh.Mount(ctx, "/")
		if err != nil {
			return count, err
		}
		host, _, _ := net.SplitHostPort(target.Address)
		work = New(fresh, host, false, false, s.Notice)
		work.Root, work.ExportRoot, work.Export = root, cloneRoot(root), "/"
		physical, relative = nextPath, slices.Clone(nextPath)
		hops++
	}
}
