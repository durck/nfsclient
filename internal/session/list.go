package session

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"nfsclient/internal/nfs"
)

func isPermDenied(err error) bool {
	var s nfs.Status
	return errors.As(err, &s) && s == 13
}

type LinkInfo struct {
	Target string
	State  string // reachable, missing, denied, loop, unavailable, unchecked
}

func (s *Session) listEntries(ctx context.Context, p string, follow bool) ([]nfs.Entry, string, error) {
	n, resolved, err := s.Resolve(ctx, p, follow)
	if err != nil {
		return nil, "", err
	}
	if n.Attr.Type != 2 {
		return []nfs.Entry{{Name: path.Base(resolved), Node: n}}, path.Dir(resolved), nil
	}
	entries, err := s.Client.ReadDir(ctx, n.Handle)
	return entries, resolved, err
}

// List inspects links within the session's root and current identity policy.
// The bounded, serial probes restore AUTH_SYS credentials and never read files.
// Transport failures return the listing collected so far plus an explicit error.
func (s *Session) List(ctx context.Context, p string, limit int) ([]nfs.Entry, map[string]LinkInfo, error) {
	entries, links, _, err := s.ListWithDirectory(ctx, p, limit)
	return entries, links, err
}

// ListWithDirectory also returns the resolved parent of the returned entries.
// It reuses the listing's resolution without additional network requests.
func (s *Session) ListWithDirectory(ctx context.Context, p string, limit int) ([]nfs.Entry, map[string]LinkInfo, string, error) {
	entries, dir, err := s.listEntries(ctx, p, false)
	if err != nil && s.AutoUIDScan && isPermDenied(err) {
		entries, dir, err = s.retryWithScan(ctx, p, false, err)
	}
	if err != nil {
		return nil, nil, "", err
	}
	links := make(map[string]LinkInfo)
	for _, e := range entries {
		if e.Attr.Type == 5 {
			links[e.Name] = LinkInfo{State: "unchecked"}
		}
	}
	previous := s.Client.Auth
	defer func() { s.Client.Auth = previous }()
	checked := 0
	for _, e := range entries {
		if e.Attr.Type != 5 || checked >= limit {
			continue
		}
		checked++
		s.Client.Auth = previous
		s.identity(e.Node)
		target, err := s.Client.Readlink(ctx, e.Handle)
		info := LinkInfo{Target: target, State: "reachable"}
		if err == nil {
			var n nfs.Node
			n, _, err = s.Resolve(ctx, path.Join(dir, e.Name), true)
			if err == nil {
				var access nfs.AccessReport
				access, err = s.Client.CheckAccess(ctx, n.Handle, 63)
				want := uint32(1) // READ for a file, LOOKUP for a directory.
				if n.Attr.Type == 2 {
					want = 2
				}
				if err == nil {
					decision := access.Decision(want)
					if n.Attr.Type == 1 {
						decision = access.ReadDecision(strings.HasPrefix(s.Client.Version(), "4"))
					}
					switch decision {
					case "denied":
						err = nfs.Status(13)
					case "unsupported", "unknown":
						info.State = "unchecked"
					}
				}
			}
		}
		if err != nil {
			var status nfs.Status
			if errors.As(err, &status) {
				switch status {
				case 2, 20:
					info.State = "missing"
				case 1, 13:
					info.State = "denied"
				default:
					info.State = "unavailable"
				}
			} else if errors.Is(err, ErrSymlinkLoop) {
				info.State = "loop"
			} else {
				info.State = "unavailable"
				links[e.Name] = info
				return entries, links, dir, fmt.Errorf("inspect link %q: %w", e.Name, err)
			}
		}
		links[e.Name] = info
	}
	return entries, links, dir, nil
}

// retryWithScan is called on permission denied when AutoUIDScan is set.
// It finds the target node (which usually doesn't require read permission),
// probes for a working UID, switches BaseAuth, and retries the listing.
func (s *Session) retryWithScan(ctx context.Context, p string, follow bool, original error) ([]nfs.Entry, string, error) {
	n, _, err := s.Resolve(ctx, p, follow)
	if err != nil {
		return nil, "", original
	}
	uid, found, err := s.findUID(ctx, n.Handle)
	if err != nil || !found {
		return nil, "", original
	}
	fmt.Fprintf(s.Notice, "Auto-scan: switching to UID %d for access.\n", uid)
	s.BaseAuth.UID = uid
	s.BaseAuth.GID = uid
	s.BaseAuth.Groups = nil
	s.Client.Auth = s.BaseAuth
	return s.listEntries(ctx, p, follow)
}
