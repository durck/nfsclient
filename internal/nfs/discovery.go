package nfs

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// DiscoveryOptions bounds read-only discovery under the current identity.
// MaxDepth applies to the NFSv4 namespace; legacy discovery checks MOUNT exports.
type DiscoveryOptions struct {
	MaxDepth   int
	MaxEntries int
	Timeout    time.Duration
	Paths      []string // Explicit absolute server paths; independent of READDIR depth.
}

func DefaultDiscoveryOptions() DiscoveryOptions {
	return DiscoveryOptions{MaxDepth: 1, MaxEntries: 1000, Timeout: 10 * time.Second}
}

func (o DiscoveryOptions) Validate() error {
	if o.MaxDepth < 1 || o.MaxDepth > 64 || o.MaxEntries < 1 || o.MaxEntries > 100000 || o.Timeout <= 0 {
		return errors.New("discovery requires depth 1..64, max-entries 1..100000 and a positive timeout")
	}
	if len(o.Paths) > o.MaxEntries {
		return errors.New("known paths exceed discovery max-entries")
	}
	for _, p := range o.Paths {
		if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || len(p) > 4096 {
			return errors.New("known discovery paths must be absolute, NUL-free and at most 4096 bytes")
		}
		parts := strings.Split(strings.Trim(p, "/"), "/")
		if len(parts) > 64 {
			return errors.New("known discovery paths cannot exceed 64 components")
		}
		for _, part := range parts {
			if part == ".." {
				return errors.New("known discovery paths cannot contain parent components (..)")
			}
		}
	}
	return nil
}

type DiscoveredExport struct {
	Export
	Source             string   `json:"source"`
	Sources            []string `json:"sources"`
	Access             string   `json:"access"`
	CanList            *bool    `json:"can_list,omitempty"`
	CanTraverse        *bool    `json:"can_traverse,omitempty"`
	FilesystemBoundary bool     `json:"filesystem_boundary,omitempty"`
	SecurityBoundary   bool     `json:"security_boundary,omitempty"`
	AdvertisedSecurity []string `json:"advertised_security,omitempty"`
	Referral           bool     `json:"referral,omitempty"`
	Traversal          string   `json:"traversal,omitempty"`
	// Listing evidence is distinct from ACCESS permission bits. Nil means no
	// READDIR was attempted; a zero count proves emptiness only at EOF.
	ListedEntries   *int   `json:"listed_entries,omitempty"`
	ListingComplete *bool  `json:"listing_complete,omitempty"`
	Error           string `json:"error,omitempty"`
}

type DiscoveryReport struct {
	pathIndex map[string]int
	Version   string             `json:"nfs_version"`
	Identity  string             `json:"identity"`
	Entries   []DiscoveredExport `json:"entries"`
	// Complete refers only to the discoverable namespace under this identity,
	// never to the server's configuration or paths hidden from READDIR.
	Complete bool     `json:"complete"`
	Issues   []string `json:"issues,omitempty"`
}

func DiscoveryErrorStatus(err error) string {
	if errors.Is(err, errDiscoveryLimit) {
		return "entry_limit"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var s Status
	if errors.As(err, &s) {
		switch s {
		case 1, 13:
			return "denied"
		case 2:
			return "not_found"
		case 10016:
			return "wrong_security"
		case 10019:
			return "referral"
		}
	}
	return "error"
}

var errDiscoveryLimit = errors.New("discovery entry limit reached")

func (r *DiscoveryReport) issue(p string, err error) {
	r.Complete = false
	r.Issues = append(r.Issues, fmt.Sprintf("%s: %v", p, err))
}

func (c *Client) discoveryAccess(ctx context.Context, n Node, e *DiscoveredExport) {
	e.Access = "unknown"
	e.Error = ""
	e.CanList, e.CanTraverse = nil, nil
	e.SecurityBoundary, e.Referral = false, false
	e.AdvertisedSecurity = nil
	if e.Traversal == "wrong_security" || e.Traversal == "referral" {
		e.Traversal = ""
	}
	requested := uint32(1)
	if n.Attr.Type == 2 {
		requested |= 2
	}
	// NFSv4 READ may be authorized by EXECUTE for a regular file (RFC 8881
	// section 18.22.3); READ alone cannot establish a denial.
	if c.v4 != nil && n.Attr.Type == 1 {
		requested |= 32
	}
	a, err := c.CheckAccess(ctx, n.Handle, requested)
	if err != nil {
		discoveryFailure(e, err)
		return
	}
	if !a.Available {
		return
	}
	supported, allowed := a.Supported, a.Allowed
	if n.Attr.Type == 2 && supported&1 != 0 {
		b := allowed&1 != 0
		e.CanList = &b
	}
	if n.Attr.Type == 2 && supported&2 != 0 {
		b := allowed&2 != 0
		e.CanTraverse = &b
	}
	if allowed&requested != 0 {
		e.Access = "accessible"
	} else if supported&requested == requested {
		e.Access = "denied"
	}
}

// Discover does not switch UID/GID, security flavor, the session root or CWD.
// Operational failures are retained in the partial report; invalid options are
// returned as errors before issuing any RPC. No files are created or modified.
func (c *Client) Discover(parent context.Context, o DiscoveryOptions) (DiscoveryReport, error) {
	r := DiscoveryReport{Version: c.Version(), Identity: c.Identity(), Entries: []DiscoveredExport{}, Complete: true}
	if err := o.Validate(); err != nil {
		return r, err
	}
	ctx, cancel := context.WithTimeout(parent, o.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		r.issue("/", err)
		return r, nil
	}
	if c.v4 == nil {
		c.discoverLegacy(ctx, o, &r)
		return r, nil
	}

	root, err := c.Mount(ctx, "/")
	r.add(DiscoveredExport{Export: Export{Path: "/", Namespace: true}, Source: "namespace", Access: "unknown"})
	if err != nil {
		discoveryFailure(&r.Entries[0], err)
		r.issue("/", err)
		if len(root.Handle) == 0 {
			for _, supplied := range o.Paths {
				p := path.Clean(supplied)
				if r.index(p) >= 0 {
					r.add(DiscoveredExport{Export: Export{Path: p}, Source: "known_path"})
					continue
				}
				if len(r.Entries) >= o.MaxEntries {
					r.issue(p, errDiscoveryLimit)
					continue
				}
				e := DiscoveredExport{Export: Export{Path: p}, Source: "known_path"}
				discoveryFailure(&e, fmt.Errorf("server root unavailable: %w", err))
				r.add(e)
			}
			return r, nil
		}
		remaining := o.MaxEntries - 1
		c.discoverKnownV4(ctx, root, o.Paths, &r, &remaining)
		return r, nil
	}
	remaining := o.MaxEntries - 1
	c.discoverKnownV4(ctx, root, o.Paths, &r, &remaining)
	type pending struct {
		node         Node
		index, depth int
	}
	queue := []pending{{root, 0, 0}}
	seen := map[string]bool{}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		e := &r.Entries[item.index]
		if err := ctx.Err(); err != nil {
			r.issue(e.Path, err)
			break
		}
		c.discoveryAccess(ctx, item.node, e)
		if e.Error != "" {
			r.issue(e.Path, errors.New(e.Error))
		}
		key := string(item.node.Handle)
		if a := item.node.Attr; a.HasFSID && a.HasFileID {
			key = fmt.Sprintf("id:%d:%d:%d", a.FSID, a.FSIDMinor, a.FileID)
		} else {
			key = "fh:" + key
		}
		if seen[key] {
			e.Traversal = "already_visited"
			continue
		}
		seen[key] = true
		if item.depth >= o.MaxDepth {
			e.Traversal = "depth_limit"
			r.issue(e.Path, errors.New("discovery depth limit reached"))
			continue
		}
		if remaining == 0 {
			e.Traversal = "entry_limit"
			r.issue(e.Path, errDiscoveryLimit)
			break
		}
		children, used, err := c.v4.discoveryChildren(ctx, item.node.Handle, remaining)
		remaining -= used
		complete := err == nil
		e.ListedEntries, e.ListingComplete = &used, &complete
		parentPath := e.Path
		if err != nil {
			e.Traversal = DiscoveryErrorStatus(err)
			r.issue(parentPath, err)
		} else {
			e.Traversal = "listed"
		}
		for _, child := range children {
			if child.Err == nil && child.Attr.Type != 2 {
				if index := r.index(path.Join(parentPath, child.Name)); index >= 0 {
					r.add(DiscoveredExport{Export: Export{Path: r.Entries[index].Path}, Source: "namespace"})
				}
				continue
			}
			e := DiscoveredExport{Export: Export{Path: path.Join(parentPath, child.Name)}, Source: "namespace", Access: "unknown"}
			if child.Err != nil {
				discoveryFailure(&e, child.Err)
				r.issue(e.Path, child.Err)
			} else {
				a, b := item.node.Attr, child.Attr
				e.FilesystemBoundary = a.HasFSID && b.HasFSID && (a.FSID != b.FSID || a.FSIDMinor != b.FSIDMinor)
				index := r.add(e)
				queue = append(queue, pending{child.Node, index, item.depth + 1})
				continue
			}
			r.add(e)
		}
	}
	return r, nil
}

func validDiscoveryName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}
