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
}

func DefaultDiscoveryOptions() DiscoveryOptions {
	return DiscoveryOptions{MaxDepth: 1, MaxEntries: 1000, Timeout: 10 * time.Second}
}

func (o DiscoveryOptions) Validate() error {
	if o.MaxDepth < 1 || o.MaxDepth > 64 || o.MaxEntries < 1 || o.MaxEntries > 100000 || o.Timeout <= 0 {
		return errors.New("discovery requires depth 1..64, max-entries 1..100000 and a positive timeout")
	}
	return nil
}

type DiscoveredExport struct {
	Export
	Source             string `json:"source"`
	Access             string `json:"access"`
	CanList            *bool  `json:"can_list,omitempty"`
	CanTraverse        *bool  `json:"can_traverse,omitempty"`
	FilesystemBoundary bool   `json:"filesystem_boundary,omitempty"`
	Traversal          string `json:"traversal,omitempty"`
	Error              string `json:"error,omitempty"`
}

type DiscoveryReport struct {
	Version  string             `json:"nfs_version"`
	Identity string             `json:"identity"`
	Entries  []DiscoveredExport `json:"entries"`
	// Complete refers only to the discoverable namespace under this identity,
	// never to the server's configuration or paths hidden from READDIR.
	Complete bool     `json:"complete"`
	Issues   []string `json:"issues,omitempty"`
}

func DiscoveryErrorStatus(err error) string {
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
	if c.Version() == "2" {
		return
	} // NFSv2 has no ACCESS operation.
	var supported, allowed uint32
	var err error
	if c.v4 != nil {
		var req encoder
		req.u32(3) // READ (directory listing) and LOOKUP (directory traversal).
		err = c.v4.compound(ctx, fh4(n.Handle), op4(3, req, func(d *decoder) {
			supported, allowed = d.u32(), d.u32()
			if supported & ^uint32(3) != 0 || allowed & ^supported != 0 {
				d.err = errors.New("invalid discovery ACCESS mask")
			}
		}))
	} else {
		supported = 3
		allowed, err = c.Access(ctx, n.Handle)
	}
	if err != nil {
		e.Access, e.Error = DiscoveryErrorStatus(err), err.Error()
		return
	}
	if supported&1 != 0 {
		b := allowed&1 != 0
		e.CanList = &b
	}
	if supported&2 != 0 {
		b := allowed&2 != 0
		e.CanTraverse = &b
	}
	if allowed&3 != 0 {
		e.Access = "accessible"
	} else if supported&3 == 3 {
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
		exports, err := c.exportsLimit(ctx, o.MaxEntries)
		if err != nil {
			r.issue("MOUNT EXPORT", err)
		}
		for _, exp := range exports {
			e := DiscoveredExport{Export: exp, Source: "mountd", Access: "unknown"}
			if err := ctx.Err(); err != nil {
				r.issue(exp.Path, err)
				break
			}
			alreadyMounted := c.mounted[exp.Path]
			n, err := c.Mount(ctx, exp.Path)
			if err != nil {
				e.Access, e.Error = DiscoveryErrorStatus(err), err.Error()
				r.issue(exp.Path, err)
			} else {
				c.discoveryAccess(ctx, n, &e)
				if e.Error != "" {
					r.issue(exp.Path, errors.New(e.Error))
				}
			}
			if !alreadyMounted && c.mounted[exp.Path] {
				// Discovery may have exhausted its budget on the NFS connection;
				// the separate MOUNT connection still needs bounded cleanup.
				cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
				if err := c.Unmount(cleanup, exp.Path); err != nil {
					r.issue(exp.Path, fmt.Errorf("MOUNT cleanup: %w", err))
				}
				stop()
			}
			r.Entries = append(r.Entries, e)
		}
		return r, nil
	}

	root, err := c.Mount(ctx, "/")
	r.Entries = append(r.Entries, DiscoveredExport{Export: Export{Path: "/", Namespace: true}, Source: "namespace", Access: "unknown"})
	if err != nil {
		r.Entries[0].Access, r.Entries[0].Error = DiscoveryErrorStatus(err), err.Error()
		r.issue("/", err)
		return r, nil
	}
	type pending struct {
		node         Node
		index, depth int
	}
	queue := []pending{{root, 0, 0}}
	seen := map[string]bool{}
	remaining := o.MaxEntries - 1
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
		parentPath := e.Path
		if err != nil {
			e.Traversal = "partial"
			r.issue(parentPath, err)
		} else {
			e.Traversal = "listed"
		}
		for _, child := range children {
			if child.Err == nil && child.Attr.Type != 2 {
				continue
			}
			e := DiscoveredExport{Export: Export{Path: path.Join(parentPath, child.Name)}, Source: "namespace", Access: "unknown"}
			if child.Err != nil {
				e.Access, e.Error = DiscoveryErrorStatus(child.Err), child.Err.Error()
				r.issue(e.Path, child.Err)
			} else {
				a, b := item.node.Attr, child.Attr
				e.FilesystemBoundary = a.HasFSID && b.HasFSID && (a.FSID != b.FSID || a.FSIDMinor != b.FSIDMinor)
				queue = append(queue, pending{child.Node, len(r.Entries), item.depth + 1})
			}
			r.Entries = append(r.Entries, e)
		}
	}
	return r, nil
}

func validDiscoveryName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}
