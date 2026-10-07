package nfs

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

func discoveryFailure(e *DiscoveredExport, err error) {
	e.Access, e.Error = DiscoveryErrorStatus(err), err.Error()
	e.SecurityBoundary = e.Access == "wrong_security"
	e.Referral = e.Access == "referral"
	if e.SecurityBoundary || e.Referral || e.Access == "entry_limit" || e.Access == "timeout" || e.Access == "cancelled" {
		e.Traversal = e.Access
	}
	var security *WrongSecurityError
	if errors.As(err, &security) {
		e.AdvertisedSecurity = append([]string(nil), security.Advertised...)
	}
}

func (r *DiscoveryReport) index(p string) int {
	if r.pathIndex == nil {
		r.pathIndex = make(map[string]int, len(r.Entries))
		for i := range r.Entries {
			r.pathIndex[r.Entries[i].Path] = i
		}
	}
	if i, ok := r.pathIndex[p]; ok {
		return i
	}
	return -1
}

// Keep the first observation and merge evidence about how a path was found.
func (r *DiscoveryReport) add(e DiscoveredExport) int {
	if i := r.index(e.Path); i >= 0 {
		old := &r.Entries[i]
		if !slices.Contains(old.Sources, e.Source) {
			old.Sources = append(old.Sources, e.Source)
		}
		old.FilesystemBoundary = old.FilesystemBoundary || e.FilesystemBoundary
		old.Namespace = old.Namespace || e.Namespace
		for _, client := range e.Clients {
			if !slices.Contains(old.Clients, client) {
				old.Clients = append(old.Clients, client)
			}
		}
		return i
	}
	e.Sources = []string{e.Source}
	r.Entries = append(r.Entries, e)
	r.pathIndex[e.Path] = len(r.Entries) - 1
	return len(r.Entries) - 1
}

func takeDiscoveryBudget(ctx context.Context, remaining *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if *remaining <= 0 {
		return errDiscoveryLimit
	}
	*remaining--
	return nil
}

// Resolve explicit components using LOOKUP only: never READDIR, READLINK or a
// referral destination. Each component consumes the same budget as a listed entry.
func (c *Client) discoveryLookupPath(ctx context.Context, n Node, suffix string, remaining *int) (Node, bool, error) {
	boundary := false
	for _, part := range strings.Split(strings.Trim(suffix, "/"), "/") {
		if part == "" || part == "." {
			continue
		}
		if n.Attr.Type == 5 {
			return n, boundary, errors.New("discovery does not follow symlinks")
		}
		if err := takeDiscoveryBudget(ctx, remaining); err != nil {
			return n, boundary, err
		}
		child, err := c.Lookup(ctx, n.Handle, part)
		if err != nil {
			return Node{}, boundary, err
		}
		a, b := n.Attr, child.Attr
		boundary = boundary || a.HasFSID && b.HasFSID && (a.FSID != b.FSID || a.FSIDMinor != b.FSIDMinor)
		n = child
	}
	return n, boundary, nil
}

func (c *Client) discoverKnownV4(ctx context.Context, root Node, paths []string, r *DiscoveryReport, remaining *int) {
	for _, supplied := range paths {
		p := path.Clean(supplied)
		if i := r.index(p); i >= 0 {
			r.add(DiscoveredExport{Export: Export{Path: p}, Source: "known_path"})
			continue
		}
		if *remaining <= 0 || ctx.Err() != nil {
			err := ctx.Err()
			if err == nil {
				err = errDiscoveryLimit
			}
			r.issue(p, err)
			continue
		}
		e := DiscoveredExport{Export: Export{Path: p}, Source: "known_path", Access: "unknown"}
		n, boundary, err := c.discoveryLookupPath(ctx, root, p, remaining)
		e.FilesystemBoundary = boundary
		if err != nil {
			discoveryFailure(&e, err)
			r.issue(p, err)
		} else {
			c.discoveryAccess(ctx, n, &e)
			if n.Attr.Type == 5 {
				e.Traversal = "symlink_not_followed"
			}
			if e.Error != "" {
				r.issue(p, errors.New(e.Error))
			}
		}
		r.add(e)
	}
}

func (c *Client) discoverLegacy(ctx context.Context, o DiscoveryOptions, r *DiscoveryReport) {
	exports, err := c.exportsLimit(ctx, o.MaxEntries)
	if err != nil {
		r.issue("MOUNT EXPORT", err)
	}
	remaining := o.MaxEntries
	advertised := make(map[string]bool, len(exports))
	for _, exp := range exports {
		advertised[path.Clean(exp.Path)] = true
	}
	nodes := map[string]Node{}
	mountErrors := map[string]error{}
	var cleanup []string
	defer func() {
		// One bounded cleanup budget, independent of an expired discovery context.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, p := range cleanup {
			if err := c.Unmount(ctx, p); err != nil {
				r.issue(p, fmt.Errorf("MOUNT cleanup: %w", err))
			}
		}
	}()
	mount := func(p string) (Node, error) {
		if n, ok := nodes[p]; ok {
			return n, nil
		}
		if err, ok := mountErrors[p]; ok {
			if limitErr := takeDiscoveryBudget(ctx, &remaining); limitErr != nil {
				return Node{}, limitErr
			}
			return Node{}, err
		}
		if err := takeDiscoveryBudget(ctx, &remaining); err != nil {
			return Node{}, err
		}
		alreadyMounted := c.mounted[p]
		n, err := c.Mount(ctx, p)
		if !alreadyMounted && c.mounted[p] {
			cleanup = append(cleanup, p)
		}
		if err != nil {
			mountErrors[p] = err
		} else {
			nodes[p] = n
		}
		return n, err
	}
	for _, supplied := range o.Paths {
		p := path.Clean(supplied)
		if r.index(p) >= 0 {
			continue
		}
		if remaining <= 0 || ctx.Err() != nil {
			err := ctx.Err()
			if err == nil {
				err = errDiscoveryLimit
			}
			r.issue(p, err)
			continue
		}
		e := DiscoveredExport{Export: Export{Path: p}, Source: "known_path", Access: "unknown"}
		root := ""
		for candidate := p; ; candidate = path.Dir(candidate) {
			if advertised[candidate] {
				root = candidate
				break
			}
			if candidate == "/" {
				break
			}
		}
		direct := root == ""
		if direct {
			root = p
		}
		n, err := mount(root)
		if err == nil {
			n, e.FilesystemBoundary, err = c.discoveryLookupPath(ctx, n, strings.TrimPrefix(p, root), &remaining)
		}
		if err != nil {
			discoveryFailure(&e, err)
			if direct {
				e.Error += "; no advertised ancestor export: direct MOUNT failed; cannot infer a hidden mount root for this path"
			}
			r.issue(p, errors.New(e.Error))
		} else {
			c.discoveryAccess(ctx, n, &e)
			if n.Attr.Type == 5 {
				e.Traversal = "symlink_not_followed"
			}
			if e.Error != "" {
				r.issue(p, errors.New(e.Error))
			}
		}
		r.add(e)
	}
	for _, exp := range exports {
		exp.Path = path.Clean(exp.Path)
		if r.index(exp.Path) >= 0 {
			r.add(DiscoveredExport{Export: exp, Source: "mountd"})
			continue
		}
		if remaining <= 0 || ctx.Err() != nil {
			err := ctx.Err()
			if err == nil {
				err = errDiscoveryLimit
			}
			r.issue(exp.Path, err)
			break
		}
		e := DiscoveredExport{Export: exp, Source: "mountd", Access: "unknown"}
		n, err := mount(exp.Path)
		if err != nil {
			discoveryFailure(&e, err)
			r.issue(exp.Path, err)
		} else {
			c.discoveryAccess(ctx, n, &e)
			if e.Error != "" {
				r.issue(exp.Path, errors.New(e.Error))
			}
		}
		r.add(e)
	}
}
