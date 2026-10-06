package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"nfsclient/internal/nfs"
)

// Cache each existing directory once. A merge must not create names that
// collide when the resulting tree is later copied to a case-insensitive OS.
type treeMergeNames struct {
	dirs  map[string]map[string]string
	total int
}

func (m *treeMergeNames) check(key, name string, list func() ([]string, error)) error {
	if m.dirs == nil {
		m.dirs = make(map[string]map[string]string)
	}
	names, ok := m.dirs[key]
	if !ok {
		entries, err := list()
		if err != nil {
			return err
		}
		if len(entries) > treeEntryLimit-m.total {
			return fmt.Errorf("merge inventory exceeds %d entries", treeEntryLimit)
		}
		names = make(map[string]string, len(entries))
		for _, entry := range entries {
			fold := strings.ToLower(entry)
			if old, exists := names[fold]; exists && old != entry {
				return fmt.Errorf("existing merge directory contains colliding names %q and %q", old, entry)
			}
			names[fold] = entry
		}
		m.total += len(entries)
		m.dirs[key] = names
	}
	if old, ok := names[strings.ToLower(name)]; ok && old != name {
		return fmt.Errorf("merge name %q collides with existing %q", name, old)
	}
	return nil
}

func (m *treeMergeNames) local(root *os.Root, name string) error {
	parent := path.Dir(name)
	return m.check(parent, path.Base(name), func() ([]string, error) {
		dir, err := root.Open(parent)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		entries, err := dir.Readdirnames(treeEntryLimit + 1)
		if len(entries) > treeEntryLimit {
			return nil, fmt.Errorf("merge directory exceeds %d entries", treeEntryLimit)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return entries, nil
	})
}

func (m *treeMergeNames) remote(ctx context.Context, c *nfs.Client, parent nfs.Node, name string) error {
	return m.check(string(parent.Handle), name, func() ([]string, error) {
		entries, err := c.ReadDir(ctx, parent.Handle)
		if err != nil {
			return nil, err
		}
		if len(entries) > treeEntryLimit {
			return nil, fmt.Errorf("merge directory exceeds %d entries", treeEntryLimit)
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name)
		}
		return names, nil
	})
}
