package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nfs-viewer/internal/nfs"
)

func localEntry(info os.FileInfo) nfs.Entry {
	kind := uint32(1)
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		kind = 5
	case info.IsDir():
		kind = 2
	case !info.Mode().IsRegular():
		kind = 0
	}
	return nfs.Entry{Name: info.Name(), Node: nfs.Node{Attr: nfs.Attr{Type: kind, Mode: uint32(info.Mode().Perm()), Size: uint64(max(info.Size(), 0)), MTime: info.ModTime()}}}
}

// Local metadata comes from the OS, without opening file contents or changing
// the process working directory. Owner IDs are omitted for Windows portability.
func (s *Shell) listLocal(p string) error {
	full := s.local(p)
	info, err := os.Lstat(full)
	if strings.HasSuffix(p, "/") || strings.HasSuffix(p, string(filepath.Separator)) {
		info, err = os.Stat(full)
	}
	if err != nil {
		return err
	}
	parent := filepath.Dir(full)
	entries := []os.FileInfo{info}
	if info.IsDir() {
		parent = full
		children, err := os.ReadDir(full)
		if err != nil {
			return err
		}
		entries = nil
		for _, child := range children {
			entry, err := child.Info()
			if err != nil {
				return fmt.Errorf("local entry %q: %w", child.Name(), err)
			}
			entries = append(entries, entry)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	rows := [][]cell{{{"NAME", bold}, {"SIZE", bold}, {"PERMISSIONS", muted}, {"MODIFIED", bold}}}
	now, dirs := time.Now(), 0
	for _, info := range entries {
		e := localEntry(info)
		name, size, tone := label(info.Name()), humanSize(e.Attr.Size), fileTone(e)
		meta, date := muted, dateTone(info.ModTime(), now)
		if info.IsDir() {
			name += "/"
			size = "-"
			dirs++
		}
		if info.Mode()&os.ModeSymlink != 0 {
			name += "@"
			link := filepath.Join(parent, info.Name())
			target, readErr := os.Readlink(link)
			if readErr == nil {
				name += " -> " + label(target)
				_, readErr = os.Stat(link)
			}
			if readErr != nil {
				state := "unverified"
				if os.IsNotExist(readErr) {
					state = "missing"
				} else if os.IsPermission(readErr) {
					state = "access denied"
				}
				name += " [" + state + "]"
				tone, meta, date = faint, faint, faint
			}
		}
		rows = append(rows, []cell{{name, tone}, {size, meta}, {info.Mode().String(), meta}, {info.ModTime().Local().Format("2006-01-02 15:04"), date}})
	}
	fmt.Fprintln(s.Out, "  "+paint(s.Color, muted, "LOCAL  ")+label(full))
	if err := table(s.Out, rows, s.Color); err != nil {
		return err
	}
	_, err = fmt.Fprintln(s.Out, "\n  "+paint(s.Color, muted, fmt.Sprintf("%d entries · %d directories", len(entries), dirs))+"\n")
	return err
}
