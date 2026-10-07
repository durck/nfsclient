package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"nfsclient/internal/nfs"
)

const treeEntryLimit = 100000
const treeDepthLimit = 128

type TreeOptions struct {
	// Merge reuses directories, but never replaces files or follows links.
	Merge bool
	// Links copies symbolic links as links, including dangling links.
	Links     bool
	Hardlinks bool
	// SkipOffline skips only files positively reported offline by RFC 9754
	// metadata. Unknown/unavailable attributes follow ordinary download behavior.
	// Metadata errors fail the transfer. Downloads only.
	SkipOffline bool
	// Mode and MTime preserve ordinary permission bits and modification times.
	// They do not preserve ACLs, owners, atime, ctime or special mode bits.
	Mode, MTime bool
}

type treeEntry struct {
	name     string
	node     nfs.Node
	local    os.FileInfo
	link     string
	hardlink string
}

// Use a portable basename policy; never interpret a server name as a drive,
// stream, separator, device or parent traversal on the receiving system.
func portableTreeName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\:\x00<>\"|?*") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for _, r := range name {
		if r < 32 {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" {
		return false
	}
	runes := []rune(base)
	return !(len(runes) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && strings.ContainsRune("123456789¹²³", runes[3]))
}

// GetTree copies a tree into a new local directory. Preflight rejects links,
// special files, cycles, unsafe names and oversized trees before creating it.
// Failure leaves the explicitly named partial tree; existing trees are refused.
func (s *Session) GetTree(ctx context.Context, remote, local string, progress TransferProgress) (count int64, resultErr error) {
	return s.GetTreeWithOptions(ctx, remote, local, TreeOptions{}, progress)
}

func (s *Session) GetTreeWithOptions(ctx context.Context, remote, local string, options TreeOptions, progress TransferProgress) (count int64, resultErr error) {
	if err := options.validate(); err != nil {
		return 0, err
	}
	root, resolvedRoot, err := s.Resolve(ctx, remote, false)
	if err != nil {
		return 0, err
	}
	if root.Attr.Type != 2 {
		return 0, errors.New("recursive source must be a directory, not a link")
	}
	entries := []treeEntry{}
	hardlinks := map[string]string{}
	seen := map[string]bool{}
	var scan func(nfs.Node, string, int) error
	scan = func(dir nfs.Node, prefix string, depth int) error {
		if depth > treeDepthLimit {
			return errors.New("recursive directory depth limit exceeded")
		}
		if seen[string(dir.Handle)] {
			return errors.New("recursive directory cycle or alias")
		}
		seen[string(dir.Handle)] = true
		if err := ctx.Err(); err != nil {
			return err
		}
		s.identity(dir)
		children, err := s.Client.ReadDir(ctx, dir.Handle)
		if err != nil {
			return err
		}
		names := map[string]bool{}
		for _, child := range children {
			if child.Name == "." || child.Name == ".." {
				continue
			}
			key := strings.ToLower(child.Name)
			if !portableTreeName(child.Name) || names[key] {
				return fmt.Errorf("unsafe or colliding recursive name %q", child.Name)
			}
			names[key] = true
			// READDIR may omit attributes/handles. Bind every entry via LOOKUP.
			// A nested scan may have selected a different owner for AUTH_SYS.
			s.identity(dir)
			n, err := s.Client.Lookup(ctx, dir.Handle, child.Name)
			if err != nil {
				return err
			}
			if n.Attr.Type != 1 && n.Attr.Type != 2 && !(options.Links && n.Attr.Type == 5) {
				return fmt.Errorf("recursive transfer refuses links and special files: %q", child.Name)
			}
			if len(entries) >= treeEntryLimit {
				return errors.New("recursive entry limit exceeded")
			}
			name := path.Join(prefix, child.Name)
			entry := treeEntry{name: name, node: n}
			if options.Hardlinks && n.Attr.Type == 1 {
				if !n.Attr.HasFSID || !n.Attr.HasFileID {
					return errors.New("hardlink preservation requires server filesystem/file IDs")
				}
				key := fmt.Sprintf("%d:%d:%d", n.Attr.FSID, n.Attr.FSIDMinor, n.Attr.FileID)
				if prior, ok := hardlinks[key]; ok {
					entry.hardlink = prior
				} else {
					hardlinks[key] = name
				}
			}
			if n.Attr.Type == 5 {
				entry.link, err = s.Client.Readlink(ctx, n.Handle)
				if err != nil {
					return err
				}
				if err := portableTreeLink(entry.link); err != nil {
					return err
				}
			}
			entries = append(entries, entry)
			if n.Attr.Type == 2 {
				if err := scan(n, name, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := scan(root, "", 0); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := os.Mkdir(local, 0700); err != nil {
		if !options.Merge || !errors.Is(err, os.ErrExist) {
			return 0, err
		}
		info, statErr := os.Lstat(local)
		if statErr != nil || !info.IsDir() {
			return 0, errors.New("merge destination must be a directory, not a link")
		}
	}
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("partial recursive download remains at %q: %w", local, resultErr)
		}
	}()
	dst, err := os.OpenRoot(local)
	if err != nil {
		return 0, err
	}
	defer dst.Close()
	mergeNames := treeMergeNames{}
	localFiles := map[string]os.FileInfo{}
	materializedHardlinks := map[string]string{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if options.Merge {
			if err := mergeNames.local(dst, entry.name); err != nil {
				return count, err
			}
		}
		if entry.node.Attr.Type == 5 {
			s.identity(entry.node)
			target, err := s.Client.Readlink(ctx, entry.node.Handle)
			if err != nil {
				return count, err
			}
			if target != entry.link {
				return count, errors.New("recursive symbolic link changed")
			}
			if err := dst.Symlink(target, entry.name); err != nil {
				return count, err
			}
			continue
		}
		if entry.node.Attr.Type == 2 {
			if err := dst.Mkdir(entry.name, 0700); err != nil {
				if !options.Merge || !errors.Is(err, os.ErrExist) {
					return count, err
				}
				info, statErr := dst.Lstat(entry.name)
				if statErr != nil || !info.IsDir() {
					return count, errors.New("merge entry must be a directory, not a link")
				}
			}
			continue
		}
		s.identity(entry.node)
		a, err := s.Client.GetAttr(ctx, entry.node.Handle)
		if err != nil {
			return count, err
		}
		if err := downloadSourceReady(a, s.Client.Version()); err != nil {
			return count, err
		}
		if err := verifyDownloadSource(entry.node.Attr, a); err != nil {
			return count, err
		}
		if options.SkipOffline {
			state, err := s.Client.OfflineMetadata(ctx, entry.node.Handle)
			if err != nil {
				return count, fmt.Errorf("offline metadata %q: %w", path.Join(resolvedRoot, entry.name), err)
			}
			if state == nfs.OfflineOffline {
				if s.Notice != nil {
					if _, err := fmt.Fprintf(s.Notice, "Skipped offline file: %q\n", path.Join(resolvedRoot, entry.name)); err != nil {
						return count, err
					}
				}
				continue
			}
		}
		// A preflight hardlink source may have been skipped. Only alias a
		// successfully materialized file; otherwise download this online name.
		linkKey := fmt.Sprintf("%d:%d:%d", a.FSID, a.FSIDMinor, a.FileID)
		if options.Hardlinks {
			entry.hardlink = materializedHardlinks[linkKey]
		}
		if entry.hardlink != "" {
			prior, err := dst.Lstat(entry.hardlink)
			if err != nil {
				return count, err
			}
			expected := localFiles[entry.hardlink]
			if expected == nil || !prior.Mode().IsRegular() || !os.SameFile(prior, expected) || prior.Size() != expected.Size() || !prior.ModTime().Equal(expected.ModTime()) {
				return count, errors.New("copied hardlink source changed")
			}
			if err := dst.Link(entry.hardlink, entry.name); err != nil {
				return count, err
			}
			continue
		}
		f, err := dst.OpenFile(entry.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return count, err
		}
		n, readErr := s.Client.ReadToProgress(ctx, entry.node.Handle, &downloadWriter{w: f, remaining: a.Size}, func(done uint64) {
			if progress != nil {
				progress(done, a.Size)
			}
		})
		count += n
		err = errors.Join(readErr, f.Sync(), f.Close())
		if err != nil {
			return count, err
		}
		if uint64(n) != a.Size {
			return count, ErrDownloadSourceChanged
		}
		after, err := s.Client.GetAttr(ctx, entry.node.Handle)
		if err != nil {
			return count, err
		}
		if err := verifyDownloadSource(a, after); err != nil {
			return count, err
		}
		if err := options.localMetadata(dst, entry.name, a); err != nil {
			return count, err
		}
		if options.Hardlinks {
			localFiles[entry.name], err = dst.Lstat(entry.name)
			if err != nil {
				return count, err
			}
			materializedHardlinks[linkKey] = entry.name
		}
	}
	// Apply directory metadata bottom-up after all child creation. Permissions
	// may remove traversal rights, so changing them during the walk is unsafe.
	for i := len(entries) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if entries[i].node.Attr.Type == 2 {
			if err := options.localMetadata(dst, entries[i].name, entries[i].node.Attr); err != nil {
				return count, err
			}
		}
	}
	if err := options.localMetadata(dst, ".", root.Attr); err != nil {
		return count, err
	}
	return count, nil
}

// PutTree uploads regular files and directories to a new remote directory.
// It does not preserve ACLs/owners, follow links, overwrite or replay mutations.
func (s *Session) PutTree(ctx context.Context, local, remote string, progress TransferProgress) (count int64, resultErr error) {
	return s.PutTreeWithOptions(ctx, local, remote, TreeOptions{}, progress)
}

func (s *Session) PutTreeWithOptions(ctx context.Context, local, remote string, options TreeOptions, progress TransferProgress) (count int64, resultErr error) {
	if options.SkipOffline {
		return 0, errors.New("--skip-offline is supported only by gettree")
	}
	if err := options.validate(); err != nil {
		return 0, err
	}
	if s.Client.Version() == "2" {
		return 0, errors.New("recursive uploads require NFSv3 or NFSv4 guarded creation")
	}
	info, err := os.Lstat(local)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, errors.New("recursive source must be a directory, not a link")
	}
	src, err := os.OpenRoot(local)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	entries := []treeEntry{}
	hardlinks := map[string]string{}
	var scan func(string, int) error
	scan = func(prefix string, depth int) error {
		if depth > treeDepthLimit {
			return errors.New("recursive directory depth limit exceeded")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		dir, err := src.Open(prefix)
		if err != nil {
			return err
		}
		children, err := dir.ReadDir(treeEntryLimit + 1)
		closeErr := dir.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		names := map[string]bool{}
		for _, child := range children {
			key := strings.ToLower(child.Name())
			if !portableTreeName(child.Name()) || names[key] {
				return fmt.Errorf("unsafe or colliding recursive name %q", child.Name())
			}
			names[key] = true
			name := path.Join(prefix, child.Name())
			a, err := src.Lstat(name)
			if err != nil {
				return err
			}
			if !a.IsDir() && !a.Mode().IsRegular() && !(options.Links && a.Mode()&os.ModeSymlink != 0) {
				return fmt.Errorf("recursive transfer refuses links and special files: %q", name)
			}
			if len(entries) >= treeEntryLimit {
				return errors.New("recursive entry limit exceeded")
			}
			entry := treeEntry{name: name, local: a}
			if options.Hardlinks && a.Mode().IsRegular() {
				f, err := src.Open(name)
				if err != nil {
					return err
				}
				opened, statErr := f.Stat()
				key, idErr := treeFileID(f)
				closeErr := f.Close()
				if err := errors.Join(statErr, idErr, closeErr); err != nil {
					return err
				}
				if !os.SameFile(a, opened) {
					return errors.New("hardlink source changed during preflight")
				}
				if prior, ok := hardlinks[key]; ok {
					entry.hardlink = prior
				} else {
					hardlinks[key] = name
				}
			}
			if a.Mode()&os.ModeSymlink != 0 {
				entry.link, err = src.Readlink(name)
				if err != nil {
					return err
				}
				if err := portableTreeLink(entry.link); err != nil {
					return err
				}
			}
			entries = append(entries, entry)
			if a.IsDir() {
				if err := scan(name, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := scan(".", 0); err != nil {
		return 0, err
	}
	p, name, err := splitDestination(remote)
	if err != nil {
		return 0, err
	}
	parent, _, err := s.Resolve(ctx, p, true)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	root, err := s.treeDirectory(ctx, parent, name, options.Merge)
	if err != nil {
		return 0, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = fmt.Errorf("partial recursive upload may remain at %q; inspect before retrying: %w", remote, resultErr)
		}
	}()
	dirs := map[string]nfs.Node{".": root}
	mergeNames := treeMergeNames{}
	remoteFiles := map[string]nfs.Node{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		current, err := src.Lstat(entry.name)
		if err != nil {
			return count, err
		}
		if !os.SameFile(entry.local, current) || current.Mode() != entry.local.Mode() {
			return count, errors.New("recursive local source changed identity or type")
		}
		parent := dirs[path.Dir(entry.name)]
		s.identity(parent)
		if options.Merge {
			if err := mergeNames.remote(ctx, s.Client, parent, path.Base(entry.name)); err != nil {
				return count, err
			}
		}
		if entry.local.Mode()&os.ModeSymlink != 0 {
			target, err := src.Readlink(entry.name)
			if err != nil {
				return count, err
			}
			if target != entry.link {
				return count, errors.New("recursive symbolic link changed")
			}
			if err := s.Client.Symlink(ctx, parent.Handle, path.Base(entry.name), target); err != nil {
				return count, err
			}
			continue
		}
		if entry.local.IsDir() {
			dir, err := s.treeDirectory(ctx, parent, path.Base(entry.name), options.Merge)
			if err != nil {
				return count, err
			}
			dirs[entry.name] = dir
			continue
		}
		if entry.hardlink != "" {
			if current.Size() != entry.local.Size() || !current.ModTime().Equal(entry.local.ModTime()) {
				return count, ErrUploadSourceChanged
			}
			prior := remoteFiles[entry.hardlink]
			priorParent := dirs[path.Dir(entry.hardlink)]
			named, err := s.Client.Lookup(ctx, priorParent.Handle, path.Base(entry.hardlink))
			if err != nil {
				return count, err
			}
			if !bytes.Equal(named.Handle, prior.Handle) || verifyDownloadSource(prior.Attr, named.Attr) != nil {
				return count, errors.New("uploaded hardlink source changed")
			}
			if err := s.Client.Link(ctx, prior.Handle, parent.Handle, path.Base(entry.name)); err != nil {
				return count, err
			}
			// LINK changes source ctime; retain the freshly acknowledged attributes.
			after, err := s.Client.GetAttr(ctx, prior.Handle)
			if err != nil {
				return count, err
			}
			before := prior.Attr
			if before.HasCTime && after.HasCTime {
				before.CTime = after.CTime
			}
			if before.HasChange && after.HasChange {
				before.Change = after.Change
			}
			if verifyDownloadSource(before, after) != nil || before.Mode != after.Mode || before.UID != after.UID || before.GID != after.GID || before.Owner != after.Owner || before.Group != after.Group {
				return count, errors.New("hardlink source content, identity or permissions changed during LINK")
			}
			prior.Attr = after
			remoteFiles[entry.hardlink] = prior
			continue
		}
		f, err := src.Open(entry.name)
		if err != nil {
			return count, err
		}
		opened, err := f.Stat()
		if err != nil || !os.SameFile(entry.local, opened) || !opened.Mode().IsRegular() || opened.Size() != entry.local.Size() || !opened.ModTime().Equal(entry.local.ModTime()) {
			f.Close()
			return count, errors.New("recursive local source changed before upload")
		}
		n, err := s.Client.Create(ctx, parent.Handle, path.Base(entry.name), 0644, false)
		if err != nil {
			f.Close()
			return count, err
		}
		s.identity(n)
		written, writeErr := s.Client.WriteFromProgress(ctx, n.Handle, io.LimitReader(f, opened.Size()), func(done uint64) {
			if progress != nil {
				progress(done, uint64(opened.Size()))
			}
		})
		count += written
		after, statErr := f.Stat()
		err = errors.Join(writeErr, statErr, f.Close())
		if err != nil {
			return count, err
		}
		if written != opened.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
			return count, errors.New("recursive local source changed during upload")
		}
		// Confirm that the newly created name still denotes our acknowledged file.
		named, err := s.Client.Lookup(ctx, parent.Handle, path.Base(entry.name))
		if err != nil {
			return count, err
		}
		if !bytes.Equal(named.Handle, n.Handle) {
			return count, errors.New("recursive destination changed identity")
		}
		if err := s.remoteTreeMetadata(ctx, n, entry.local, options); err != nil {
			return count, err
		}
		if options.Hardlinks {
			n.Attr, err = s.Client.GetAttr(ctx, n.Handle)
			if err != nil {
				return count, err
			}
			remoteFiles[entry.name] = n
		}
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if entries[i].local.IsDir() {
			if err := s.remoteTreeMetadata(ctx, dirs[entries[i].name], entries[i].local, options); err != nil {
				return count, err
			}
		}
	}
	if err := s.remoteTreeMetadata(ctx, root, info, options); err != nil {
		return count, err
	}
	return count, nil
}

// Backslashes have incompatible path semantics on Windows and Unix. Keep link
// text unchanged instead of silently translating its meaning across platforms.
func portableTreeLink(target string) error {
	if target == "" || len(target) > 4096 || strings.ContainsAny(target, "\\\x00") {
		return errors.New("symbolic link target is empty, oversized or not portable")
	}
	return nil
}

func (s *Session) treeDirectory(ctx context.Context, parent nfs.Node, name string, merge bool) (nfs.Node, error) {
	dir, err := s.Client.Create(ctx, parent.Handle, name, 0755, true)
	if err == nil || !merge || !errors.Is(err, nfs.Status(17)) {
		return dir, err
	}
	dir, err = s.Client.Lookup(ctx, parent.Handle, name)
	if err != nil {
		return nfs.Node{}, err
	}
	if dir.Attr.Type != 2 {
		return nfs.Node{}, errors.New("merge entry must be a directory, not a link")
	}
	return dir, nil
}
