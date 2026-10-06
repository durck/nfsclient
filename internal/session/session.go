package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nfsclient/internal/nfs"
)

type Session struct {
	Client                                    *nfs.Client
	Host, Export, CWD                         string
	Root                                      nfs.Node
	ExportRoot                                nfs.Node
	DiscoveredRoot                            *nfs.Node
	DiscoveryAttempts                         int
	RootVerification                          *RootVerification
	AutoUID, AutoEscape, Escaped, AutoUIDScan bool
	BaseAuth                                  nfs.Auth
	Notice                                    io.Writer
	ProbeError                                error
	LockPaths                                 map[uint64]string
}

var ErrSymlinkLoop = errors.New("too many symbolic links")
var ErrDestinationExists = errors.New("destination exists")

func New(c *nfs.Client, host string, autoUID, autoEscape bool, notice io.Writer) *Session {
	if notice == nil {
		notice = io.Discard
	}
	v := c.Version()
	escapeOK := v == "2" || v == "3" || strings.HasPrefix(v, "4")
	return &Session{Client: c, Host: host, CWD: "/", AutoUID: autoUID && v == "3" && c.Security() == "sys", AutoEscape: autoEscape && escapeOK, BaseAuth: c.Auth, Notice: notice}
}
func (s *Session) identity(n nfs.Node) {
	if s.AutoUID && s.Client.Version() == "3" && s.Client.Security() == "sys" {
		s.Client.Auth.UID = n.Attr.UID
		s.Client.Auth.GID = n.Attr.GID
	}
}
func (s *Session) Use(ctx context.Context, export string) error {
	if len(s.Client.Locks()) != 0 {
		return nfs.ErrLocksHeld
	}
	oldAuth := s.Client.Auth
	s.Client.Auth = s.BaseAuth
	n, err := s.Client.Mount(ctx, export)
	if err != nil {
		s.Client.Auth = oldAuth
		return err
	}
	s.identity(n)
	if _, err = s.Client.ReadDir(ctx, n.Handle); err != nil {
		s.Client.Auth = oldAuth
		return err
	}
	if err = s.Client.Tune(ctx, n.Handle); err != nil {
		s.Client.Auth = oldAuth
		return err
	}
	s.Root = n
	s.ExportRoot = cloneRoot(n)
	s.DiscoveredRoot = nil
	s.DiscoveryAttempts = 0
	s.RootVerification = nil
	s.Export = export
	s.CWD = "/"
	s.Escaped = false
	s.ProbeError = nil
	if s.AutoEscape {
		_, err = s.Escape(ctx)
		s.ProbeError = err
		if err != nil {
			fmt.Fprintf(s.Notice, "Escape probe: %v\n", err)
		}
	}
	return nil
}

// RootCandidates only handles the documented Linux knfsd v1 handle layout.
// The candidates refer to filesystem roots, not necessarily the host's /.
func RootCandidates(fh []byte) [][]byte {
	lengths := []int{8, 4, 12, 8, 8, 8, 16, 24}
	if len(fh) < 4 || fh[0] != 1 || fh[1] != 0 || int(fh[2]) >= len(lengths) {
		return nil
	}
	end := 4 + lengths[fh[2]]
	if len(fh) < end {
		return nil
	}
	makeFH := func(kind byte, data []byte) []byte {
		out := append([]byte(nil), fh[:end]...)
		out[3] = kind
		return append(out, data...)
	}
	out := [][]byte{}
	for _, ino := range []uint32{2, 128} {
		// A root directory needs only its own inode and generation. The
		// parent form differs between generic exportfs (three words) and
		// XFS (four); the parentless two-word form is valid for both.
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, ino)
		out = append(out, makeFH(1, b))
	}
	for sub := uint64(256); sub < 272; sub++ {
		b := make([]byte, 20)
		binary.LittleEndian.PutUint64(b, 256)
		binary.LittleEndian.PutUint64(b[8:], sub)
		out = append(out, makeFH(0x4d, b))
	}
	return out
}
func (s *Session) Escape(ctx context.Context) (bool, error) {
	v := s.Client.Version()
	if v != "2" && v != "3" && !strings.HasPrefix(v, "4") {
		return false, errors.New("root handle probing requires NFSv2, NFSv3, or NFSv4")
	}
	if s.Export == "" {
		return false, errors.New("select an export with use first")
	}
	if s.Escaped {
		return true, nil
	}
	if strings.HasPrefix(v, "4") {
		return s.escapeV4(ctx)
	}
	previous := s.Client.Auth
	defer func() {
		if !s.Escaped {
			s.Client.Auth = previous
		}
	}()
	candidates := RootCandidates(s.Root.Handle)
	s.DiscoveryAttempts = 0
	if len(candidates) == 0 {
		return false, errors.New("unsupported file-handle format; escape not tested")
	}
	for _, fh := range candidates {
		s.DiscoveryAttempts++
		s.Client.Auth = previous
		a, err := s.Client.GetAttr(ctx, fh)
		if err != nil {
			var status nfs.Status
			if errors.As(err, &status) {
				continue
			}
			return false, err
		}
		if a.Type != 2 || a.FSID == s.Root.Attr.FSID && a.FileID == s.Root.Attr.FileID {
			continue
		}
		n := nfs.Node{Handle: fh, Attr: a}
		s.identity(n)
		if _, err = s.Client.ReadDir(ctx, fh); err != nil {
			var status nfs.Status
			if errors.As(err, &status) {
				continue
			}
			return false, err
		}
		s.Root = n
		candidate := cloneRoot(n)
		s.DiscoveredRoot = &candidate
		s.RootVerification = nil
		s.CWD = "/"
		s.Escaped = true
		return true, nil
	}
	return false, nil
}

// escapeV4 uses PUTROOTFH to obtain the NFSv4 pseudo-root and navigates to it
// if it is above the current export root in the namespace.
func (s *Session) escapeV4(ctx context.Context) (bool, error) {
	n, err := s.Client.GetNFSv4Root(ctx)
	if err != nil {
		return false, err
	}
	if n.Attr.Type != 2 {
		return false, nil
	}
	// If identity is available on both sides and they match, we're already at the pseudo-root.
	if n.Attr.HasFSID && n.Attr.HasFileID && s.Root.Attr.HasFSID && s.Root.Attr.HasFileID &&
		n.Attr.FSID == s.Root.Attr.FSID && n.Attr.FSIDMinor == s.Root.Attr.FSIDMinor &&
		n.Attr.FileID == s.Root.Attr.FileID {
		return false, nil
	}
	if _, err = s.Client.ReadDir(ctx, n.Handle); err != nil {
		var status nfs.Status
		if errors.As(err, &status) {
			return false, nil
		}
		return false, err
	}
	s.Root = n
	candidate := cloneRoot(n)
	s.DiscoveredRoot = &candidate
	s.RootVerification = nil
	s.CWD = "/"
	s.Escaped = true
	return true, nil
}

// ProbeSquash checks whether the server exports with no_root_squash by creating
// a temporary file as UID 0 and inspecting the resulting ownership.
// Requires AUTH_SYS.  The probe file is always removed.
func (s *Session) ProbeSquash(ctx context.Context) (bool, error) {
	if s.Client.Security() != "sys" {
		return false, errors.New("no_root_squash probe requires AUTH_SYS; reconnect without --sec")
	}
	if s.Export == "" {
		return false, errors.New("select an export with use first")
	}
	previous := s.Client.Auth
	defer func() { s.Client.Auth = previous }()
	probe := previous
	probe.UID, probe.GID, probe.Groups = 0, 0, nil
	s.Client.Auth = probe
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return false, err
	}
	name := ".squash-probe-" + hex.EncodeToString(rnd[:])
	n, err := s.Client.Create(ctx, s.Root.Handle, name, 0600, false)
	if err != nil {
		return false, fmt.Errorf("create probe file: %w", err)
	}
	defer s.Client.Remove(ctx, s.Root.Handle, name)
	if a, err2 := s.Client.GetAttr(ctx, n.Handle); err2 == nil {
		n.Attr = a
	}
	return n.Attr.UID == 0, nil
}

// Resolve processes .. after symlink expansion, preserving filesystem semantics.
func (s *Session) Resolve(ctx context.Context, p string, followFinal bool) (nfs.Node, string, error) {
	if s.Export == "" {
		return nfs.Node{}, "", errors.New("no export selected; use EXPORT")
	}
	if !strings.HasPrefix(p, "/") {
		p = strings.TrimSuffix(s.CWD, "/") + "/" + p
	}
	queue := strings.Split(p, "/")
	nodes := []nfs.Node{s.Root}
	names := []string{}
	links := 0
	for len(queue) > 0 {
		part := queue[0]
		queue = queue[1:]
		parent := nodes[len(nodes)-1]
		if parent.Attr.Type != 2 {
			return nfs.Node{}, "", errors.New("path component is not a directory")
		}
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(nodes) > 1 {
				nodes = nodes[:len(nodes)-1]
				names = names[:len(names)-1]
			}
			continue
		}
		s.identity(parent)
		n, err := s.Client.Lookup(ctx, parent.Handle, part)
		if err != nil {
			return nfs.Node{}, "", fmt.Errorf("lookup %q: %w", part, err)
		}
		if n.Attr.Type == 5 && (followFinal || len(queue) > 0) {
			links++
			if links > 40 {
				return nfs.Node{}, "", ErrSymlinkLoop
			}
			s.identity(n)
			target, err := s.Client.Readlink(ctx, n.Handle)
			if err != nil {
				return nfs.Node{}, "", err
			}
			if target == "" {
				return nfs.Node{}, "", errors.New("empty symbolic link")
			}
			if strings.HasPrefix(target, "/") {
				nodes = nodes[:1]
				names = nil
			}
			queue = append(strings.Split(target, "/"), queue...)
			continue
		}
		nodes = append(nodes, n)
		names = append(names, part)
	}
	n := nodes[len(nodes)-1]
	s.identity(n)
	return n, "/" + strings.Join(names, "/"), nil
}
func (s *Session) CD(ctx context.Context, p string) error {
	n, resolved, err := s.Resolve(ctx, p, true)
	if err != nil {
		return err
	}
	if n.Attr.Type != 2 {
		return errors.New("not a directory")
	}
	s.CWD = resolved
	return nil
}
func (s *Session) LS(ctx context.Context, p string) ([]nfs.Entry, error) {
	entries, _, err := s.listEntries(ctx, p, true)
	return entries, err
}
func (s *Session) Cat(ctx context.Context, p string, w io.Writer) (int64, error) {
	n, _, err := s.Resolve(ctx, p, true)
	if err != nil {
		return 0, err
	}
	if n.Attr.Type != 1 {
		return 0, errors.New("only regular files can be read")
	}
	return s.Client.ReadTo(ctx, n.Handle, w)
}

// Get uses a sibling temporary file; the requested filename only appears after
// a complete transfer. Existing destinations are never overwritten.
func (s *Session) Get(ctx context.Context, remote, local string) (int64, error) {
	return s.GetProgress(ctx, remote, local, nil)
}

// TransferProgress runs synchronously; total is the source size at open time.
// A successful final callback is not a completion signal: Get must also sync
// and publish its temporary file before returning success.
type TransferProgress func(done, total uint64)

type TransferOptions struct {
	readRange *transferRange
	Overwrite bool
	Progress  TransferProgress
}

func (s *Session) GetProgress(ctx context.Context, remote, local string, progress TransferProgress) (int64, error) {
	return s.GetWithOptions(ctx, remote, local, TransferOptions{Progress: progress})
}

func (s *Session) GetWithOptions(ctx context.Context, remote, local string, options TransferOptions) (int64, error) {
	return s.getWithOptions(ctx, remote, local, options, false, nil)
}

// GetPlus uses READ_PLUS with the same source and local publication checks as Get.
func (s *Session) GetPlus(ctx context.Context, remote, local string, progress TransferProgress) (int64, error) {
	if s.Client.Version() != "4.2" {
		return 0, nfs.ErrRequiresV42
	}
	return s.getWithOptions(ctx, remote, local, TransferOptions{Progress: progress}, true, nil)
}

// GetPNFS preserves the ordinary download's source guards and atomic publication.
func (s *Session) GetPNFS(ctx context.Context, remote, local string, options nfs.PNFSOptions, progress TransferProgress) (int64, error) {
	return s.getWithOptions(ctx, remote, local, TransferOptions{Progress: progress}, false, &options)
}

func (s *Session) getWithOptions(ctx context.Context, remote, local string, options TransferOptions, readPlus bool, pnfs *nfs.PNFSOptions) (int64, error) {
	var readGuard func() error
	if pnfs != nil && pnfs.Layout == "block" {
		g := captureReadSession(s)
		readGuard = func() error { return g.check(s) }
		if err := readGuard(); err != nil {
			return 0, err
		}
	}
	progress := options.Progress
	if info, err := os.Lstat(local); err == nil {
		if !options.Overwrite {
			return 0, fmt.Errorf("%w: %s", ErrDestinationExists, local)
		}
		if !info.Mode().IsRegular() {
			return 0, errors.New("overwrite destination must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	node, _, err := s.Resolve(ctx, remote, true)
	if err != nil {
		return 0, err
	}
	if node.Attr.Type != 1 {
		return 0, errors.New("only regular files can be read")
	}
	if err := downloadSourceReady(node.Attr, s.Client.Version()); err != nil {
		return 0, err
	}
	total := node.Attr.Size
	if r := options.readRange; r != nil {
		if r.offset > total || r.length > total-r.offset {
			return 0, errors.New("read range exceeds the current file size")
		}
		if err := s.Client.RequireRangeLock(node.Handle, r.offset, r.length, false); err != nil {
			return 0, err
		}
		total = r.length
	}
	if progress != nil {
		progress(0, total)
	}
	if readGuard != nil {
		if err := readGuard(); err != nil {
			return 0, err
		}
	}
	f, err := os.CreateTemp(filepath.Dir(local), ".nfs-download-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	onProgress := func(done uint64) {
		if progress != nil {
			progress(done, total)
		}
	}
	writer := &downloadWriter{w: f, remaining: total}
	verifiedBeforeReturn := false
	verifyRead := func() error {
		if readGuard != nil {
			if err := readGuard(); err != nil {
				return err
			}
		}
		if writer.remaining != 0 {
			return ErrDownloadSourceChanged
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		after, err := s.Client.GetAttr(ctx, node.Handle)
		if err != nil {
			return fmt.Errorf("cannot verify completed download; destination not published: %w", err)
		}
		if err := verifyDownloadSource(node.Attr, after); err != nil {
			return err
		}
		if readGuard != nil {
			if err := readGuard(); err != nil {
				return err
			}
		}
		verifiedBeforeReturn = true
		return nil
	}
	var n int64
	if r := options.readRange; r != nil {
		n, err = s.Client.ReadRangeToProgress(ctx, node.Handle, r.offset, r.length, writer, onProgress)
	} else if pnfs != nil {
		n, err = s.Client.ReadPNFSToProgressVerified(ctx, node.Handle, node.Attr.Size, writer, *pnfs, onProgress, verifyRead)
	} else if readPlus {
		n, err = s.Client.ReadPlusToProgress(ctx, node.Handle, node.Attr.Size, writer, onProgress)
	} else {
		n, err = s.Client.ReadToProgress(ctx, node.Handle, writer, onProgress)
	}
	if err != nil {
		return n, err
	}
	if uint64(n) != total {
		return n, fmt.Errorf("%w: expected %d bytes, received %d", ErrDownloadSourceChanged, total, n)
	}
	if !verifiedBeforeReturn {
		if err = f.Sync(); err != nil {
			return n, err
		}
		if err = f.Close(); err != nil {
			return n, err
		}
	}
	if err = ctx.Err(); err != nil {
		return n, err
	}
	after, err := s.Client.GetAttr(ctx, node.Handle)
	if err != nil {
		return n, fmt.Errorf("cannot verify completed download; destination not published: %w", err)
	}
	if verifiedBeforeReturn {
		err = verifyPNFSReturnedSource(node.Attr, after)
	} else {
		err = verifyDownloadSource(node.Attr, after)
	}
	if err != nil {
		return n, err
	}
	if readGuard != nil {
		if err := readGuard(); err != nil {
			return n, err
		}
	}
	if err := ctx.Err(); err != nil {
		return n, err
	}
	// Publish on the same filesystem, preserving no-replace semantics.
	if r := options.readRange; r != nil {
		if err := s.Client.RequireRangeLock(node.Handle, r.offset, r.length, false); err != nil {
			return n, err
		}
	}
	if options.Overwrite {
		if err = os.Rename(f.Name(), local); err != nil {
			return n, fmt.Errorf("replace download: %w", err)
		}
		return n, nil
	}
	if err = publishDownload(f.Name(), local); err != nil {
		if errors.Is(err, os.ErrExist) {
			return n, fmt.Errorf("%w: %s", ErrDestinationExists, local)
		}
		return n, fmt.Errorf("publish download: %w", err)
	}
	return n, nil
}
func splitDestination(p string) (string, string, error) {
	if p == "" || strings.HasSuffix(p, "/") {
		return "", "", errors.New("destination must include a filename")
	}
	i := strings.LastIndex(p, "/")
	parent, name := ".", p
	if i >= 0 {
		parent = p[:i+1]
		name = p[i+1:]
	}
	if name == "." || name == ".." || strings.ContainsRune(name, 0) {
		return "", "", errors.New("invalid destination name")
	}
	return parent, name, nil
}
func (s *Session) Put(ctx context.Context, local, remote string) (int64, error) {
	return s.PutProgress(ctx, local, remote, nil)
}

func (s *Session) PutProgress(ctx context.Context, local, remote string, progress TransferProgress) (int64, error) {
	return s.PutWithOptions(ctx, local, remote, TransferOptions{Progress: progress})
}

func (s *Session) PutWithOptions(ctx context.Context, local, remote string, options TransferOptions) (written int64, resultErr error) {
	progress := options.Progress
	f, err := os.Open(local)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("only regular files can be uploaded")
	}
	if progress != nil {
		progress(0, uint64(info.Size()))
	}
	p, name, err := splitDestination(remote)
	if err != nil {
		return 0, err
	}
	parent, _, err := s.Resolve(ctx, p, true)
	if err != nil {
		return 0, err
	}
	if parent.Attr.Type != 2 {
		return 0, errors.New("destination parent is not a directory")
	}
	createName, mode := name, uint32(0644)
	var replacement *nfs.V4ReplacementMetadata
	if options.Overwrite {
		existing, lookupErr := s.Client.Lookup(ctx, parent.Handle, name)
		if lookupErr == nil {
			if existing.Attr.Type != 1 {
				return 0, errors.New("overwrite destination must be a regular file")
			}
			if s.Client.Version() == "2" || s.Client.Version() == "3" {
				return 0, nfs.ErrLegacyReplacementUnsupported
			}
			mode = existing.Attr.Mode & 0777
			if strings.HasPrefix(s.Client.Version(), "4.") {
				replacement, err = s.Client.CaptureV4Replacement(ctx, existing.Handle)
				if err != nil {
					return 0, err
				}
				mode = 0600
			}
		} else {
			var status nfs.Status
			if !errors.As(lookupErr, &status) || status != 2 {
				return 0, lookupErr
			}
			// No existing object was selected for replacement. A later arrival
			// must retain no-replace protection, including on NFSv4.
			options.Overwrite = false
		}
		if options.Overwrite {
			var token [12]byte
			if _, err := rand.Read(token[:]); err != nil {
				return 0, err
			}
			createName = ".nfs-upload-" + hex.EncodeToString(token[:])
		}
	}
	if s.Client.Version() == "2" {
		written, err := s.Client.UploadV2(ctx, parent.Handle, name, mode, f, info.Size(), options.Overwrite, func(done uint64) {
			if progress != nil {
				progress(done, uint64(info.Size()))
			}
		})
		if !options.Overwrite && errors.Is(err, nfs.Status(17)) {
			return written, fmt.Errorf("%w: %s: %w", ErrDestinationExists, remote, err)
		}
		return written, err
	}
	n, err := s.Client.Create(ctx, parent.Handle, createName, mode, false)
	if err != nil {
		var status nfs.Status
		if !options.Overwrite && errors.As(err, &status) && status == 17 {
			return 0, fmt.Errorf("%w: %s", ErrDestinationExists, remote)
		}
		return 0, err
	}
	published := false
	if options.Overwrite {
		defer func() {
			if published {
				return
			}
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			previous := s.Client.Auth
			s.identity(parent)
			defer func() { s.Client.Auth = previous }()
			if replacement != nil {
				target, err := s.Client.Lookup(cleanup, parent.Handle, createName)
				if err != nil {
					if !errors.Is(err, nfs.Status(2)) {
						resultErr = errors.Join(resultErr, fmt.Errorf("temporary upload %q may remain: %w", createName, err))
					}
					return
				}
				if string(target.Handle) != string(n.Handle) {
					resultErr = errors.Join(resultErr, fmt.Errorf("temporary upload %q changed identity; cleanup withheld", createName))
					return
				}
			}
			if err := s.Client.Remove(cleanup, parent.Handle, createName); err != nil {
				var status nfs.Status
				if !errors.As(err, &status) || status != 2 {
					resultErr = errors.Join(resultErr, fmt.Errorf("temporary upload %q may remain: %w", createName, err))
				}
			}
		}()
	}
	if replacement != nil {
		s.identity(n)
		if err := s.Client.CheckV4ReplacementStage(ctx, n.Handle, replacement); err != nil {
			return 0, err
		}
	}
	s.identity(n)
	written, err = s.Client.WriteFromProgress(ctx, n.Handle, &uploadReader{f: f, before: info, remaining: info.Size()}, func(done uint64) {
		if progress != nil {
			progress(done, uint64(info.Size()))
		}
	})
	if err != nil {
		if options.Overwrite {
			return written, fmt.Errorf("replacement upload incomplete; original destination preserved (temporary file %q): %w", createName, err)
		}
		return written, fmt.Errorf("upload incomplete; %q may contain %d bytes: %w", remote, written, err)
	}
	if options.Overwrite {
		if replacement != nil {
			if err := s.Client.ApplyV4Replacement(ctx, n.Handle, replacement); err != nil {
				return written, err
			}
			if err := s.Client.VerifyV4ReplacementSource(ctx, parent.Handle, name, replacement); err != nil {
				return written, err
			}
			if err := s.Client.VerifyV4ReplacementStage(ctx, parent.Handle, createName, n.Handle, replacement); err != nil {
				return written, err
			}
		}
		s.identity(parent)
		if err := s.Client.Rename(ctx, parent.Handle, createName, parent.Handle, name); err != nil {
			return written, fmt.Errorf("publish replacement (temporary file %q): %w", createName, err)
		}
		published = true
	}
	return written, nil
}
func (s *Session) Chmod(ctx context.Context, p string, mode uint32) error {
	n, _, err := s.Resolve(ctx, p, true)
	if err != nil {
		return err
	}
	return s.Client.Chmod(ctx, n.Handle, mode)
}
func (s *Session) Mkdir(ctx context.Context, p string) error {
	dir, name, err := splitDestination(p)
	if err != nil {
		return err
	}
	n, _, err := s.Resolve(ctx, dir, true)
	if err != nil {
		return err
	}
	_, err = s.Client.Create(ctx, n.Handle, name, 0755, true)
	return err
}

// UIDScan probes UIDs [start, end] against fh and returns those that grant
// read access. Stops after maxResults hits. Caller's auth is always restored.
// Requires AUTH_SYS.
func (s *Session) UIDScan(ctx context.Context, fh []byte, start, end, maxResults uint32) ([]uint32, error) {
	if s.Client.Security() != "sys" {
		return nil, errors.New("UID scan requires AUTH_SYS")
	}
	previous := s.Client.Auth
	defer func() { s.Client.Auth = previous }()
	var found []uint32
	for uid := start; uid <= end; uid++ {
		if ctx.Err() != nil {
			return found, ctx.Err()
		}
		probe := previous
		probe.UID, probe.GID, probe.Groups = uid, uid, nil
		s.Client.Auth = probe
		ok, err := s.canRead(ctx, fh, uid, uid)
		if ok {
			found = append(found, uid)
			if uint32(len(found)) >= maxResults {
				break
			}
		} else if err != nil {
			var status nfs.Status
			if !errors.As(err, &status) {
				return found, err
			}
		}
	}
	return found, nil
}

// findUID probes the file/directory owner UID and a few common UIDs to find
// one that grants read access without a full range scan. The caller's auth is
// always restored; the caller is responsible for applying the found UID.
// Returns (uid, true, nil) on success, (0, false, nil) when none is found, or
// (0, false, err) on a non-NFS transport error.
func (s *Session) findUID(ctx context.Context, fh []byte) (uint32, bool, error) {
	if s.Client.Security() != "sys" {
		return 0, false, nil
	}
	a, err := s.Client.GetAttr(ctx, fh)
	if err != nil {
		return 0, false, nil
	}
	previous := s.Client.Auth
	defer func() { s.Client.Auth = previous }()
	// Try owner, group owner, root, and a few other common UIDs.
	seen := map[uint32]bool{}
	candidates := []uint32{a.UID, a.GID, 0, 33, 65534}
	for _, uid := range candidates {
		if seen[uid] {
			continue
		}
		seen[uid] = true
		probe := previous
		probe.UID, probe.GID, probe.Groups = uid, uid, nil
		s.Client.Auth = probe
		ok, err := s.canRead(ctx, fh, uid, uid)
		if ok {
			return uid, true, nil
		}
		if err != nil {
			var status nfs.Status
			if !errors.As(err, &status) {
				return 0, false, err
			}
		}
	}
	return 0, false, nil
}

func (s *Session) canRead(ctx context.Context, fh []byte, uid, gid uint32) (bool, error) {
	a, err := s.Client.GetAttr(ctx, fh)
	if err != nil {
		var status nfs.Status
		if errors.As(err, &status) {
			return false, nil
		}
		return false, err
	}
	if a.Type == 2 {
		_, err = s.Client.ReadDir(ctx, fh)
		return err == nil, err
	}
	if s.Client.Version() == "2" {
		return modeAllowsRead(a, uid, gid), nil
	}
	bits, err := s.Client.Access(ctx, fh)
	if err != nil {
		var status nfs.Status
		if errors.As(err, &status) {
			return false, nil
		}
		return false, err
	}
	return bits&1 != 0, nil
}

func modeAllowsRead(a nfs.Attr, uid, gid uint32) bool {
	if uid == 0 {
		return a.Mode&0400 != 0
	}
	if a.UID == uid {
		return a.Mode&0400 != 0
	}
	if a.GID == gid {
		return a.Mode&0040 != 0
	}
	return a.Mode&0004 != 0
}
