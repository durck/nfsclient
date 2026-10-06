// Package krbconfig loads bounded, immutable Kerberos file profiles.
package krbconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const MaxBytes = 1 << 20
const MaxFiles = 64
const MaxDepth = 8
const maxDirectoryEntries = 1024

var ErrChanged = errors.New("kerberos configuration dependencies changed; reconnect with an explicitly selected profile")

type dependency struct {
	path  string
	info  os.FileInfo
	hash  [32]byte
	names []string
}

// Snapshot owns immutable normalized text and all source dependencies. Values
// are unexported so callers cannot replace policy after authentication begins.
type Snapshot struct {
	text, fingerprint string
	dependencies      []dependency
}

func (s *Snapshot) Text() string        { return s.text }
func (s *Snapshot) Fingerprint() string { return s.fingerprint }

// Verify checks contents, identity, metadata and directory membership. These
// observations cannot lock external files; consumers always use the saved text.
func (s *Snapshot) Verify() error {
	if s == nil {
		return errors.New("missing Kerberos configuration snapshot")
	}
	for _, dep := range s.dependencies {
		info, err := os.Stat(dep.path)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrChanged, dep.path, err)
		}
		if !os.SameFile(dep.info, info) || dep.info.Mode() != info.Mode() || dep.info.Size() != info.Size() || !dep.info.ModTime().Equal(info.ModTime()) {
			return fmt.Errorf("%w: %s", ErrChanged, dep.path)
		}
		if dep.names != nil {
			names, err := directoryNames(dep.path)
			if err != nil || !slices.Equal(names, dep.names) {
				return fmt.Errorf("%w: directory %s", ErrChanged, dep.path)
			}
		} else {
			data, _, err := readFile(dep.path, MaxBytes)
			if err != nil || sha256.Sum256(data) != dep.hash {
				return fmt.Errorf("%w: file %s", ErrChanged, dep.path)
			}
		}
	}
	return nil
}

func readFile(path string, limit int) ([]byte, os.FileInfo, error) {
	selected, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !selected.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("kerberos configuration is not a regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("kerberos configuration is not a regular file: %s", path)
	}
	if !os.SameFile(selected, before) {
		return nil, nil, ErrChanged
	}
	if before.Size() > int64(limit) {
		return nil, nil, errors.New("kerberos configuration exceeds 1 MiB total")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > limit {
		return nil, nil, errors.New("kerberos configuration exceeds 1 MiB total")
	}
	after, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, nil, ErrChanged
	}
	return data, before, nil
}

func directoryNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maxDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxDirectoryEntries {
		return nil, errors.New("kerberos include directory exceeds 1024 entries")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names, nil
}

func includedName(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	if strings.HasSuffix(name, ".conf") {
		return true
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return name != ""
}

type loader struct {
	profile      profile
	dependencies []dependency
	active       map[string]bool
	bytes, files int
}

// Load resolves only explicit absolute include/include-directory directives.
// Every file has independent section context. Included directories use sorted
// MIT-compatible names. Dynamic modules and final markers are refused.
func Load(path string) (*Snapshot, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	l := &loader{active: map[string]bool{}}
	if err := l.file(abs, 0); err != nil {
		return nil, err
	}
	text := l.profile.text()
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("empty Kerberos configuration")
	}
	if len(text) > MaxBytes {
		return nil, errors.New("normalized Kerberos configuration exceeds 1 MiB")
	}
	h := sha256.New()
	for _, dep := range l.dependencies {
		fmt.Fprintf(h, "%s\x00%x\x00", dep.path, dep.hash)
		for _, name := range dep.names {
			fmt.Fprintf(h, "%s\x00", name)
		}
	}
	s := &Snapshot{text: text, fingerprint: hex.EncodeToString(h.Sum(nil)), dependencies: l.dependencies}
	if err := s.Verify(); err != nil {
		return nil, err
	}
	return s, nil
}

func (l *loader) file(path string, depth int) error {
	if depth > MaxDepth {
		return errors.New("kerberos include depth exceeds 8")
	}
	if l.files >= MaxFiles {
		return errors.New("kerberos include file count exceeds 64")
	}
	l.files++
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	key := filepath.Clean(real)
	// SameFile below also catches hard-link aliases on platforms that expose IDs.
	if l.active[key] {
		return fmt.Errorf("kerberos include cycle: %s", path)
	}
	data, info, err := readFile(path, MaxBytes-l.bytes)
	if err != nil {
		return err
	}
	for _, dep := range l.dependencies {
		if l.active[dep.path] && os.SameFile(dep.info, info) {
			return fmt.Errorf("kerberos include cycle: %s", path)
		}
	}
	l.active[key] = true
	l.active[path] = true
	defer func() { delete(l.active, key); delete(l.active, path) }()
	l.bytes += len(data)
	l.dependencies = append(l.dependencies, dependency{path: path, info: info, hash: sha256.Sum256(data)})
	include := func(kind, target string) error {
		if !filepath.IsAbs(target) {
			return errors.New("kerberos include paths must be absolute")
		}
		if kind == "include" {
			return l.file(filepath.Clean(target), depth+1)
		}
		if len(l.dependencies) >= MaxFiles*2 {
			return errors.New("kerberos include dependency count exceeds 128")
		}
		info, err := os.Stat(target)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("kerberos includedir requires a directory")
		}
		names, err := directoryNames(target)
		if err != nil {
			return err
		}
		l.dependencies = append(l.dependencies, dependency{path: target, info: info, names: names})
		for _, name := range names {
			if includedName(name) {
				if err := l.file(filepath.Join(target, name), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := l.profile.parse(string(data), include); err != nil {
		return fmt.Errorf("kerberos configuration %s: %w", path, err)
	}
	return nil
}
