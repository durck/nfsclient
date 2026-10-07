package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"nfsclient/internal/nfs"
)

func (s *Shell) info(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "--json" {
		args = nil
	}
	if len(args) != 0 {
		return errors.New("usage: info")
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	r := struct {
		nfs.ConnectionInfo
		Export string `json:"export"`
		CWD    string `json:"cwd"`
	}{s.Session.Client.ConnectionInfo(ctx), s.Session.Export, s.Session.CWD}
	enc := json.NewEncoder(s.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (s *Shell) capabilities(ctx context.Context, args []string) error {
	p, _, err := inspectionPath(args, "--json", false)
	if err != nil {
		return fmt.Errorf("usage: capabilities [PATH] [--json]: %w", err)
	}
	restore := s.pinInspectionIdentity()
	defer restore()
	n, resolved, err := s.Session.Resolve(ctx, p, false)
	if err != nil {
		return err
	}
	caps, err := s.Session.Client.Capabilities(ctx, n.Handle)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(s.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Path     string `json:"path"`
		Identity string `json:"identity"`
		nfs.Capabilities
	}{resolved, s.Session.Client.Identity(), caps})
}

// Pin the caller's current identity, including through resolver/list helpers.
// Inspection must never select a different observed owner or trigger UID scans.
func (s *Shell) pinInspectionIdentity() func() {
	sess := s.Session
	auto, scan, auth := sess.AutoUID, sess.AutoUIDScan, sess.Client.Auth
	sess.AutoUID, sess.AutoUIDScan = false, false
	return func() { sess.AutoUID, sess.AutoUIDScan, sess.Client.Auth = auto, scan, auth }
}

func inspectionPath(args []string, flag string, required bool) (string, bool, error) {
	p, found, paths, literal := ".", false, 0, false
	for _, arg := range args {
		if !literal && arg == "--" {
			literal = true
			continue
		}
		if !literal && arg == flag {
			if found {
				return "", false, fmt.Errorf("%s must not repeat", flag)
			}
			found = true
		} else {
			if !literal && strings.HasPrefix(arg, "--") {
				return "", false, fmt.Errorf("unknown option %s", arg)
			}
			p = arg
			paths++
		}
	}
	if paths > 1 || required && paths != 1 {
		return "", false, errors.New("expected one path")
	}
	return p, found, nil
}

func offlinePath(args []string, required bool) (string, error) {
	p, found, err := inspectionPath(args, "--offline", required)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errors.New("usage: ls --offline [PATH] or stat --offline PATH")
	}
	return p, nil
}

func (s *Shell) statWithOffline(ctx context.Context, args []string) error {
	p, err := offlinePath(args, true)
	if err != nil {
		return err
	}
	restore := s.pinInspectionIdentity()
	defer restore()
	n, _, err := s.Session.Resolve(ctx, p, false)
	if err != nil {
		return err
	}
	n.Attr.Offline, err = s.Session.Client.OfflineMetadata(ctx, n.Handle)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(s.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(n.Attr)
}

func (s *Shell) listWithOffline(ctx context.Context, args []string) error {
	p, err := offlinePath(args, false)
	if err != nil {
		return err
	}
	restore := s.pinInspectionIdentity()
	defer restore()
	entries, links, err := s.Session.List(ctx, p, 32)
	if err != nil {
		return err
	}
	for i := range entries {
		entries[i].Attr.Offline = nfs.OfflineUnknown
	}
	for i := range entries {
		if len(entries[i].Handle) == 0 {
			continue
		}
		entries[i].Attr.Offline, err = s.Session.Client.OfflineMetadata(ctx, entries[i].Handle)
		if err != nil {
			if printErr := s.printEntries(entries, links); printErr != nil {
				return printErr
			}
			return fmt.Errorf("offline metadata %q: %w", entries[i].Name, err)
		}
	}
	return s.printEntries(entries, links)
}
