package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"nfs-viewer/internal/nfs"
)

// GetResumeFailover tries each explicitly approved endpoint at most once after
// a recoverable read failure. Fresh OPENs, source checks and complete prefix
// comparison replace shared-state assumptions; held locks forbid switching.
func (s *Session) GetResumeFailover(ctx context.Context, remote, local string, targets []nfs.ReadReplica, progress TransferProgress) (int64, error) {
	if len(targets) < 1 || len(targets) > 8 {
		return 0, errors.New("read failover requires 1..8 approved targets")
	}
	targets = slices.Clone(targets)
	seen := make(map[string]bool)
	for _, target := range targets {
		if err := s.Client.ValidateReadReplica(target); err != nil {
			return 0, err
		}
		host, port, _ := net.SplitHostPort(target.Address)
		value, _ := strconv.Atoi(port)
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		}
		key := net.JoinHostPort(strings.TrimSuffix(strings.ToLower(host), "."), strconv.Itoa(value))
		if seen[key] {
			return 0, errors.New("duplicate read failover endpoint")
		}
		seen[key] = true
	}
	if s.AutoUID || s.AutoEscape || s.Escaped || s.Export == "" {
		return 0, errors.New("read failover requires fixed identity and a selected export")
	}
	if len(s.Client.Locks()) != 0 {
		return 0, nfs.ErrLocksHeld
	}
	if s.BaseAuth.UID != s.Client.Auth.UID || s.BaseAuth.GID != s.Client.Auth.GID || !slices.Equal(s.BaseAuth.Groups, s.Client.Auth.Groups) {
		return 0, errors.New("read failover requires current and base credentials to match")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	unlock, err := lockResume(local)
	if err != nil {
		return 0, err
	}
	defer unlock()
	g := captureReadSession(s)
	source := resumeSource{guard: func(_ []byte, _ string, _ bool) error { return g.check(s) }}
	count, err := s.getResume(ctx, remote, local, progress, &source)
	for i, target := range targets {
		if err == nil || !source.set || !readRecoveryError(err) {
			return count, err
		}
		if checkErr := g.check(s); checkErr != nil {
			return count, errors.Join(err, checkErr)
		}
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		fmt.Fprintf(s.Notice, "Read failover %d/%d to %s: %v\n", i+1, len(targets), target.Address, err)
		if checkErr := g.check(s); checkErr != nil {
			return count, errors.Join(err, checkErr)
		}
		fresh, connectErr := s.Client.ConnectReadReplica(ctx, target)
		if connectErr != nil {
			err = connectErr
			continue
		}
		host, _, _ := net.SplitHostPort(target.Address)
		if err = s.installReconnect(ctx, fresh, host); err != nil {
			continue
		}
		g.client, g.host = s.Client, s.Host
		g.root, g.exportRoot = bytes.Clone(s.Root.Handle), bytes.Clone(s.ExportRoot.Handle)
		if checkErr := g.check(s); checkErr != nil {
			return count, checkErr
		}
		count, err = s.getResume(ctx, remote, local, progress, &source)
	}
	if ctx.Err() != nil {
		return count, ctx.Err()
	}
	if err != nil && readRecoveryError(err) {
		return count, fmt.Errorf("read failover exhausted (%d approved targets): %w", len(targets), err)
	}
	return count, err
}

type readSession struct {
	client                      *nfs.Client
	auth, baseAuth              nfs.Auth
	identity, host, export, cwd string
	root, exportRoot            []byte
}

func captureReadSession(s *Session) readSession {
	g := readSession{client: s.Client, auth: s.Client.Auth, baseAuth: s.BaseAuth, identity: s.Client.Identity(), host: s.Host, export: s.Export, cwd: s.CWD, root: bytes.Clone(s.Root.Handle), exportRoot: bytes.Clone(s.ExportRoot.Handle)}
	g.auth.Groups = slices.Clone(g.auth.Groups)
	g.baseAuth.Groups = slices.Clone(g.baseAuth.Groups)
	return g
}

func (g readSession) check(s *Session) error {
	if len(s.Client.Locks()) != 0 {
		return errors.New("read recovery lock inventory changed")
	}
	return g.checkProfile(s)
}

func (g readSession) checkProfile(s *Session) error {
	if s.Client != g.client || s.Client.Identity() != g.identity || s.Host != g.host || s.Export != g.export || s.CWD != g.cwd || s.AutoUID || s.AutoEscape || s.Escaped || !bytes.Equal(s.Root.Handle, g.root) || !bytes.Equal(s.ExportRoot.Handle, g.exportRoot) || s.Client.Auth.UID != g.auth.UID || s.Client.Auth.GID != g.auth.GID || !slices.Equal(s.Client.Auth.Groups, g.auth.Groups) || s.BaseAuth.UID != g.baseAuth.UID || s.BaseAuth.GID != g.baseAuth.GID || !slices.Equal(s.BaseAuth.Groups, g.baseAuth.Groups) {
		return errors.New("read recovery session, namespace, identity or lock inventory changed")
	}
	return nil
}
