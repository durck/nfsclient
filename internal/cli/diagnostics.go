package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

func (s *Shell) mounts(ctx context.Context, args []string) error {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		return fmt.Errorf("usage: mounts [--json]")
	}
	r, callErr := s.Session.Client.Mounts(ctx)
	if asJSON {
		if err := json.NewEncoder(s.Out).Encode(r); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(s.Out, "MOUNT records / NFS %s\n  Identity: %s\n  %s\n", r.Version, label(r.Identity), r.Meaning)
		for _, e := range r.Entries {
			fmt.Fprintf(s.Out, "  %s  %s\n", label(e.Hostname), label(e.Path))
		}
		if r.Complete && len(r.Entries) == 0 {
			fmt.Fprintln(s.Out, "  No records returned.")
		}
	}
	return callErr
}

func (s *Shell) handle(ctx context.Context, args []string) error {
	p, asJSON, err := inspectionPath(args, "--json", false)
	if err != nil {
		return fmt.Errorf("usage: handle [PATH] [--json]: %w", err)
	}
	h, err := s.Session.HandlePath(ctx, p)
	if err != nil {
		return err
	}
	lookup, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	r := struct {
		session.HandleReport
		Connection nfs.ConnectionInfo `json:"connection"`
	}{h, s.Session.Client.ConnectionInfo(lookup)}
	if asJSON {
		return json.NewEncoder(s.Out).Encode(r)
	}
	_, err = fmt.Fprintf(s.Out, "Handle: %s\n  Export: %s\n  Server: %s\n  Connected peer: %s\n  NFS: %s / %s\n  Identity: %s\n  Opaque handle (%d bytes, hex): %s\n", label(h.Path), label(h.Export), label(r.Connection.RequestedHost), label(r.Connection.Peer), r.Connection.Version, r.Connection.Transport, label(r.Connection.Identity), h.Bytes, h.Handle)
	return err
}
