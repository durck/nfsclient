package nfs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const mountDumpLimit = 4096
const mountDumpTimeout = 5 * time.Second

var ErrMountUnavailable = errors.New("MOUNT DUMP unavailable")

// MountEntry is a mount daemon's historical record, not an active NFS client.
type MountEntry struct {
	Hostname string `json:"hostname"`
	Path     string `json:"path"`
}

type MountReport struct {
	Version   string       `json:"version"`
	Identity  string       `json:"identity"`
	Peer      string       `json:"mount_peer,omitempty"`
	Source    string       `json:"source"`
	Meaning   string       `json:"meaning"`
	Available bool         `json:"available"`
	Complete  bool         `json:"complete"`
	Entries   []MountEntry `json:"entries"`
	Error     string       `json:"error,omitempty"`
}

// Mounts uses the established MOUNT transport, including its configured service
// port and authentication. NFSv4 never discovers or contacts a legacy service.
// DUMP has no pagination; both the transport record and decoded list are bounded.
func (c *Client) Mounts(ctx context.Context) (r MountReport, err error) {
	r = MountReport{Version: c.Version(), Identity: c.Identity(), Source: "MOUNT DUMP", Meaning: "Historical mount daemon records; not an active client list. Records may be stale or incomplete.", Entries: []MountEntry{}}
	defer func() {
		if err != nil {
			r.Error = err.Error()
		}
	}()
	if c.v4 != nil || strings.HasPrefix(c.Version(), "4") {
		return r, fmt.Errorf("%w: NFSv4 has no MOUNT protocol", ErrMountUnavailable)
	}
	if c.mount == nil || c.mount.conn == nil {
		return r, fmt.Errorf("%w: no connected mount daemon", ErrMountUnavailable)
	}
	r.Peer = c.mount.conn.RemoteAddr().String()
	ctx, cancel := context.WithTimeout(ctx, mountDumpTimeout)
	defer cancel()
	d, err := c.mount.call(ctx, mountProgram, c.mountVersion(), 2, &c.Auth, nil)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if errors.Is(err, RPCStatus(1)) || errors.Is(err, RPCStatus(2)) || errors.Is(err, RPCStatus(3)) {
			return r, fmt.Errorf("%w: %w", ErrMountUnavailable, err)
		}
		return r, fmt.Errorf("MOUNT DUMP failed: %w", err)
	}
	r.Available = true
	for d.boolean() && d.err == nil {
		if err := ctx.Err(); err != nil {
			return r, fmt.Errorf("MOUNT DUMP: %w", err)
		}
		if len(r.Entries) >= mountDumpLimit {
			return r, fmt.Errorf("MOUNT DUMP exceeds %d entry limit; partial records only", mountDumpLimit)
		}
		entry := MountEntry{Hostname: string(d.opaque(255)), Path: string(d.opaque(1024))}
		if d.err != nil {
			break
		}
		r.Entries = append(r.Entries, entry)
	}
	if d.err != nil {
		return r, fmt.Errorf("malformed MOUNT DUMP: %w", d.err)
	}
	if len(d.b) != 0 {
		return r, errors.New("malformed MOUNT DUMP: trailing data")
	}
	r.Complete = true
	return r, nil
}
