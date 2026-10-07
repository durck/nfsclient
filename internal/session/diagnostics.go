package session

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
)

type HandleReport struct {
	Path     string `json:"path"`
	Export   string `json:"export"`
	Encoding string `json:"encoding"`
	Handle   string `json:"handle"`
	Bytes    int    `json:"bytes"`
}

// HandlePath exports only the opaque bytes returned by NFS. Resolving the path
// preserves the current identity and does not follow the final symbolic link.
func (s *Session) HandlePath(ctx context.Context, name string) (HandleReport, error) {
	if name == "" || strings.ContainsRune(name, 0) || name != "/" && strings.HasSuffix(name, "/") {
		return HandleReport{}, errors.New("an exact path without a trailing slash is required")
	}
	auto, scan, auth := s.AutoUID, s.AutoUIDScan, s.Client.Auth
	s.AutoUID, s.AutoUIDScan = false, false
	defer func() { s.AutoUID, s.AutoUIDScan, s.Client.Auth = auto, scan, auth }()
	if err := ctx.Err(); err != nil {
		return HandleReport{}, err
	}
	n, resolved, err := s.Resolve(ctx, name, false)
	if err != nil {
		return HandleReport{}, err
	}
	if len(n.Handle) == 0 {
		return HandleReport{}, errors.New("server did not supply an opaque file handle")
	}
	return HandleReport{Path: resolved, Export: s.Export, Encoding: "hex", Handle: hex.EncodeToString(n.Handle), Bytes: len(n.Handle)}, nil
}
