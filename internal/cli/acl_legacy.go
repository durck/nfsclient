package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"nfsclient/internal/nfs"
)

// The on-disk schema contains only editable policy and its version/type/owner
// constraints. File handles and observation timestamps are never imported.
type legacyACLDocument struct {
	Version uint32           `json:"version"`
	Type    uint32           `json:"type"`
	UID     uint32           `json:"uid"`
	GID     uint32           `json:"gid"`
	Mode    uint32           `json:"mode"`
	Access  []legacyACLEntry `json:"access"`
	Default []legacyACLEntry `json:"default"`
}

type legacyACLEntry struct {
	Tag  uint32 `json:"tag"`
	ID   uint32 `json:"id"`
	Perm uint32 `json:"perm"`
}

func (s *Shell) exportACL(ctx context.Context, path, local, attribute string) error {
	if strings.HasPrefix(s.Session.Client.Version(), "4") {
		return s.exportV4ACL(ctx, path, local, attribute)
	}
	if attribute != "acl" {
		return errors.New("NFSv2/v3 export requires acl (both access and default policy)")
	}
	node, err := s.legacyACLNode(ctx, path)
	if err != nil {
		return err
	}
	acl, err := s.Session.Client.GetLegacyACL(ctx, node.Handle)
	if err != nil {
		return err
	}
	version, _ := strconv.ParseUint(s.Session.Client.Version(), 10, 32)
	doc := legacyACLDocument{Version: uint32(version), Type: acl.Attr.Type, UID: acl.Attr.UID, GID: acl.Attr.GID, Mode: acl.Attr.Mode,
		Access: []legacyACLEntry{}, Default: []legacyACLEntry{}}
	for _, e := range acl.Access {
		doc.Access = append(doc.Access, legacyACLEntry{e.Tag, e.ID, e.Perm})
	}
	for _, e := range acl.Default {
		doc.Default = append(doc.Default, legacyACLEntry{e.Tag, e.ID, e.Perm})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.local(local), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return errors.Join(err, f.Close())
}

func (s *Shell) setACL(ctx context.Context, path, local string) error {
	if strings.HasPrefix(s.Session.Client.Version(), "4") {
		return s.setV4ACL(ctx, path, local)
	}
	f, err := os.Open(s.local(local))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if len(data) > 1024*1024 {
		return errors.New("ACL JSON exceeds 1 MiB")
	}
	policy, version, err := parseLegacyACLJSON(data)
	if err != nil {
		return err
	}
	if strconv.FormatUint(uint64(version), 10) != s.Session.Client.Version() {
		return errors.New("ACL JSON version differs from selected NFS version")
	}
	node, err := s.legacyACLNode(ctx, path)
	if err != nil {
		return err
	}
	if err := s.Session.Client.EditLegacyACL(ctx, node, policy); err != nil {
		return err
	}
	_, err = fmt.Fprintln(s.Out, "ACL applied and exact readback verified.")
	return err
}

// Resolve each component without Session.identity or symlink expansion. Even a
// component subsequently cancelled by '..' must be an actual directory.
func (s *Shell) legacyACLNode(ctx context.Context, path string) (nfs.Node, error) {
	if s.Session.Client.Version() != "2" && s.Session.Client.Version() != "3" {
		return nfs.Node{}, nfs.ErrNFSACLUnavailable
	}
	if s.Session.Export == "" {
		return nfs.Node{}, errors.New("no export selected; use EXPORT")
	}
	if !strings.HasPrefix(path, "/") {
		path = strings.TrimSuffix(s.Session.CWD, "/") + "/" + path
	}
	nodes := []nfs.Node{s.Session.Root}
	for _, part := range strings.Split(path, "/") {
		parent := nodes[len(nodes)-1]
		if parent.Attr.Type != 2 {
			return nfs.Node{}, errors.New("ACL path component is not a directory")
		}
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(nodes) > 1 {
				nodes = nodes[:len(nodes)-1]
			}
			continue
		}
		node, err := s.Session.Client.Lookup(ctx, parent.Handle, part)
		if err != nil {
			return nfs.Node{}, err
		}
		if node.Attr.Type != 1 && node.Attr.Type != 2 {
			return nfs.Node{}, errors.New("acl requires a regular file or directory; symbolic links are not followed")
		}
		nodes = append(nodes, node)
	}
	return nodes[len(nodes)-1], nil
}

// Decode one exact object, rejecting duplicate/case-variant/unknown keys and
// omissions. encoding/json's normal struct decoding silently accepts those.
func legacyACLFields(data []byte, names ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("ACL JSON requires an object")
	}
	fields := make(map[string]json.RawMessage, len(names))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		allowed := false
		for _, name := range names {
			if key == name {
				allowed = true
			}
		}
		if !ok || !allowed || fields[key] != nil {
			return nil, errors.New("ACL JSON contains an unknown or duplicate field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("ACL JSON fields must not be null")
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("ACL JSON must contain exactly one object")
	}
	if len(fields) != len(names) {
		return nil, errors.New("ACL JSON requires every policy field, including explicit default")
	}
	return fields, nil
}

func parseLegacyACLJSON(data []byte) (*nfs.NFS3ACL, uint32, error) {
	if !utf8.Valid(data) {
		return nil, 0, errors.New("ACL JSON must be valid UTF-8")
	}
	fields, err := legacyACLFields(data, "version", "type", "uid", "gid", "mode", "access", "default")
	if err != nil {
		return nil, 0, err
	}
	var version uint32
	policy := &nfs.NFS3ACL{}
	for name, target := range map[string]*uint32{"version": &version, "type": &policy.Attr.Type, "uid": &policy.Attr.UID, "gid": &policy.Attr.GID, "mode": &policy.Attr.Mode} {
		if err := json.Unmarshal(fields[name], target); err != nil {
			return nil, 0, err
		}
	}
	if version != 2 && version != 3 {
		return nil, 0, errors.New("ACL JSON requires version 2 or 3")
	}
	for name, target := range map[string]*[]nfs.NFS3ACLEntry{"access": &policy.Access, "default": &policy.Default} {
		var entries []json.RawMessage
		if err := json.Unmarshal(fields[name], &entries); err != nil {
			return nil, 0, err
		}
		if len(entries) > 1024 {
			return nil, 0, errors.New("ACL exceeds 1024 entries")
		}
		*target = make([]nfs.NFS3ACLEntry, 0, len(entries))
		for _, raw := range entries {
			entryFields, err := legacyACLFields(raw, "tag", "id", "perm")
			if err != nil {
				return nil, 0, err
			}
			var entry nfs.NFS3ACLEntry
			for key, dest := range map[string]*uint32{"tag": &entry.Tag, "id": &entry.ID, "perm": &entry.Perm} {
				if err := json.Unmarshal(entryFields[key], dest); err != nil {
					return nil, 0, err
				}
			}
			*target = append(*target, entry)
		}
	}
	return policy, version, nfs.ValidateLegacyACL(policy)
}
