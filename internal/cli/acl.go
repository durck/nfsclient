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

func (s *Shell) inspectACL(ctx context.Context, path string) error {
	if strings.HasPrefix(s.Session.Client.Version(), "4") {
		acl, err := s.readV4ACL(ctx, path, "acl")
		if err != nil {
			return err
		}
		enc := json.NewEncoder(s.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(acl)
	}
	node, err := s.legacyACLNode(ctx, path)
	if err != nil {
		return err
	}
	if node.Attr.Type != 1 && node.Attr.Type != 2 {
		return errors.New("acl requires a regular file or directory; symbolic links are not followed")
	}
	acl, err := s.Session.Client.GetLegacyACL(ctx, node.Handle)
	if err != nil {
		return err
	}
	return printLegacyACL(s.Out, acl, s.Session.Client.Version())
}

func (s *Shell) aclNode(ctx context.Context, path string) (nfs.Node, error) {
	if !strings.HasPrefix(s.Session.Client.Version(), "4") {
		return nfs.Node{}, nfs.ErrNFS4ACLUnavailable
	}
	inspection := *s.Session
	inspection.AutoUID = false
	node, _, err := inspection.Resolve(ctx, path, false)
	if err != nil {
		return nfs.Node{}, err
	}
	if node.Attr.Type != 1 && node.Attr.Type != 2 {
		return nfs.Node{}, errors.New("acl requires a regular file or directory; symbolic links are not followed")
	}
	return node, nil
}

func (s *Shell) readV4ACL(ctx context.Context, path, attribute string) (*nfs.NFS4ACL, error) {
	node, err := s.aclNode(ctx, path)
	if err != nil {
		return nil, err
	}
	return s.Session.Client.GetNFS4ACL(ctx, node.Handle, attribute)
}

func (s *Shell) exportV4ACL(ctx context.Context, path, local, attribute string) error {
	acl, err := s.readV4ACL(ctx, path, attribute)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(acl, "", "  ")
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

func (s *Shell) setV4ACL(ctx context.Context, path, local string) error {
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
	acl, err := parseV4ACLJSON(data)
	if err != nil {
		return err
	}
	node, err := s.aclNode(ctx, path)
	if err != nil {
		return err
	}
	if err := s.Session.Client.SetNFS4ACL(ctx, node.Handle, acl); err != nil {
		return err
	}
	_, err = fmt.Fprintln(s.Out, "ACL applied and exact readback verified.")
	return err
}

// ACL edits must not silently turn a misspelled/omitted type into ALLOW or
// overwrite duplicate object keys. Every policy field is explicit.
func parseV4ACLJSON(data []byte) (*nfs.NFS4ACL, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("ACL JSON must be valid UTF-8")
	}
	// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD. A
	// principal must never be silently changed while parsing a policy edit.
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) || data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return nil, errors.New("truncated ACL JSON escape")
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return nil, err
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return nil, errors.New("unpaired ACL JSON surrogate")
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return nil, errors.New("unpaired ACL JSON surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return nil, errors.New("unpaired ACL JSON surrogate")
			}
			i += 6
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 8 {
			return errors.New("ACL JSON nesting exceeds schema")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("ACL JSON has a duplicate object key")
				}
				seen[name] = true
				allowed := depth == 0 && (name == "attribute" || name == "flags" || name == "entries") || depth == 2 && (name == "type" || name == "flags" || name == "mask" || name == "who")
				if !allowed {
					return errors.New("ACL JSON contains an unknown field")
				}
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := scan(0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("ACL JSON must contain exactly one object")
	}
	var document struct {
		Attribute *string `json:"attribute"`
		Flags     *uint32 `json:"flags"`
		Entries   *[]struct {
			Type  *uint32 `json:"type"`
			Flags *uint32 `json:"flags"`
			Mask  *uint32 `json:"mask"`
			Who   *string `json:"who"`
		} `json:"entries"`
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&document); err != nil {
		return nil, err
	}
	if document.Attribute == nil || document.Flags == nil || document.Entries == nil {
		return nil, errors.New("ACL JSON requires attribute, flags and entries")
	}
	acl := &nfs.NFS4ACL{Attribute: *document.Attribute, Flags: *document.Flags, Entries: []nfs.NFS4ACE{}}
	for _, a := range *document.Entries {
		if a.Type == nil || a.Flags == nil || a.Mask == nil || a.Who == nil {
			return nil, errors.New("each ACE requires type, flags, mask and who")
		}
		acl.Entries = append(acl.Entries, nfs.NFS4ACE{Type: *a.Type, Flags: *a.Flags, Mask: *a.Mask, Who: *a.Who})
	}
	return acl, nfs.ValidateNFS4ACL(acl)
}

func printNFS3ACL(w io.Writer, acl *nfs.NFS3ACL) error {
	return printLegacyACL(w, acl, "3")
}

func printLegacyACL(w io.Writer, acl *nfs.NFS3ACL, version string) error {
	var out strings.Builder
	fmt.Fprintf(&out, "# NFSv%s ACL (read-only)\n", version)
	fmt.Fprintf(&out, "# owner: %d  group: %d\n", acl.Attr.UID, acl.Attr.GID)
	for i, entries := range [][]nfs.NFS3ACLEntry{acl.Access, acl.Default} {
		var mask uint32
		for _, entry := range entries {
			if entry.Tag == nfs.ACLMask {
				mask = entry.Perm
			}
		}
		for _, entry := range entries {
			prefix, who, id := "", "", ""
			if i == 1 {
				prefix = "default:"
			}
			effective := entry.Perm
			switch entry.Tag {
			case nfs.ACLUserObj:
				who = "user"
			case nfs.ACLUser:
				who, id = "user", fmt.Sprint(entry.ID)
				effective &= mask
			case nfs.ACLGroupObj:
				who = "group"
				effective &= mask
			case nfs.ACLGroup:
				who, id = "group", fmt.Sprint(entry.ID)
				effective &= mask
			case nfs.ACLMask:
				who = "mask"
			case nfs.ACLOther:
				who = "other"
			}
			fmt.Fprintf(&out, "%s%s:%s:%s", prefix, who, id, aclPermissions(entry.Perm))
			if effective != entry.Perm {
				fmt.Fprintf(&out, "\t#effective:%s", aclPermissions(effective))
			}
			fmt.Fprintln(&out)
		}
	}
	fmt.Fprintln(&out, "# Masked permissions are not a server access decision.")
	_, err := io.WriteString(w, out.String())
	return err
}

func aclPermissions(perm uint32) string {
	text := []byte("---")
	for i, flag := range []uint32{4, 2, 1} {
		if perm&flag != 0 {
			text[i] = "rwx"[i]
		}
	}
	return string(text)
}
