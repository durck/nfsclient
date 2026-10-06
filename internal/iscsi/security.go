package iscsi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Security is an explicit policy for one approved target. Secret files contain
// raw bytes (12..1024 bytes, without implicit newline trimming). Policy values
// contain no secret material and may be bound into recovery evidence.
type Security struct {
	AuthMethod       string `json:"auth_method"`
	Username         string `json:"username,omitempty"`
	SecretFile       string `json:"secret_file,omitempty"`
	TargetUsername   string `json:"target_username,omitempty"`
	TargetSecretFile string `json:"target_secret_file,omitempty"`
	HeaderDigest     string `json:"header_digest"`
	DataDigest       string `json:"data_digest"`
}

func (s Security) Validate() error {
	if s.AuthMethod != "" && s.AuthMethod != "none" && s.AuthMethod != "chap" && s.AuthMethod != "mutual-chap" {
		return errors.New("unsupported iSCSI authentication policy")
	}
	for _, d := range []string{s.HeaderDigest, s.DataDigest} {
		if d != "" && d != "none" && d != "crc32c" {
			return errors.New("unsupported iSCSI digest policy")
		}
	}
	if s.AuthMethod == "" || s.AuthMethod == "none" {
		if s.Username != "" || s.SecretFile != "" || s.TargetUsername != "" || s.TargetSecretFile != "" {
			return errors.New("iSCSI credentials require explicit CHAP policy")
		}
		return nil
	}
	if !validCHAPName(s.Username) || !filepath.IsAbs(s.SecretFile) {
		return errors.New("CHAP requires an identity and absolute secret-file path")
	}
	if s.AuthMethod == "mutual-chap" {
		if !validCHAPName(s.TargetUsername) || s.Username == s.TargetUsername || !filepath.IsAbs(s.TargetSecretFile) || filepath.Clean(s.SecretFile) == filepath.Clean(s.TargetSecretFile) {
			return errors.New("mutual CHAP requires distinct identities and secret files")
		}
	} else if s.TargetUsername != "" || s.TargetSecretFile != "" {
		return errors.New("target credentials require mutual CHAP")
	}
	return nil
}

func validCHAPName(s string) bool {
	if len(s) == 0 || len(s) > 223 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 || c == '=' || c == ',' {
			return false
		}
	}
	return true
}

// LoadSecurity reads a bounded policy file; duplicate, unknown, null and
// case-variant fields are refused. Secrets are never embedded in this format.
func LoadSecurity(path string) (Security, error) {
	var s Security
	if !filepath.IsAbs(path) {
		return s, errors.New("iSCSI security profile requires an absolute path")
	}
	b, err := readPolicyFile(path, 16384)
	if err != nil {
		return s, errors.New("cannot read iSCSI security profile")
	}
	defer clear(b)
	d := json.NewDecoder(bytes.NewReader(b))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return s, errors.New("invalid iSCSI security profile")
	}
	fields := map[string]*string{"auth_method": &s.AuthMethod, "username": &s.Username, "secret_file": &s.SecretFile, "target_username": &s.TargetUsername, "target_secret_file": &s.TargetSecretFile, "header_digest": &s.HeaderDigest, "data_digest": &s.DataDigest}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return s, errors.New("invalid iSCSI security profile")
		}
		k, ok := t.(string)
		dest := fields[k]
		if !ok || dest == nil || seen[k] {
			return s, errors.New("unknown or duplicate iSCSI security field")
		}
		seen[k] = true
		var value *string
		if err = d.Decode(&value); err != nil || value == nil {
			return s, errors.New("iSCSI security fields must be strings")
		}
		*dest = *value
	}
	if _, err = d.Token(); err != nil {
		return s, errors.New("invalid iSCSI security profile")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return s, errors.New("trailing iSCSI security profile data")
	}
	for _, k := range []string{"auth_method", "header_digest", "data_digest"} {
		if !seen[k] || *fields[k] == "" {
			return s, errors.New("iSCSI security profile must explicitly select authentication and digests")
		}
	}
	return s, s.Validate()
}

func readPolicyFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid policy file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("policy file changed")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		clear(b)
		return nil, errors.New("policy file exceeds bound")
	}
	return b, nil
}

func (s Security) secrets() (a, b []byte, err error) {
	if err = s.Validate(); err != nil {
		return
	}
	if s.AuthMethod == "" || s.AuthMethod == "none" {
		return
	}
	a, err = readPolicyFile(s.SecretFile, 1024)
	if err != nil || len(a) < 12 {
		clear(a)
		return nil, nil, errors.New("CHAP secret must be a readable regular file containing 12..1024 raw bytes")
	}
	if s.AuthMethod == "mutual-chap" {
		b, err = readPolicyFile(s.TargetSecretFile, 1024)
		if err != nil || len(b) < 12 || bytes.Equal(a, b) {
			clear(a)
			clear(b)
			return nil, nil, errors.New("mutual CHAP requires readable distinct 12..1024-byte secrets")
		}
	}
	return
}

func digestName(s string) string {
	if s == "crc32c" {
		return "CRC32C"
	}
	return "None"
}
