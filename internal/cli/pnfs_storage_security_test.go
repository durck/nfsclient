package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"nfs-viewer/internal/iscsi"
	"nfs-viewer/internal/testiscsi"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func secureStorageFixture(t *testing.T, enabled bool) (iscsi.Security, testiscsi.Options, string) {
	t.Helper()
	if !enabled {
		return iscsi.Security{}, testiscsi.Options{}, ""
	}
	dir := t.TempDir()
	s := iscsi.Security{AuthMethod: "mutual-chap", Username: "initiator", TargetUsername: "target", SecretFile: filepath.Join(dir, "initiator.secret"), TargetSecretFile: filepath.Join(dir, "target.secret"), HeaderDigest: "crc32c", DataDigest: "crc32c"}
	a, b := []byte("cli-initiator-unique-secret"), []byte("cli-target-distinct-secret")
	for path, data := range map[string][]byte{s.SecretFile: a, s.TargetSecretFile: b} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	profile := filepath.Join(dir, "profile.json")
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(profile, data, 0600); err != nil {
		t.Fatal(err)
	}
	return s, testiscsi.Options{CHAPUsername: s.Username, CHAPSecret: a, TargetUsername: s.TargetUsername, TargetSecret: b, HeaderDigest: true, DataDigest: true}, profile
}
func storagePolicies(target string, s iscsi.Security) map[string]iscsi.Security {
	return map[string]iscsi.Security{target: s}
}

func TestSecureISCSIBlockCLI(t *testing.T) {
	for _, minor := range []uint32{1, 2} {
		for _, mode := range []string{"api", "cli"} {
			t.Run(fmt.Sprintf("read/4.%d/%s", minor, mode), func(t *testing.T) { runBlockDownloadPublication(t, minor, "secure-iscsi-"+mode) })
			t.Run(fmt.Sprintf("write/4.%d/%s", minor, mode), func(t *testing.T) { runBlockUploadFlow(t, minor, "secure-iscsi-"+mode, false) })
		}
	}
}

func TestISCSISecurityCLIArguments(t *testing.T) {
	_, _, profile := secureStorageFixture(t, true)
	for _, args := range []string{"--block-security", "--osd-security", "--block-security missing", "--block-security a=" + strconv.Quote(profile) + " --block-security a=" + strconv.Quote(profile), "--osd-security a=" + strconv.Quote(profile)} {
		if _, err := (&Shell{Out: io.Discard, Err: io.Discard}).Execute(context.Background(), "putpnfs a b --layout block "+args); err == nil {
			t.Fatal("invalid policy arguments accepted")
		}
	}
}
