package nfs

import (
	"nfs-viewer/internal/iscsi"
	"nfs-viewer/internal/testiscsi"
	"os"
	"path/filepath"
	"testing"
)

func TestStoragePolicyApprovalAndRecoveryBinding(t *testing.T) {
	target := "iscsi://127.0.0.1:3260/" + testiscsi.Name + "/0"
	policy := iscsi.Security{AuthMethod: "chap", Username: "approved", SecretFile: filepath.Join(t.TempDir(), "secret"), HeaderDigest: "crc32c", DataDigest: "crc32c"}
	o := PNFSOptions{Layout: "block", BlockTargets: []string{target}, BlockInitiator: testiscsi.Initiator, BlockSecurity: map[string]iscsi.Security{target: policy}}
	validated, err := validatePNFSOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	o.BlockSecurity[target] = iscsi.Security{}
	if validated.BlockSecurity[target] != policy {
		t.Fatal("caller policy map retained")
	}
	c := &Client{}
	original := c.blockRecoveryProfile(validated)
	for _, change := range []func(*iscsi.Security){func(p *iscsi.Security) { p.AuthMethod = "none"; p.Username = ""; p.SecretFile = "" }, func(p *iscsi.Security) { p.Username = "other" }, func(p *iscsi.Security) { p.HeaderDigest = "none" }, func(p *iscsi.Security) { p.DataDigest = "none" }} {
		changed := policy
		change(&changed)
		validated.BlockSecurity[target] = changed
		if c.blockRecoveryProfile(validated) == original {
			t.Fatal("changed policy preserved recovery identity")
		}
	}
	validated.BlockSecurity[target] = policy
	for _, data := range []string{"initial-raw-secret", "replacement-secret"} {
		if err := os.WriteFile(policy.SecretFile, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if c.blockRecoveryProfile(validated) != original {
			t.Fatal("recovery evidence depends on secret bytes")
		}
	}
	for _, mode := range []string{"unapproved", "file", "object", "osd-on-block", "bad-digest"} {
		bad := validated
		bad.BlockSecurity = map[string]iscsi.Security{target: policy}
		switch mode {
		case "unapproved":
			bad.BlockSecurity = map[string]iscsi.Security{target + "1": policy}
		case "file":
			bad.Layout = "file"
		case "object":
			bad.Layout = "object"
		case "osd-on-block":
			bad.OSDSecurity = bad.BlockSecurity
		case "bad-digest":
			p := policy
			p.HeaderDigest = "automatic"
			bad.BlockSecurity[target] = p
		}
		if _, err := validatePNFSOptions(bad); err == nil {
			t.Fatalf("unsafe policy accepted: %s", mode)
		}
	}
	object := PNFSOptions{Layout: "object", OSDTargets: []string{target}, OSDInitiator: testiscsi.Initiator, OSDSecurity: map[string]iscsi.Security{target: policy}}
	if _, err := validatePNFSOptions(object); err != nil {
		t.Fatal(err)
	}
	object.OSDSecurity = map[string]iscsi.Security{target + "1": policy}
	if _, err := validatePNFSOptions(object); err == nil {
		t.Fatal("unapproved OSD policy accepted")
	}
}
