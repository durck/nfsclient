package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

// Uses the existing disposable kernel fixture and its independent POSIX ACL
// seeds. This proves native attribute operations and effective user access;
// it does not claim arbitrary Windows ACLs are representable by Linux POSIX.
func TestKernelNFS4ACLManagement(t *testing.T) {
	for _, version := range []string{"4.0", "4.1", "4.2"} {
		t.Run(version, func(t *testing.T) { kernelV4ACLManagement(t, kernelConfig(t, version, "tcp")) })
	}
}

func kernelV4ACLManagement(t *testing.T, cfg nfs.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connect := func(uid uint32) *session.Session {
		config := kernelACLIdentity(t, cfg, uid)
		c, err := nfs.Connect(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		s := session.New(c, config.Host, false, false, nil)
		if err := s.Use(ctx, kernelExport(cfg.Version, "data")); err != nil {
			t.Fatal(err)
		}
		return s
	}
	owner, bob, other := connect(20001), connect(20002), connect(20004)
	local := filepath.Join(t.TempDir(), "source")
	const payload = "native ACL management payload\n"
	if err := os.WriteFile(local, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	remote := fmt.Sprintf("acl/inherit/manage-%d", time.Now().UnixNano())
	if _, err := owner.Put(ctx, local, remote); err != nil {
		t.Fatal(err)
	}
	if err := owner.Chmod(ctx, remote, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sh := &Shell{Session: owner, Out: &out, Err: io.Discard, LocalDir: t.TempDir()}
	owner.AutoUID = true // The ACL commands must override automatic adoption.
	before := owner.Client.Auth
	if _, err := sh.Execute(ctx, "getacl "+remote+" saved.json"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(sh.LocalDir, "saved.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := parseV4ACLJSON(data)
	if err != nil || len(policy.Entries) == 0 {
		t.Fatalf("native ACL: %+v %v", policy, err)
	}
	// Change the file to the fixture's named-user grant, then restore the
	// exported owner-only policy through the command being tested.
	owner.AutoUID = false
	if err := owner.Chmod(ctx, remote, 0640); err != nil {
		t.Fatal(err)
	}
	var allowed bytes.Buffer
	if _, err := bob.Cat(ctx, remote, &allowed); err != nil || allowed.String() != payload {
		t.Fatalf("fixture named grant before ACL set: %v", err)
	}
	owner.AutoUID = true
	if _, err := sh.Execute(ctx, "setacl "+remote+" saved.json"); err != nil {
		t.Fatal(err)
	}
	if !owner.AutoUID || !reflect.DeepEqual(owner.Client.Auth, before) {
		t.Fatal("ACL command adopted a different identity")
	}
	if !strings.Contains(out.String(), "exact readback verified") {
		t.Fatal("missing confirmation")
	}
	out.Reset()
	if _, err := sh.Execute(ctx, "acl "+remote); err != nil {
		t.Fatal(err)
	}
	var got nfs.NFS4ACL
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || !slices.Equal(got.Entries, policy.Entries) {
		t.Fatalf("CLI readback: %v", err)
	}
	if _, err := sh.Execute(ctx, "getacl "+remote+" saved.json"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("export overwrote existing policy: %v", err)
	}
	// Resolve as owner so the negative control reaches SETATTR instead of
	// stopping at the parent directory's independent traversal policy.
	otherNode, _, err := owner.Resolve(ctx, remote, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Client.SetNFS4ACL(ctx, otherNode.Handle, policy); !errors.Is(err, nfs.Status(13)) && !errors.Is(err, nfs.Status(1)) {
		t.Fatalf("unauthorized ACL edit: %v", err)
	}
	var denied bytes.Buffer
	if _, err := other.Cat(ctx, remote, &denied); err == nil || denied.Len() != 0 {
		t.Fatalf("ACL edit exposed payload: %v", err)
	}
	denied.Reset()
	if _, err := bob.Cat(ctx, remote, &denied); err == nil || denied.Len() != 0 {
		t.Fatalf("ACL set failed to revoke named-user read: %v", err)
	}
	owner.AutoUID = false
	var contents bytes.Buffer
	if _, err := owner.Cat(ctx, remote, &contents); err != nil || contents.String() != payload {
		t.Fatalf("ACL edit changed payload: %v %q", err, contents.String())
	}
	// Leave the uniquely named fixture for independent getfacl/stat evidence.
	t.Logf("NATIVE_ACL_MANAGEMENT path=%s version=%s entries=%d fixed_identity=true payload_unchanged=true unauthorized_denied=true named_read_revoked=true", remote, cfg.Version, len(policy.Entries))
}
