package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
)

func TestRootSelectionAndVerification(t *testing.T) {
	sh, dir, out := testShell(t)
	ctx := context.Background()
	sess := sh.Session
	if err := os.MkdirAll(filepath.Join(dir, "share", "inside"), 0755); err != nil {
		t.Fatal(err)
	}
	original, err := sess.Client.Lookup(ctx, sess.Root.Handle, "share")
	if err != nil {
		t.Fatal(err)
	}
	// Model a discovered parent using only real handles issued by this fixture.
	// This verifies root-state transitions, not Linux handle-guessing success.
	candidate := sess.Root
	sess.ExportRoot = original
	sess.Export = "/share"
	sess.DiscoveredRoot = &candidate
	sess.Escaped = true
	sess.CWD = "/share/inside"
	sess.AutoEscape = true
	beforeRoot, beforeAuth := sess.Root, sess.Client.Auth
	if _, err := sh.Execute(ctx, "root verify"); err != nil {
		t.Fatal(err)
	}
	if sess.CWD != "/share/inside" || !reflect.DeepEqual(sess.Root, beforeRoot) || !reflect.DeepEqual(sess.Client.Auth, beforeAuth) {
		t.Fatal("verification changed navigation or identity")
	}
	if !strings.Contains(out.String(), "Unverified; requires independent server-side confirmation") || sess.RootVerification == nil {
		t.Fatalf("missing evidence: %s", out.String())
	}
	out.Reset()
	if _, err := sh.Execute(ctx, "root reset"); err != nil {
		t.Fatal(err)
	}
	if sess.Escaped || sess.CWD != "/" || !bytes.Equal(sess.Root.Handle, original.Handle) || sess.RootVerification != nil {
		t.Fatal("reset did not restore export root")
	}
	if !sess.AutoEscape {
		t.Fatal("reset silently changed the future auto-escape preference")
	}
	if entries, err := sess.LS(ctx, "."); err != nil || len(entries) != 1 || entries[0].Name != "inside" {
		t.Fatalf("reset listing: %+v %v", entries, err)
	}
	if _, err := sh.Execute(ctx, "root discovered"); err != nil {
		t.Fatal(err)
	}
	if !sess.Escaped || !bytes.Equal(sess.Root.Handle, candidate.Handle) {
		t.Fatal("saved discovery was not selected")
	}
	if _, err := sh.Execute(ctx, "root info"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "filesystem candidate") || !strings.Contains(out.String(), "Discovered directory") {
		t.Fatal(out.String())
	}
	if err := sess.Use(ctx, "/"); err != nil {
		t.Fatal(err)
	}
	if sess.DiscoveredRoot != nil || sess.RootVerification != nil {
		t.Fatal("export change retained stale evidence")
	}
}

func TestRootFailedSwitchPreservesState(t *testing.T) {
	sh, _, _ := testShell(t)
	sess := sh.Session
	ctx := context.Background()
	if _, err := sh.Execute(ctx, "root discovered"); err == nil {
		t.Fatal("missing candidate accepted")
	}
	file, err := sess.Client.Create(ctx, sess.Root.Handle, "not-a-directory", 0644, false)
	if err != nil {
		t.Fatal(err)
	}
	sess.DiscoveredRoot = &file
	sess.Client.Auth = nfs.Auth{UID: 123, GID: 456, Groups: []uint32{789}}
	sess.CWD = "/keep"
	oldRoot, oldAuth := sess.Root, sess.Client.Auth
	if _, err := sh.Execute(ctx, "root discovered"); err == nil {
		t.Fatal("regular file accepted as root")
	}
	if sess.CWD != "/keep" || !reflect.DeepEqual(sess.Root, oldRoot) || !reflect.DeepEqual(sess.Client.Auth, oldAuth) {
		t.Fatal("failed selection changed session state")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := sh.Execute(canceled, "root reset"); err == nil {
		t.Fatal("cancellation ignored")
	}
	if !reflect.DeepEqual(sess.Client.Auth, oldAuth) {
		t.Fatal("canceled reset changed identity")
	}
	if _, err := sh.Execute(ctx, "root unknown"); err == nil {
		t.Fatal("unknown root action accepted")
	}
	if _, err := sh.Execute(ctx, "root verify extra"); err == nil {
		t.Fatal("extra argument accepted")
	}
}

func TestRootCompletionAndHelp(t *testing.T) {
	sh, _, out := testShell(t)
	if err := sh.printHelp(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "root info|verify|reset") {
		t.Fatal("root commands absent from help")
	}
	c := completer{shell: sh, ctx: context.Background()}
	line := []rune("root v")
	matches, _ := c.Do(line, len(line))
	if len(matches) != 1 || string(matches[0]) != "erify " {
		t.Fatalf("completion: %q", matches)
	}
}
