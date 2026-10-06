package gssapi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"nfs-viewer/internal/krbconfig"
)

func TestInitiatorFileSnapshotPreservesRealmsAndTrust(t *testing.T) {
	dir := t.TempDir()
	root, child := filepath.Join(dir, "root"), filepath.Join(dir, "child")
	texts := map[string]string{
		root:  "[libdefaults]\n default_realm = HOME\n[realms]\n HOME = {\n kdc = home.test\n }\ninclude " + child + "\n[capaths]\n HOME = {\n TARGET = .\n }\n",
		child: "[realms]\n TARGET = {\n kdc = target.test\n }\n[capaths]\n TARGET = {\n HOME = .\n }\n",
	}
	for name, text := range texts {
		if err := os.WriteFile(name, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := krbconfig.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var initiator Initiator
	if err := WithConfigSnapshot(snapshot)(&initiator); err != nil {
		t.Fatal(err)
	}
	cfg, paths, err := initiator.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Realms) != 2 || cfg.Realms[0].Realm != "HOME" || cfg.Realms[1].Realm != "TARGET" || paths == nil {
		t.Fatalf("split policy was discarded: %+v %v", cfg, paths)
	}
	if err := os.WriteFile(child, []byte("[realms]\n OTHER = {\n kdc = changed.test\n }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := initiator.loadConfig(); !errors.Is(err, krbconfig.ErrChanged) {
		t.Fatalf("load adopted changed policy: %v", err)
	}
	if _, err := NewInitiator(WithConfigSnapshot(snapshot), WithCCache("must-not-open")); !errors.Is(err, krbconfig.ErrChanged) {
		t.Fatalf("credentials reached before changed-policy check: %v", err)
	}
	if _, _, err := initiator.Initiate("nfs/target.test", 0, nil); !errors.Is(err, krbconfig.ErrChanged) {
		t.Fatalf("ticket request reached before changed-policy check: %v", err)
	}
}
