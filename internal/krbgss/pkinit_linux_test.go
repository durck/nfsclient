//go:build linux

package gssapi

import (
	stdcontext "context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPKINITHelperIsolation(t *testing.T) {
	for _, mode := range []string{"success", "failure", "missing-record", "large-record", "wrong-principal", "malformed-result", "missing-result", "cancel", "helper-writable", "armor-readable", "keytab-readable", "helper-symlink", "armor-symlink", "helper-change"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			parent := filepath.Join(dir, "temporary")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", parent)
			t.Setenv("KRB5_TRACE", "must-not-inherit")
			t.Setenv("KRB5_CLIENT_KTNAME", "must-not-inherit")
			helper, armor, keytab, fixture, marker := filepath.Join(dir, "helper"), filepath.Join(dir, "armor"), filepath.Join(dir, "keytab"), filepath.Join(dir, "fixture"), filepath.Join(dir, "called")
			realm := "NFS.TEST"
			if mode == "foreign-armor-realm" {
				realm = "OTHER.TEST"
			}
			if err := os.WriteFile(armor, nativeASFixtureCache(t, "root", realm, mode == "expired-armor"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keytab, []byte("synthetic helper-fixture keytab input"), 0600); err != nil {
				t.Fatal(err)
			}
			name := "root"
			if mode == "wrong-principal" {
				name = "bob"
			}
			result := nativeASFixtureCache(t, name, "NFS.TEST", false)
			if mode == "malformed-result" {
				result = []byte{0}
			}
			if err := os.WriteFile(fixture, result, 0600); err != nil {
				t.Fatal(err)
			}
			script := "#!/bin/sh\nset -eu\n[ \"$#\" -eq 16 ]\n[ \"$KRB5_CONFIG\" = \"$HOME/krb5.conf\" ]\n[ -z \"${KRB5_TRACE+x}\" ]\n[ -z \"${KRB5_CLIENT_KTNAME+x}\" ]\n[ \"${8#FILE:}\" != " + shellFixtureQuote(keytab) + " ]\n[ \"${10#FILE:}\" != " + shellFixtureQuote(armor) + " ]\nprintf called > " + shellFixtureQuote(marker) + "\numask 077\n"
			if mode == "failure" {
				script += "printf 'synthetic-secret-must-not-leak' >&2\nexit 1\n"
			} else if mode == "cancel" {
				script += "exec sleep 5\n"
			} else {
				if mode != "missing-result" {
					script += "cp " + shellFixtureQuote(fixture) + " \"${16#FILE:}\"\n"
				}
				switch mode {
				case "missing-record":
					script += "printf 'synthetic-secret-must-not-leak'\n"
				case "large-record":
					script += "printf '%0100d' 1\n"
				case "helper-change":
					script += "printf '# changed' >> " + shellFixtureQuote(helper) + "\nprintf 'nfs-viewer-as-helper/1 pkinit-required\\n'\n"
				default:
					script += "printf 'nfs-viewer-as-helper/1 pkinit-required\\n'\n"
				}
			}
			if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "helper-writable":
				os.Chmod(helper, 0770)
			case "armor-readable":
				os.Chmod(armor, 0644)
			case "keytab-readable":
				os.Chmod(keytab, 0644)
			case "helper-symlink":
				alias := helper + "-link"
				if err := os.Symlink(helper, alias); err != nil {
					t.Fatal(err)
				}
				helper = alias
			case "armor-symlink":
				alias := armor + "-link"
				if err := os.Symlink(armor, alias); err != nil {
					t.Fatal(err)
				}
				armor = alias
			}
			ctx, cancel := stdcontext.WithTimeout(stdcontext.Background(), time.Second)
			defer cancel()
			if mode == "cancel" {
				time.AfterFunc(50*time.Millisecond, cancel)
			}
			cache, err := runPKINIT(ctx, helper, "root@NFS.TEST", "[libdefaults]\n default_realm = NFS.TEST\n", PKINITFiles{Cert: keytab, Key: armor, CA: keytab})
			if (err == nil) != (mode == "success") {
				t.Fatal("incorrect native helper result", err)
			}
			if cache != nil {
				clearNativeCache(cache)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("helper output leaked")
			}
			if mode == "cancel" && !strings.Contains(err.Error(), "context canceled") {
				t.Fatal("cancellation lost", err)
			}
			files, err := os.ReadDir(parent)
			if err != nil || len(files) != 0 {
				t.Fatal("private temporary credentials retained", err)
			}
			if strings.Contains(mode, "symlink") || mode == "helper-writable" || mode == "armor-readable" || mode == "keytab-readable" || mode == "expired-armor" || mode == "foreign-armor-realm" {
				if _, err := os.Stat(marker); err == nil {
					t.Fatal("unsafe input launched helper")
				}
			}
		})
	}
}
