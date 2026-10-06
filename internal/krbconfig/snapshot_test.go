package krbconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
	client "nfs-viewer/internal/krbclient"
)

func writeProfile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSplitProfileMatchesFlatAuthenticationAndTrust(t *testing.T) {
	dir := t.TempDir()
	parts := filepath.Join(dir, "parts")
	if err := os.Mkdir(parts, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "krb5.conf")
	first := "[realms]\n HOME = {\n kdc = first.test\n }\n[capaths]\n HOME = {\n TARGET = VIA\n }\n"
	second := "[realms]\n HOME = {\n kdc = second.test\n }\n TARGET = {\n kdc = target.test\n }\n[capaths]\n HOME = {\n TARGET = SECOND\n OTHER = .\n }\n"
	writeProfile(t, filepath.Join(parts, "10_base"), first)
	writeProfile(t, filepath.Join(parts, "20_extra.conf"), second)
	writeProfile(t, filepath.Join(parts, ".hidden.conf"), "module bad")
	writeProfile(t, filepath.Join(parts, "ignored.txt"), "module bad")
	prefix := "[libdefaults]\n default_realm = HOME\n dns_lookup_kdc = false\n"
	writeProfile(t, root, prefix+"includedir "+parts+"\n rdns = false\n")
	snapshot, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	flat, err := Normalize(prefix + " rdns = false\n" + first + second)
	if err != nil {
		t.Fatal(err)
	}
	a, err := config.NewFromString(snapshot.Text())
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.NewFromString(flat)
	if err != nil {
		t.Fatal(err)
	}
	pa, err := client.ParseCAPaths(snapshot.Text())
	if err != nil {
		t.Fatal(err)
	}
	pb, err := client.ParseCAPaths(flat)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(pa, pb) || len(a.Realms) != 2 || len(a.Realms[0].KDC) != 2 {
		t.Fatalf("split policy differs:\n%s", snapshot.Text())
	}
	if err := snapshot.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestProfileRefusesAmbiguityAndUnsupportedSyntax(t *testing.T) {
	for _, text := range []string{
		"", "module /dynamic", "include relative", "includedir relative", "key = value",
		"[realms]*\n", "[Realms]\n", "[realms]\n HOME = {\n", "[libdefaults]\n default_realm = HOME\n[libdefaults]\n Default_Realm = OTHER\n",
		"[realms]\n HOME = {\n default_domain = home.test\n }\n[realms]\n HOME = {\n default_domain = other.test\n }\n",
		"[realms]\n HOME = {\n kdc = host\n }*\n", "[libdefaults]\n a = true\n a = {\n b = false\n }\n",
		"[libdefaults]\n a* = true\n", "[libdefaults]\n a = { b = x }\n", "[libdefaults]\n a = \xff\n",
	} {
		t.Run(fmt.Sprintf("case%d", len(text)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			writeProfile(t, path, text)
			if _, err := Load(path); err == nil {
				t.Fatalf("accepted %q", text)
			}
		})
	}
	root := filepath.Join(t.TempDir(), "root")
	child := filepath.Join(filepath.Dir(root), "child")
	writeProfile(t, root, "[libdefaults]\ninclude "+child+"\n")
	writeProfile(t, child, "default_realm = CHILD\n")
	if _, err := Load(root); err == nil {
		t.Fatal("child inherited parent section")
	}
	if _, err := Normalize("include " + child); err == nil {
		t.Fatal("text profile resolved external includes")
	}
}

func TestProfileIncludeBoundsAndReadFailures(t *testing.T) {
	t.Run("cycle", func(t *testing.T) {
		dir := t.TempDir()
		a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		writeProfile(t, a, "include "+b)
		writeProfile(t, b, "include "+a)
		if _, err := Load(a); err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatal(err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i <= MaxDepth+1; i++ {
			body := "[libdefaults]\n"
			if i <= MaxDepth {
				body = "include " + filepath.Join(dir, fmt.Sprint(i+1))
			}
			writeProfile(t, filepath.Join(dir, fmt.Sprint(i)), body)
		}
		if _, err := Load(filepath.Join(dir, "0")); err == nil || !strings.Contains(err.Error(), "depth") {
			t.Fatal(err)
		}
	})
	t.Run("files", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i < MaxFiles; i++ {
			writeProfile(t, filepath.Join(dir, fmt.Sprintf("f%d", i)), "[libdefaults]\n")
		}
		root := filepath.Join(t.TempDir(), "root")
		writeProfile(t, root, "includedir "+dir)
		if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "file count") {
			t.Fatal(err)
		}
	})
	t.Run("total-size", func(t *testing.T) {
		dir := t.TempDir()
		child := filepath.Join(dir, "child")
		root := filepath.Join(dir, "root")
		writeProfile(t, child, strings.Repeat("#x\n", MaxBytes/6))
		writeProfile(t, root, "include "+child+"\n"+strings.Repeat("#x\n", MaxBytes/6))
		if _, err := Load(root); err == nil || !strings.Contains(err.Error(), "1 MiB") {
			t.Fatal(err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "root")
		writeProfile(t, root, strings.Repeat("x", MaxBytes+1))
		if _, err := Load(root); err == nil {
			t.Fatal("oversized accepted")
		}
	})
	for _, kind := range []string{"missing-file", "missing-directory", "directory-as-file"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "root")
			directive := "include " + filepath.Join(dir, "missing")
			if kind == "missing-directory" {
				directive = "includedir " + filepath.Join(dir, "missing")
			}
			if kind == "directory-as-file" {
				directive = "include " + dir
			}
			writeProfile(t, root, directive)
			if _, err := Load(root); err == nil {
				t.Fatal("unreadable input accepted")
			}
		})
	}
}

func TestSnapshotDetectsChangedDependencies(t *testing.T) {
	for _, fault := range []string{"root", "child", "same-metadata", "added-member", "removed-member", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			parts := filepath.Join(dir, "parts")
			if err := os.Mkdir(parts, 0700); err != nil {
				t.Fatal(err)
			}
			root, child := filepath.Join(dir, "root"), filepath.Join(parts, "realm.conf")
			writeProfile(t, root, "includedir "+parts+"\n[libdefaults]\n default_realm = HOME\n")
			writeProfile(t, child, "[realms]\n HOME = {\n kdc = first.test\n }\n")
			snapshot, err := Load(root)
			if err != nil {
				t.Fatal(err)
			}
			saved := snapshot.Text()
			info, err := os.Stat(child)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "root":
				writeProfile(t, root, "[libdefaults]\n default_realm = OTHER\n")
			case "child", "same-metadata":
				writeProfile(t, child, "[realms]\n HOME = {\n kdc = other.test\n }\n")
				if fault == "same-metadata" {
					if err := os.Chtimes(child, info.ModTime(), info.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
			case "added-member":
				writeProfile(t, filepath.Join(parts, "another.conf"), "[realms]\n")
			case "removed-member":
				if err := os.Remove(child); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				tmp := filepath.Join(dir, "replacement")
				data, err := os.ReadFile(child)
				if err != nil {
					t.Fatal(err)
				}
				writeProfile(t, tmp, string(data))
				if err := os.Remove(child); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, child); err != nil {
					t.Fatal(err)
				}
			}
			if err := snapshot.Verify(); !errors.Is(err, ErrChanged) {
				t.Fatalf("change not detected: %v", err)
			}
			if snapshot.Text() != saved {
				t.Fatal("snapshot changed")
			}
			if fault == "child" {
				next, err := Load(root)
				if err != nil {
					t.Fatal(err)
				}
				if next.Fingerprint() == snapshot.Fingerprint() {
					t.Fatal("fingerprint ignored included policy")
				}
			}
		})
	}
}
