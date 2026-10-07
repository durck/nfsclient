package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"nfsclient/internal/nfs"
	"nfsclient/internal/scan"
)

func TestLoadPathsFileFormats(t *testing.T) {
	for _, bom := range []string{"", "\ufeff"} {
		file := filepath.Join(t.TempDir(), "paths.txt")
		if err := os.WriteFile(file, []byte(bom+"# comment\r\n\r\n /hidden/name \r\n/with space\r\n/hash#literal\n"), 0600); err != nil {
			t.Fatal(err)
		}
		o := nfs.DefaultDiscoveryOptions()
		o.Paths = []string{"/explicit"}
		o.MaxEntries = 4
		if err := loadPathsFile(file, &o); err != nil {
			t.Fatal(err)
		}
		if want := []string{"/explicit", "/hidden/name", "/with space", "/hash#literal"}; !reflect.DeepEqual(o.Paths, want) {
			t.Fatalf("paths = %q, want %q", o.Paths, want)
		}
	}
}

func TestLoadPathsFileRejectsTransactionally(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"relative", "/valid\nrelative\n", "line 2"},
		{"nul", "/valid\n/bad\x00path\n", "line 2"},
		{"parent", "/valid\n/../escape\n", "line 2"},
		{"long-path", "/valid\n/" + strings.Repeat("x", 4096) + "\n", "line 2"},
		{"deep-path", "/valid\n/" + strings.Repeat("a/", 65) + "\n", "line 2"},
		{"merged-limit", "/valid\n/second\n/over-limit\n", "line 3"},
		{"duplicate-limit", "/valid\n/valid\n/valid\n", "line 3"},
		{"scanner", "/valid\n#" + strings.Repeat("x", 70*1024), "line 2"},
		{"comment-budget", strings.Repeat("# comment\n", 2*1024*1024), "byte limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "paths.txt")
			if err := os.WriteFile(file, []byte(tc.input), 0600); err != nil {
				t.Fatal(err)
			}
			o := nfs.DefaultDiscoveryOptions()
			o.MaxEntries, o.Paths = 3, []string{"/explicit"}
			err := loadPathsFile(file, &o)
			if err == nil || !strings.Contains(err.Error(), file) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v; want filename and %q", err, tc.want)
			}
			if !reflect.DeepEqual(o.Paths, []string{"/explicit"}) {
				t.Fatalf("failed load changed paths: %q", o.Paths)
			}
		})
	}
}

func TestLoadPathsFileErrors(t *testing.T) {
	dir := t.TempDir()
	for _, file := range []string{filepath.Join(dir, "missing.txt"), dir} {
		o := nfs.DefaultDiscoveryOptions()
		if err := loadPathsFile(file, &o); err == nil || !strings.Contains(err.Error(), file) {
			t.Fatalf("load %q: %v", file, err)
		}
	}
	file := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, -1, 100001} {
		o := nfs.DefaultDiscoveryOptions()
		o.MaxEntries = limit
		if err := loadPathsFile(file, &o); err == nil {
			t.Fatalf("accepted max-entries %d", limit)
		}
	}
	o := nfs.DefaultDiscoveryOptions()
	o.Paths = []string{"relative"}
	if err := loadPathsFile(file, &o); err == nil {
		t.Fatal("accepted invalid explicit path")
	}
	o.Paths = []string{"/first", "/second"}
	o.MaxEntries = 1
	if err := loadPathsFile(file, &o); err == nil {
		t.Fatal("accepted explicit paths exceeding budget")
	}
}

func TestLoadPathsFileByteBoundary(t *testing.T) {
	file := filepath.Join(t.TempDir(), "paths.txt")
	// Short comment lines reach the byte limit without reaching the line limit.
	input := strings.Repeat("#"+strings.Repeat("x", 1022)+"\n", 16*1024)
	for _, extra := range []string{"", "#"} {
		if err := os.WriteFile(file, []byte(input+extra), 0600); err != nil {
			t.Fatal(err)
		}
		o := nfs.DefaultDiscoveryOptions()
		o.Paths = []string{"/explicit"}
		err := loadPathsFile(file, &o)
		if extra == "" && err != nil || extra != "" && (err == nil || !strings.Contains(err.Error(), "byte limit")) {
			t.Fatalf("%d bytes: %v", len(input+extra), err)
		}
		if !reflect.DeepEqual(o.Paths, []string{"/explicit"}) {
			t.Fatalf("comment-only input changed paths: %q", o.Paths)
		}
	}
}

func TestExportsPathsFileUsesLocalDir(t *testing.T) {
	sh, _, out := testShell(t)
	dir := t.TempDir()
	if _, err := sh.Execute(context.Background(), "lcd \""+dir+"\""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "paths.txt"), []byte("/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"paths.txt", filepath.Join(dir, "paths.txt")} {
		out.Reset()
		if _, err := sh.Execute(context.Background(), "exports --paths-file \""+file+"\" --json"); err != nil {
			t.Fatal(err)
		}
		var report nfs.DiscoveryReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Entries) == 0 {
			t.Fatalf("report %s: %v", out, err)
		}
	}
}

func TestExportsPathsFileHelp(t *testing.T) {
	for _, command := range []string{"help exports", "exports --help"} {
		var out bytes.Buffer
		sh := &Shell{Out: &out}
		if _, err := sh.Execute(context.Background(), command); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "--paths-file") || !strings.Contains(out.String(), "lcd") {
			t.Fatalf("missing paths-file usage and local directory semantics: %s", &out)
		}
	}
}

func TestExportsDiscoveryPreservesSession(t *testing.T) {
	sh, _, out := testShell(t)
	s := sh.Session
	root, export, cwd, auth := s.Root, s.Export, s.CWD, s.Client.Auth
	for _, line := range []string{"exports", "exports --recursive --depth 5 --max-entries 10 --discovery-timeout 1s --json", "exports --path / --path /hidden/name --json"} {
		out.Reset()
		if _, err := sh.Execute(context.Background(), line); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(line, "--json") {
			var report nfs.DiscoveryReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Identity == "" {
				t.Fatalf("%s %v", out.String(), err)
			}
		} else if !strings.Contains(out.String(), "Identity:") {
			t.Fatal(out.String())
		}
		if !reflect.DeepEqual(root, s.Root) || export != s.Export || cwd != s.CWD || !reflect.DeepEqual(auth, s.Client.Auth) {
			t.Fatal("exports changed session")
		}
		if _, err := s.LS(context.Background(), "."); err != nil {
			t.Fatal("session unusable", err)
		}
	}
	for _, line := range []string{"exports extra", "exports --depth 0", "exports --max-entries 0", "exports --discovery-timeout 0s", "exports --unknown"} {
		if _, err := sh.Execute(context.Background(), line); err == nil {
			t.Fatal("accepted", line)
		}
	}
}

func TestDiscoveryRepeatedPathFlagsPreserveCommas(t *testing.T) {
	o := nfs.DefaultDiscoveryOptions()
	var recursive bool
	f := pflag.NewFlagSet("test", pflag.ContinueOnError)
	discoveryFlags(f, &o, &recursive)
	if err := f.Parse([]string{"--path", "/a,b", "--path", "/space name"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(o.Paths, []string{"/a,b", "/space name"}) {
		t.Fatal(o.Paths)
	}
}

func TestScanDiscoveryExplicitPorts(t *testing.T) {
	_, port := testServer(t)
	var out bytes.Buffer
	cmd := newScanCommand(&out)
	cmd.SetArgs([]string{"127.0.0.1", "--nfs-version", "3", "--nfs-port", fmt.Sprint(port), "--mount-port", fmt.Sprint(port), "--portmap-port", "0", "--no-squash-check", "--no-escape-check", "--output", "json", "--recursive"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var report scan.Result
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Hosts) != 1 || !report.Hosts[0].Reachable || report.Hosts[0].Identity == "" || report.Hosts[0].NFSVersion != "3" {
		t.Fatal(out.String())
	}
}
