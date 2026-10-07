package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"nfsclient/internal/nfs"
	"nfsclient/internal/scan"
)

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
