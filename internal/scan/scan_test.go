package scan

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"nfsclient/internal/nfs"
)

func TestDiscoveryDeniedOutput(t *testing.T) {
	r := Result{Hosts: []HostResult{{Host: "127.0.0.1", Reachable: true, Identity: "UID 1", Exports: []ExportResult{{DiscoveredExport: nfs.DiscoveredExport{Export: nfs.Export{Path: "/bad\x1b[31m"}, Source: "namespace", Access: "denied"}}}, DiscoveryIssues: []string{"denied\npath"}}}}
	var out bytes.Buffer
	printText(&out, r, DefaultOptions())
	s := out.String()
	if strings.Contains(s, "IP_RESTRICTED") || strings.Contains(s, "ip-restricted") || strings.Contains(s, "\x1b") || !strings.Contains(s, "denied (cause not disclosed)") || !strings.Contains(s, "not advertised") || !strings.Contains(s, "Partial discovery") {
		t.Fatal(s)
	}
}

func TestScanValidation(t *testing.T) {
	for _, mutate := range []func(*Options){func(o *Options) { o.Concurrency = 0 }, func(o *Options) { o.Timeout = 0 }, func(o *Options) { o.Output = "bad" }, func(o *Options) { o.Discovery.MaxDepth = 0 }} {
		o := DefaultOptions()
		mutate(&o)
		if err := Run(context.Background(), nil, o, &bytes.Buffer{}); err == nil {
			t.Fatal("accepted invalid options", o)
		}
	}
}

func TestScanDiscoveryPathsOnlyDefaults(t *testing.T) {
	o := DefaultOptions()
	o.Discovery = nfs.DiscoveryOptions{Paths: []string{"/known"}}
	if err := Run(context.Background(), nil, o, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	o.Discovery.Paths = []string{"relative"}
	if err := Run(context.Background(), nil, o, &bytes.Buffer{}); err == nil {
		t.Fatal("paths discarded while applying discovery defaults")
	}
}

func TestV2ProbeResultsVisibleWithoutAccessOperation(t *testing.T) {
	yes := true
	r := Result{Hosts: []HostResult{{Host: "127.0.0.1", Reachable: true, NFSVersion: "2", DiscoveryComplete: true, Exports: []ExportResult{{DiscoveredExport: nfs.DiscoveredExport{Export: nfs.Export{Path: "/data"}, Source: "mountd", Access: "unknown"}, NoRootSquash: &yes, Escaped: &yes, EscapeMethod: "knfsd_v2"}}}}}
	var out bytes.Buffer
	printText(&out, r, DefaultOptions())
	for _, want := range []string{"NO_ROOT_SQUASH", "ESCAPE(knfsd_v2)", "1 vulnerable"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal(out.String())
		}
	}
}
