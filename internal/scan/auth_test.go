package scan

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/nfs"
	"nfsclient/internal/testutil/dnsfixture"
)

func kerberosOptions() Options {
	opts := DefaultOptions()
	opts.Security = "krb5p"
	opts.Kerberos = nfs.KerberosConfig{ConfigFile: "explicit.conf", Principal: "alice@NFS.TEST", Keytab: "explicit.keytab"}
	return opts
}

func TestTargetSPNBindings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		targets  []Target
		mappings []string
		global   string
		want     []string
	}{
		{"single", []Target{{Host: "nfs.example"}}, nil, "nfs/service.example", []string{"nfs/service.example"}},
		{"aliases", []Target{{Host: "NFS.example.", NFSPort: 2049}, {Host: "nfs.example", NFSPort: 2049}}, nil, "nfs/service.example", []string{"nfs/service.example", "nfs/service.example"}},
		{"hosts", []Target{{Host: "one.example."}, {Host: "two.example"}}, []string{"ONE.example=nfs/first.example", "two.example.=nfs/second.example"}, "", []string{"nfs/first.example", "nfs/second.example"}},
		{"ports", []Target{{Host: "nfs.example", NFSPort: 2049}, {Host: "nfs.example", NFSPort: 2050}}, []string{"NFS.example.:2049=nfs/first.example", "nfs.example:2050=nfs/second.example"}, "", []string{"nfs/first.example", "nfs/second.example"}},
		{"ipv6", []Target{{Host: "::1", NFSPort: 2050}}, []string{"[0:0:0:0:0:0:0:1]:2050=nfs/service.example"}, "", []string{"nfs/service.example"}},
		{"duplicates", []Target{{Host: "nfs.example", NFSPort: 2049}}, []string{"nfs.example=nfs/service.example", "NFS.example.=nfs/service.example", "nfs.example:2049=nfs/service.example"}, "", []string{"nfs/service.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := kerberosOptions()
			opts.Kerberos.SPN, opts.TargetSPNs = tc.global, tc.mappings
			got, err := opts.targetSPNs(tc.targets)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("SPN binding = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestTargetSPNDiscoveredLegacyPort(t *testing.T) {
	for _, version := range []string{"", "auto", "2", "3"} {
		t.Run(version, func(t *testing.T) {
			opts := kerberosOptions()
			opts.NFSVersion = version
			targets := []Target{{Host: "nfs.example"}}
			opts.TargetSPNs = []string{"nfs.example:2049=nfs/service.example"}
			if _, err := opts.targetSPNs(targets); err == nil {
				t.Fatal("bound a port-qualified SPN before discovering the legacy NFS port")
			}
			opts.TargetSPNs = []string{"nfs.example=nfs/service.example"}
			if _, err := opts.targetSPNs(targets); err != nil {
				t.Fatal(err)
			}
			opts.TargetSPNs = nil
			opts.Kerberos.SPN = "nfs/service.example"
			if _, err := opts.targetSPNs(targets); err != nil {
				t.Fatal(err)
			}
			if _, err := opts.targetSPNs(append(targets, Target{Host: "nfs.example", NFSPort: 2049})); err == nil {
				t.Fatal("coalesced discovered and explicit endpoints under a single SPN")
			}
			opts.Kerberos.SPN = ""
			opts.TargetSPNs = []string{"nfs.example:2049=nfs/service.example"}
			opts.NFSPort = 2049
			if _, err := opts.targetSPNs(targets); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, version := range []string{"4", "4.0", "4.1", "4.2", "auto"} {
		opts := kerberosOptions()
		opts.NFSVersion = version
		opts.TargetSPNs = []string{"nfs.example:2049=nfs/service.example"}
		target := Target{Host: "nfs.example"}
		if version == "auto" {
			target.DomainRoot = "/.domainroot/example"
		}
		if _, err := opts.targetSPNs([]Target{target}); err != nil {
			t.Fatalf("v4 default port rejected: %s: %v", version, err)
		}
	}
}

func TestKerberosPreflightBeforeAnyTargetNetwork(t *testing.T) {
	dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message { return dnsfixture.Loopback(q) })
	for _, tc := range []struct {
		name    string
		change  func(*Options)
		targets []Target
		want    string
	}{
		{"missing-spn", func(o *Options) {}, nil, "requires --krb5-config"},
		{"shared-spn", func(o *Options) { o.Kerberos.SPN = "nfs/service.example" }, nil, "one target endpoint"},
		{"missing-map", func(o *Options) { o.TargetSPNs = []string{"one.example=nfs/service.example"} }, nil, "missing --target-spn"},
		{"unused-map", func(o *Options) {
			o.TargetSPNs = []string{"one.example=nfs/a", "two.example=nfs/b", "typo.example=nfs/c"}
		}, nil, "does not match"},
		{"duplicate-conflict", func(o *Options) { o.TargetSPNs = []string{"one.example=nfs/a", "ONE.example.=nfs/b"} }, nil, "conflicting"},
		{"overlap-conflict", func(o *Options) { o.TargetSPNs = []string{"one.example=nfs/a", "one.example:2049=nfs/b"} }, []Target{{Host: "one.example", NFSPort: 2049}}, "conflicting"},
		{"unknown-port", func(o *Options) { o.TargetSPNs = []string{"one.example:2049=nfs/a"} }, []Target{{Host: "one.example"}}, "requires --nfs-port"},
		{"ambiguous-host", func(o *Options) { o.TargetSPNs = []string{"one.example=nfs/a"} }, []Target{{Host: "one.example", NFSPort: 2049}, {Host: "one.example", NFSPort: 2050}}, "ambiguous"},
		{"mixed-flags", func(o *Options) { o.Kerberos.SPN = "nfs/a"; o.TargetSPNs = []string{"one.example=nfs/a"} }, nil, "cannot be combined"},
		{"no-credential", func(o *Options) { o.Kerberos.SPN = "nfs/a"; o.Kerberos.Keytab = "" }, nil, "requires --krb5-config"},
		{"two-credentials", func(o *Options) { o.Kerberos.SPN = "nfs/a"; o.Kerberos.Password = "private-value" }, nil, "exactly one"},
		{"sys-credentials", func(o *Options) { o.Security = "sys"; o.Kerberos = nfs.KerberosConfig{Password: "private-value"} }, nil, "require --sec"},
		{"invalid-spn", func(o *Options) { o.TargetSPNs = []string{"one.example=host/a"} }, nil, "SPN must"},
		{"malformed-map", func(o *Options) { o.TargetSPNs = []string{"one.example"} }, nil, "TARGET="},
		{"invalid-port", func(o *Options) { o.TargetSPNs = []string{"one.example:65536=nfs/a"} }, nil, "1..65535"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := kerberosOptions()
			opts.DNS.Server = dns.Address
			tc.change(&opts)
			targets := tc.targets
			if targets == nil {
				targets = []Target{{Host: "one.example"}, {Host: "two.example"}}
			}
			var out bytes.Buffer
			err := RunTargets(context.Background(), targets, opts, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v; want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "private-value") || out.Len() != 0 {
				t.Fatal("leaked credentials or partial report")
			}
		})
	}
	if dns.UDP.Load()+dns.TCP.Load() != 0 {
		t.Fatal("performed DNS before all identity mappings were validated")
	}
}
