package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/resolve"
	"nfsclient/internal/testutil/dnsfixture"
)

func TestEndpointValidationBeforeNetwork(t *testing.T) {
	dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message { return dnsfixture.Loopback(q) })
	for _, target := range []Target{
		{Host: ""}, {Host: "."}, {Host: " "}, {Host: "host", NFSPort: -1},
		{Host: "host", NFSPort: 65536}, {Host: "host", DomainRoot: "relative"},
		{Host: "host", DomainRoot: "/../bad"},
	} {
		o := DefaultOptions()
		o.DNS.Server = dns.Address
		if err := RunTargets(context.Background(), []Target{{Host: "valid.synthetic.invalid"}, target}, o, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid target: %+v", target)
		}
	}
	if dns.UDP.Load()+dns.TCP.Load() != 0 {
		t.Fatal("contacted DNS before validating all targets")
	}
	for _, mutate := range []func(*Options){
		func(o *Options) { o.DNS.Server = "dns.example" },
		func(o *Options) { o.NFSPort = -1 },
		func(o *Options) { o.PortmapPort = 65536 },
		func(o *Options) { o.MountPort = -1 },
		func(o *Options) { o.NFSVersion = "invalid" },
	} {
		o := DefaultOptions()
		mutate(&o)
		if err := o.Validate(); err == nil {
			t.Fatalf("accepted invalid options: %+v", o)
		}
	}
}

func TestDomainRootOptions(t *testing.T) {
	o := DefaultOptions()
	o.NFSPort = 2049
	backing := []string{"/known", "sentinel"}
	o.Discovery.Paths = backing[:1]
	target := Target{Host: "nfs.example.", NFSPort: 2050, DomainRoot: "/example"}
	got, err := targetOptions(target, o)
	if err != nil || got.NFSPort != 2050 || got.NFSVersion != "auto" || !reflect.DeepEqual(got.Discovery.Paths, []string{"/known", "/example"}) {
		t.Fatalf("endpoint options: %+v, %v", got, err)
	}
	if backing[1] != "sentinel" || len(o.Discovery.Paths) != 1 || o.NFSPort != 2049 {
		t.Fatal("modified caller options or path backing array")
	}
	o.Discovery.MaxEntries = 1
	if _, err := targetOptions(target, o); err == nil {
		t.Fatal("domain root exceeded known-path budget")
	}
	o.Discovery.Paths = []string{target.DomainRoot}
	got, err = targetOptions(target, o)
	if err != nil || len(got.Discovery.Paths) != 1 {
		t.Fatalf("duplicate root used an extra path slot: %+v %v", got, err)
	}
	for _, version := range []string{"2", "3"} {
		o.NFSVersion = version
		if _, err := targetOptions(target, o); err == nil {
			t.Fatalf("accepted domain root with NFS%s", version)
		}
	}
	o.NFSVersion = "4.1"
	got, err = targetOptions(target, o)
	if err != nil || got.NFSVersion != "4.1" {
		t.Fatalf("changed explicit version: %+v %v", got, err)
	}
}

func TestRunTargetsDedupAndEndpointOutput(t *testing.T) {
	dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message {
		r := dnsfixture.Loopback(q)
		r.RCode, r.Answers = dnsmessage.RCodeNameError, nil
		return r
	})
	o := DefaultOptions()
	o.Output, o.DNS.Server, o.PortmapPort = "json", dns.Address, 0
	targets := []Target{
		{Host: "NFS.synthetic.invalid.", DomainRoot: "/a"},
		{Host: "nfs.synthetic.invalid", NFSPort: 2049, DomainRoot: "/a"},
		{Host: "nfs.synthetic.invalid", NFSPort: 2050, DomainRoot: "/a"},
		{Host: "nfs.synthetic.invalid", NFSPort: 2050, DomainRoot: "/b"},
	}
	original := append([]Target(nil), targets...)
	var out bytes.Buffer
	if err := RunTargets(context.Background(), targets, o, &out); err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 3 || result.Hosts[0].Host != targets[0].Host || result.Hosts[1].NFSPort != 2050 || result.Hosts[2].DomainRoot != "/b" {
		t.Fatalf("incorrect deduplication/output: %s", out.String())
	}
	if !reflect.DeepEqual(original, targets) {
		t.Fatal("mutated targets")
	}
	result.Hosts[1].Reachable = true
	out.Reset()
	printText(&out, result, o)
	if !strings.Contains(out.String(), "[nfs.synthetic.invalid:2050]") {
		t.Fatal(out.String())
	}
}

func TestTCPProbeCustomDNS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, tcp := range []bool{false, true} {
		dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message { return dnsfixture.Loopback(q) })
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, err := resolve.New(ctx, resolve.Config{Server: dns.Address, TCP: tcp})
		if err != nil {
			t.Fatal(err)
		}
		if !tcpProbe(ctx, r, "nfs.synthetic.invalid.", listener.Addr().(*net.TCPAddr).Port) {
			t.Fatal("probe failed with custom DNS")
		}
		cancel()
		if tcp && (dns.UDP.Load() != 0 || dns.TCP.Load() == 0) || !tcp && (dns.TCP.Load() != 0 || dns.UDP.Load() == 0) {
			t.Fatalf("wrong DNS transport: UDP=%d TCP=%d", dns.UDP.Load(), dns.TCP.Load())
		}
	}
}

func TestScanProbeDeadlineAndCancellation(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		dns := dnsfixture.Start(t, func(_ string, _ dnsmessage.Message) *dnsmessage.Message { return nil })
		o := DefaultOptions()
		o.DNS = resolve.Config{Server: dns.Address, TCP: tcp}
		o.Timeout = 100 * time.Millisecond
		start := time.Now()
		result := probeHost(context.Background(), "nfs.synthetic.invalid.", o)
		if result.Reachable || time.Since(start) > 400*time.Millisecond {
			t.Fatalf("probe exceeded 100ms budget: %v %+v", time.Since(start), result)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		o.Timeout, o.Concurrency = time.Second, 1
		start = time.Now()
		err := Run(ctx, []string{"one.invalid.", "two.invalid."}, o, &bytes.Buffer{})
		if !errors.Is(err, context.Canceled) || time.Since(start) > 400*time.Millisecond {
			t.Fatalf("cancellation stalled: %v %v", time.Since(start), err)
		}
	}
}
