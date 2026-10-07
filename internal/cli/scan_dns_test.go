package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"nfsclient/internal/scan"
	"nfsclient/internal/testutil/dnsfixture"
)

func scanDNSFixture(t *testing.T, records ...dnsmessage.SRVResource) *dnsfixture.Server {
	t.Helper()
	return dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message {
		r := dnsfixture.Loopback(q)
		if len(q.Questions) == 1 && q.Questions[0].Type == dnsmessage.TypeSRV {
			if q.Questions[0].Name.String() != "_nfs-domainroot._tcp.scan.invalid." {
				t.Errorf("unexpected SRV query %s", q.Questions[0].Name)
			}
			for _, record := range records {
				r.Answers = append(r.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET}, Body: &record})
			}
		}
		return r
	})
}

func TestScanSRVEndpoints(t *testing.T) {
	dns := scanDNSFixture(t,
		dnsmessage.SRVResource{Target: dnsmessage.MustNewName("one.scan.invalid."), Port: 2049},
		dnsmessage.SRVResource{Target: dnsmessage.MustNewName("two.scan.invalid."), Port: 18204, Priority: 1},
	)
	targets, err := lookupNFSSRVTargets(context.Background(), "SCAN.INVALID.", dns.Address)
	want := []scan.Target{{Host: "one.scan.invalid.", NFSPort: 2049, DomainRoot: "/.domainroot/scan.invalid"}, {Host: "two.scan.invalid.", NFSPort: 18204, DomainRoot: "/.domainroot/scan.invalid"}}
	if err != nil || !reflect.DeepEqual(targets, want) {
		t.Fatalf("targets=%+v error=%v", targets, err)
	}
}

func TestScanSRVUnavailableAndInvalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []dnsmessage.SRVResource
	}{
		{"empty", nil},
		{"unavailable", []dnsmessage.SRVResource{{Target: dnsmessage.MustNewName(".")}}},
		{"zero-port", []dnsmessage.SRVResource{{Target: dnsmessage.MustNewName("nfs.scan.invalid.")}}},
		{"invalid-host", []dnsmessage.SRVResource{{Target: dnsmessage.MustNewName("bad_name.scan.invalid."), Port: 2049}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns := scanDNSFixture(t, tc.records...)
			if targets, err := lookupNFSSRVTargets(context.Background(), "scan.invalid", dns.Address); err == nil || len(targets) != 0 {
				t.Fatalf("invalid service accepted: %+v %v", targets, err)
			}
		})
	}
}

func TestScanDNSDomainValidation(t *testing.T) {
	for _, name := range []string{"", ".", "host..invalid", "-bad.invalid", "bad-.invalid", "bad/name", "name:2049", "127.0.0.1", " with-space", "a_underscore", strings.Repeat("x", 64) + ".invalid"} {
		if _, err := lookupNFSSRVTargets(context.Background(), name, "invalid DNS endpoint"); err == nil || !strings.Contains(err.Error(), "domain name") {
			t.Errorf("invalid domain %q: %v", name, err)
		}
	}
}

func TestScanDNSDeadlineAndEarlyValidation(t *testing.T) {
	dns := dnsfixture.Start(t, func(_ string, _ dnsmessage.Message) *dnsmessage.Message { return nil })
	for _, extra := range [][]string{{"--timeout", "0s"}, {"--concurrency", "0"}, {"--nfs-version", "3"}, {"--output", "invalid"}, {"--path", "relative"}} {
		cmd := newScanCommand(&bytes.Buffer{})
		cmd.SetArgs(append([]string{"--dns-domain", "scan.invalid", "--dns-server", dns.Address}, extra...))
		if err := cmd.Execute(); err == nil {
			t.Fatalf("accepted invalid flags: %v", extra)
		}
	}
	if dns.UDP.Load() != 0 || dns.TCP.Load() != 0 {
		t.Fatal("invalid options caused DNS traffic")
	}
	cmd := newScanCommand(&bytes.Buffer{})
	cmd.SetArgs([]string{"--dns-domain", "scan.invalid", "--dns-server", dns.Address, "--timeout", "30ms"})
	start := time.Now()
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "DNS SRV") {
		t.Fatalf("lookup failure: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("DNS ignored scan timeout")
	}
}

// A real RPC peer behind a DNS-only hostname tests both the fast TCP probe and
// NFS negotiation. READDIR returns empty, so the domain root requires LOOKUP.
func scanV4Fixture(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			peer := &missingV4Peer{}
			peer.inspectOperation = func(code uint32, d *missingV4Decoder, current *string) ([]byte, uint32, error) {
				switch code {
				case 9:
					bits := d.bitmap()
					if reflect.DeepEqual(bits, []uint32{10}) {
						return missingV4Opaque(missingV4Words(nil, 1, 1<<10), missingV4Words(nil, 60)), 0, nil
					}
					return missingV4Opaque(missingV4Words(nil, 2, 1<<1|1<<4, 1<<1), missingV4Words(nil, 2, 0, 0, 0755)), 0, nil
				case 15:
					*current += "/" + string(d.opaque())
					return nil, 0, nil
				case 3:
					mask := d.word()
					return missingV4Words(nil, mask, mask), 0, nil
				case 26:
					d.take(16)
					d.word()
					d.word()
					d.bitmap()
					return missingV4Words(nil, 0, 0, 0, 1), 0, nil
				case 35, 36, 24, 22, 10:
					return peer.operation(code, d, current)
				default:
					return nil, 10004, nil
				}
			}
			// The scanner's initial TCP probe connects and closes without RPC.
			if err := peer.serve(l); err != nil {
				if !strings.Contains(err.Error(), "unexpected minor version") {
					t.Errorf("scan wire: %v", err)
				}
			}
		}
	}()
	t.Cleanup(func() { close(stop); l.Close(); <-done })
	return l.Addr().(*net.TCPAddr).Port
}

func TestScanDNSOnlyConnectsWithSRVPortAndDomainRoot(t *testing.T) {
	for _, override := range []bool{false, true} {
		t.Run(fmt.Sprintf("port-override=%t", override), func(t *testing.T) {
			port := scanV4Fixture(t)
			advertised := port
			if override {
				advertised = 1
			}
			record := dnsmessage.SRVResource{Target: dnsmessage.MustNewName("nfs.scan.invalid."), Port: uint16(advertised)}
			dns := scanDNSFixture(t, record, record) // Duplicate records must not scan twice.
			var out bytes.Buffer
			cmd := newScanCommand(&out)
			args := []string{"--dns-domain", "scan.invalid", "--dns-server", dns.Address, "--nfs-version", "4.0", "--portmap-port", "0", "--no-squash-check", "--no-escape-check", "--output", "json"}
			if override {
				args = append(args, "--nfs-port", fmt.Sprint(port))
			}
			cmd.SetArgs(args)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := cmd.ExecuteContext(ctx); err != nil {
				t.Fatal(err)
			}
			var result scan.Result
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Hosts) != 1 || !result.Hosts[0].Reachable || result.Hosts[0].NFSVersion != "4.0" || result.Hosts[0].NFSPort != port {
				t.Fatal(out.String())
			}
			var found bool
			for _, ex := range result.Hosts[0].Exports {
				found = found || ex.Path == "/.domainroot/scan.invalid" && ex.Access == "accessible"
			}
			if !found {
				t.Fatalf("domain root not explicitly inspected: %s", out.String())
			}
		})
	}
}

func TestScanCustomDNSWithoutSRV(t *testing.T) {
	_, port := testServer(t)
	var lookups atomic.Int32
	dns := dnsfixture.Start(t, func(_ string, q dnsmessage.Message) *dnsmessage.Message {
		lookups.Add(1)
		return dnsfixture.Loopback(q)
	})
	var out bytes.Buffer
	cmd := newScanCommand(&out)
	cmd.SetArgs([]string{"nfs.scan.invalid.", "--dns-server", dns.Address, "--nfs-version", "3", "--nfs-port", fmt.Sprint(port), "--mount-port", fmt.Sprint(port), "--portmap-port", "0", "--no-squash-check", "--no-escape-check", "--output", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var result scan.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || !result.Hosts[0].Reachable || lookups.Load() == 0 {
		t.Fatal(out.String())
	}
}
