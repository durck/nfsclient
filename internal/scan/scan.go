package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"nfsclient/internal/nfs"
	"nfsclient/internal/resolve"
	"nfsclient/internal/session"
)

type Options struct {
	NFSVersion  string
	PortmapPort int
	NFSPort     int
	MountPort   int
	Discovery   nfs.DiscoveryOptions
	Timeout     time.Duration
	Concurrency int
	CheckSquash bool
	CheckEscape bool
	Output      string // "text" or "json"
	// Auth
	UID      uint32
	GID      uint32
	Groups   []uint32
	Security string
	Kerberos nfs.KerberosConfig
	// TargetSPNs maps explicit HOST[:PORT]=SPN identities; alternative to Kerberos.SPN.
	TargetSPNs []string
	DNS        resolve.Config
}

// Target retains service-discovery endpoint and namespace information.
type Target struct {
	Host       string
	NFSPort    int
	DomainRoot string
}

func DefaultOptions() Options {
	return Options{
		NFSVersion:  "auto",
		PortmapPort: 111,
		Discovery:   nfs.DefaultDiscoveryOptions(),
		Timeout:     5 * time.Second,
		Concurrency: 20,
		CheckSquash: true,
		CheckEscape: true,
		Output:      "text",
		UID:         65534,
		GID:         65534,
		Security:    "sys",
	}
}

const (
	AccessOK     = "accessible"
	AccessDenied = "denied"
)

type ExportResult struct {
	nfs.DiscoveredExport
	// Retain the original JSON field; values are advertised rules, not proof of access.
	AllowedClients []string `json:"allowed_clients,omitempty"`
	NoRootSquash   *bool    `json:"no_root_squash,omitempty"`
	Escaped        *bool    `json:"escaped,omitempty"`
	EscapeMethod   string   `json:"escape_method,omitempty"`
	ProbeError     string   `json:"probe_error,omitempty"`
}

type HostResult struct {
	Host              string         `json:"host"`
	NFSPort           int            `json:"nfs_port,omitempty"`
	DomainRoot        string         `json:"domain_root,omitempty"`
	Reachable         bool           `json:"reachable"`
	NFSVersion        string         `json:"nfs_version,omitempty"`
	Transport         string         `json:"transport,omitempty"`
	Exports           []ExportResult `json:"exports,omitempty"`
	Identity          string         `json:"identity,omitempty"`
	DiscoveryComplete bool           `json:"discovery_complete"`
	DiscoveryIssues   []string       `json:"discovery_issues,omitempty"`
	Error             string         `json:"error,omitempty"`
}

type Result struct {
	Hosts []HostResult `json:"hosts"`
}

// Run scans hosts concurrently and writes the report to w.
func Run(ctx context.Context, hosts []string, opts Options, w io.Writer) error {
	targets := make([]Target, len(hosts))
	for i, host := range hosts {
		targets[i] = Target{Host: host}
	}
	return RunTargets(ctx, targets, opts, w)
}

func (opts Options) normalized() Options {
	if opts.Discovery.MaxDepth == 0 && opts.Discovery.MaxEntries == 0 && opts.Discovery.Timeout == 0 {
		paths := opts.Discovery.Paths
		opts.Discovery = nfs.DefaultDiscoveryOptions()
		opts.Discovery.Paths = paths
	}
	return opts
}

// Validate checks scan settings without contacting DNS or NFS servers.
func (opts Options) Validate() error {
	opts = opts.normalized()
	if err := opts.DNS.Validate(); err != nil {
		return err
	}
	if err := opts.Discovery.Validate(); err != nil {
		return err
	}
	if opts.Timeout <= 0 || opts.Concurrency < 1 || opts.Concurrency > 1024 {
		return fmt.Errorf("scan requires a positive timeout and concurrency 1..1024")
	}
	if opts.Output != "text" && opts.Output != "json" {
		return fmt.Errorf("output must be text or json")
	}
	for _, port := range []int{opts.NFSPort, opts.PortmapPort, opts.MountPort} {
		if port < 0 || port > 65535 {
			return fmt.Errorf("scan ports must be 0..65535")
		}
	}
	switch opts.NFSVersion {
	case "", "auto", "2", "3", "4", "4.0", "4.1", "4.2":
	default:
		return fmt.Errorf("invalid NFS version %q", opts.NFSVersion)
	}
	_, err := opts.spnMappings()
	return err
}

func targetOptions(target Target, opts Options) (Options, error) {
	opts = opts.normalized()
	if strings.Trim(strings.TrimSpace(target.Host), ".") == "" {
		return opts, fmt.Errorf("scan target host must not be empty")
	}
	if target.NFSPort < 0 || target.NFSPort > 65535 {
		return opts, fmt.Errorf("target NFS port must be 0..65535")
	}
	if target.NFSPort > 0 {
		opts.NFSPort = target.NFSPort
	}
	if target.DomainRoot != "" {
		switch opts.NFSVersion {
		case "", "auto":
			opts.NFSVersion = "auto"
		case "2", "3":
			return opts, fmt.Errorf("DNS domain roots require NFSv4")
		}
		found := false
		for _, p := range opts.Discovery.Paths {
			found = found || p == target.DomainRoot
		}
		if !found {
			opts.Discovery.Paths = append(append([]string(nil), opts.Discovery.Paths...), target.DomainRoot)
		}
	}
	return opts, opts.Discovery.Validate()
}

// RunTargets validates all endpoints before scanning, preserving distinct ports
// and domain roots while coalescing equivalent DNS host names.
func RunTargets(ctx context.Context, targets []Target, opts Options, w io.Writer) error {
	opts = opts.normalized()
	if err := opts.Validate(); err != nil {
		return err
	}
	spns, err := opts.targetSPNs(targets)
	if err != nil {
		return err
	}
	type preparedTarget struct {
		target Target
		opts   Options
	}
	var prepared []preparedTarget
	seen := make(map[Target]bool)
	for i, target := range targets {
		perTarget, err := targetOptions(target, opts)
		if err != nil {
			return fmt.Errorf("target %q: %w", target.Host, err)
		}
		perTarget.Kerberos.SPN = spns[i]
		port := perTarget.NFSPort
		if port == 0 {
			port = 2049
		}
		key := Target{Host: strings.ToLower(strings.TrimSuffix(target.Host, ".")), NFSPort: port, DomainRoot: target.DomainRoot}
		if !seen[key] {
			seen[key] = true
			prepared = append(prepared, preparedTarget{target, perTarget})
		}
	}
	results := make([]HostResult, len(prepared))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, item := range prepared {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(idx int, item preparedTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = probeEndpoint(ctx, item.target.Host, item.opts, item.target.DomainRoot != "")
			results[idx].DomainRoot = item.target.DomainRoot
		}(i, item)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}

	sr := Result{Hosts: results}

	if opts.Output == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(sr)
	}

	printText(w, sr, opts)
	return nil
}

func probeHost(ctx context.Context, host string, opts Options) HostResult {
	return probeEndpoint(ctx, host, opts, false)
}

func probeEndpoint(ctx context.Context, host string, opts Options, v4Only bool) HostResult {
	result := HostResult{Host: host, NFSPort: opts.NFSPort}

	// Fast TCP probe before attempting NFS negotiation.
	probePort := 2049
	if opts.NFSPort > 0 {
		probePort = opts.NFSPort
	}
	probeCtx, stopProbe := context.WithTimeout(ctx, opts.Timeout)
	resolver, err := resolve.New(probeCtx, opts.DNS)
	if err != nil {
		stopProbe()
		result.Error = err.Error()
		return result
	}
	// Share one deadline across both probes, including DNS lookup time.
	// A filtered NFS port must not prevent finding a reachable portmapper.
	ports := []int{probePort}
	if opts.PortmapPort > 0 && !v4Only && opts.PortmapPort != probePort {
		ports = append(ports, opts.PortmapPort)
	}
	probes := make(chan bool, len(ports))
	for _, port := range ports {
		go func(port int) { probes <- tcpProbe(probeCtx, resolver, host, port) }(port)
	}
	up := false
	for range ports {
		if <-probes {
			up = true
			stopProbe()
		}
	}
	stopProbe()
	if !up {
		result.Error = "unreachable"
		if ctx.Err() != nil {
			result.Error = ctx.Err().Error()
		}
		return result
	}

	cfg := nfs.Config{
		Host:        host,
		Version:     opts.NFSVersion,
		V4Only:      v4Only,
		PortmapPort: opts.PortmapPort,
		NFSPort:     opts.NFSPort,
		MountPort:   opts.MountPort,
		Timeout:     opts.Timeout,
		Auth:        nfs.Auth{UID: opts.UID, GID: opts.GID, Groups: opts.Groups},
		Security:    opts.Security,
		Kerberos:    opts.Kerberos,
		DNS:         opts.DNS,
	}

	tctx, cancel := context.WithTimeout(ctx, opts.Timeout*3+opts.Discovery.Timeout)
	defer cancel()

	client, err := nfs.Connect(tctx, cfg)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer client.Close()

	result.Reachable = true
	result.NFSVersion = client.Version()
	result.Transport = client.Transport()

	report, err := client.Discover(tctx, opts.Discovery)
	if err != nil {
		result.Error = "exports: " + err.Error()
		return result
	}

	result.Identity, result.DiscoveryComplete, result.DiscoveryIssues = report.Identity, report.Complete, report.Issues
	for _, exp := range report.Entries {
		r := ExportResult{DiscoveredExport: exp, AllowedClients: exp.Clients}
		// Vulnerability probes apply to advertised exports / observed filesystem
		// boundaries, not every directory in a namespace walk.
		if (opts.CheckSquash || opts.CheckEscape) && (exp.Source == "mountd" || exp.FilesystemBoundary) && (exp.Access == AccessOK || exp.Access == "unknown") {
			probeCtx, stop := context.WithTimeout(tctx, opts.Timeout)
			probeExport(probeCtx, client, host, exp.Export, opts, &r)
			stop()
		}
		result.Exports = append(result.Exports, r)
	}

	return result
}

func probeExport(ctx context.Context, client *nfs.Client, host string, exp nfs.Export, opts Options, result *ExportResult) {
	sess := session.New(client, host, false, false, io.Discard)
	if err := sess.Use(ctx, exp.Path); err != nil {
		result.ProbeError = err.Error()
		return
	}

	if opts.CheckSquash {
		if squash, err := sess.ProbeSquash(ctx); err == nil {
			v := squash
			result.NoRootSquash = &v
		} else {
			result.ProbeError = "squash: " + err.Error()
		}
	}

	// PUTROOTFH is normal NFSv4 namespace navigation, not evidence of escape.
	if opts.CheckEscape && !strings.HasPrefix(client.Version(), "4.") {
		if escaped, err := sess.Escape(ctx); err == nil {
			v := escaped
			result.Escaped = &v
			if escaped {
				result.EscapeMethod = "knfsd_v" + client.Version()
			}
		} else {
			if result.ProbeError != "" {
				result.ProbeError += "; "
			}
			result.ProbeError += "escape: " + err.Error()
		}
	}

	_ = client.Unmount(ctx, exp.Path)
}

func tcpProbe(ctx context.Context, resolver *net.Resolver, host string, port int) bool {
	dialer := net.Dialer{Resolver: resolver}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func printText(w io.Writer, r Result, opts Options) {
	accessible, restricted, vulnerable := 0, 0, 0

	for _, h := range r.Hosts {
		displayHost := h.Host
		if h.NFSPort > 0 && h.NFSPort != 2049 {
			displayHost = net.JoinHostPort(h.Host, strconv.Itoa(h.NFSPort))
		}
		if !h.Reachable {
			if h.Error != "" && h.Error != "unreachable" {
				fmt.Fprintf(w, "[%s]  failed: %s\n\n", safe(displayHost), safe(h.Error))
			}
			continue
		}

		fmt.Fprintf(w, "[%s]  NFS %s/%s\n", safe(displayHost), safe(h.NFSVersion), safe(h.Transport))
		fmt.Fprintf(w, "  Identity: %s\n", safe(h.Identity))
		if h.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", safe(h.Error))
		}

		for _, ex := range h.Exports {
			clients := "not advertised"
			if len(ex.Clients) > 0 {
				clients = strings.Join(ex.Clients, ",")
			}
			line := fmt.Sprintf("  %-32s  [%s; %s]", safe(ex.Path), safe(ex.Source), safe(clients))

			switch ex.Access {
			case AccessOK:
				accessible++
				line += "  accessible"
			case AccessDenied:
				restricted++
				line += "  denied (cause not disclosed)"
			default:
				line += "  " + safe(ex.Access)
			}
			permission := func(value *bool) string {
				if value == nil {
					return "?"
				}
				if *value {
					return "yes"
				}
				return "no"
			}
			line += "  list=" + permission(ex.CanList) + " traverse=" + permission(ex.CanTraverse)
			vulnerableResource := false
			if opts.CheckSquash && ex.NoRootSquash != nil {
				if *ex.NoRootSquash {
					line += "  NO_ROOT_SQUASH"
					vulnerableResource = true
				} else {
					line += "  root_squash"
				}
			}
			if opts.CheckEscape && ex.Escaped != nil {
				if *ex.Escaped {
					line += fmt.Sprintf("  ESCAPE(%s)", safe(ex.EscapeMethod))
					vulnerableResource = true
				} else {
					line += "  no-escape"
				}
			}
			if vulnerableResource {
				vulnerable++
			}
			if ex.Error != "" {
				line += "  " + safe(ex.Error)
			}
			if ex.ProbeError != "" {
				line += "  probe: " + safe(ex.ProbeError)
			}
			if ex.FilesystemBoundary {
				line += "  filesystem-boundary"
			}
			if ex.Traversal != "" {
				line += "  " + safe(nfs.DiscoveryTraversalDescription(ex.Traversal))
			}
			fmt.Fprintln(w, line)
			fmt.Fprintln(w, "    Listing: "+ex.ListingDescription())
		}
		if len(h.Exports) == 0 {
			fmt.Fprintln(w, "  No resources discovered; accessible paths may still exist.")
		}
		if !h.DiscoveryComplete {
			fmt.Fprintln(w, "  Partial discovery")
		}
		for _, issue := range h.DiscoveryIssues {
			fmt.Fprintln(w, "    "+safe(issue))
		}
		fmt.Fprintln(w)
	}

	nfsHosts, unreachable := 0, 0
	for _, h := range r.Hosts {
		if h.Reachable {
			nfsHosts++
		} else {
			unreachable++
		}
	}

	fmt.Fprintf(w, "summary: %d hosts  %d NFS  %d unreachable  |  %d accessible  %d denied  %d vulnerable\n",
		len(r.Hosts), nfsHosts, unreachable, accessible, restricted, vulnerable)
	fmt.Fprintln(w, "Sources: mountd = advertised export; namespace = observed NFSv4 path; known_path = supplied path.")
	fmt.Fprintln(w, "list/traverse: yes/no = server access decision; ? = unknown. Listing records READDIR evidence only.")
}

func safe(s string) string {
	q := fmt.Sprintf("%q", s)
	return q[1 : len(q)-1]
}
