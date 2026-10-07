package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"nfsclient/internal/nfs"
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
	if opts.Discovery == (nfs.DiscoveryOptions{}) {
		opts.Discovery = nfs.DefaultDiscoveryOptions()
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
	results := make([]HostResult, len(hosts))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = probeHost(ctx, h, opts)
		}(i, host)
	}
	wg.Wait()

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
	result := HostResult{Host: host}

	// Fast TCP probe before attempting NFS negotiation.
	probePort := 2049
	if opts.NFSPort > 0 {
		probePort = opts.NFSPort
	}
	probeTimeout := opts.Timeout / 2
	if probeTimeout < 500*time.Millisecond {
		probeTimeout = 500 * time.Millisecond
	}
	portmapUp := opts.PortmapPort > 0 && tcpProbe(host, opts.PortmapPort, probeTimeout)
	nfsUp := tcpProbe(host, probePort, probeTimeout)
	if !portmapUp && !nfsUp {
		result.Error = "unreachable"
		return result
	}

	cfg := nfs.Config{
		Host:        host,
		Version:     opts.NFSVersion,
		PortmapPort: opts.PortmapPort,
		NFSPort:     opts.NFSPort,
		MountPort:   opts.MountPort,
		Timeout:     opts.Timeout,
		Auth:        nfs.Auth{UID: opts.UID, GID: opts.GID, Groups: opts.Groups},
		Security:    opts.Security,
		Kerberos:    opts.Kerberos,
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

func tcpProbe(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func printText(w io.Writer, r Result, opts Options) {
	accessible, restricted, vulnerable := 0, 0, 0

	for _, h := range r.Hosts {
		if !h.Reachable {
			if h.Error != "" && h.Error != "unreachable" {
				fmt.Fprintf(w, "[%s]  failed: %s\n\n", safe(h.Host), safe(h.Error))
			}
			continue
		}

		fmt.Fprintf(w, "[%s]  NFS %s/%s\n", safe(h.Host), safe(h.NFSVersion), safe(h.Transport))
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
				line += "  " + safe(ex.Traversal)
			}
			fmt.Fprintln(w, line)
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
}

func safe(s string) string {
	q := fmt.Sprintf("%q", s)
	return q[1 : len(q)-1]
}
