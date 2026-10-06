package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

type Options struct {
	NFSVersion  string
	PortmapPort int
	NFSPort     int
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

type AccessStatus string

const (
	AccessOK           AccessStatus = "accessible"
	AccessIPRestricted AccessStatus = "ip_restricted"
	AccessNotFound     AccessStatus = "not_found"
	AccessError        AccessStatus = "error"
)

type ExportResult struct {
	Path           string       `json:"path"`
	AllowedClients []string     `json:"allowed_clients,omitempty"`
	Access         AccessStatus `json:"access"`
	NoRootSquash   *bool        `json:"no_root_squash,omitempty"`
	Escaped        *bool        `json:"escaped,omitempty"`
	EscapeMethod   string       `json:"escape_method,omitempty"`
	Error          string       `json:"error,omitempty"`
}

type HostResult struct {
	Host       string         `json:"host"`
	Reachable  bool           `json:"reachable"`
	NFSVersion string         `json:"nfs_version,omitempty"`
	Transport  string         `json:"transport,omitempty"`
	Exports    []ExportResult `json:"exports,omitempty"`
	Error      string         `json:"error,omitempty"`
}

type Result struct {
	Hosts []HostResult `json:"hosts"`
}

// Run scans hosts concurrently and writes the report to w.
func Run(ctx context.Context, hosts []string, opts Options, w io.Writer) error {
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
		Timeout:     opts.Timeout,
		Auth:        nfs.Auth{UID: opts.UID, GID: opts.GID, Groups: opts.Groups},
		Security:    opts.Security,
		Kerberos:    opts.Kerberos,
	}

	tctx, cancel := context.WithTimeout(ctx, opts.Timeout*3)
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

	exports, err := client.Exports(tctx)
	if err != nil {
		result.Error = "exports: " + err.Error()
		return result
	}

	for _, exp := range exports {
		result.Exports = append(result.Exports, probeExport(tctx, client, host, exp, opts))
	}

	return result
}

func probeExport(ctx context.Context, client *nfs.Client, host string, exp nfs.Export, opts Options) ExportResult {
	result := ExportResult{
		Path:           exp.Path,
		AllowedClients: exp.Clients,
	}

	// session.Use() calls client.Mount() internally; Status(13) = IP restriction.
	sess := session.New(client, host, false, false, io.Discard)
	if err := sess.Use(ctx, exp.Path); err != nil {
		var s nfs.Status
		if errors.As(err, &s) {
			switch s {
			case 13:
				result.Access = AccessIPRestricted
			case 2:
				result.Access = AccessNotFound
			default:
				result.Access = AccessError
				result.Error = err.Error()
			}
		} else {
			result.Access = AccessError
			result.Error = err.Error()
		}
		return result
	}
	result.Access = AccessOK

	if opts.CheckSquash {
		if squash, err := sess.ProbeSquash(ctx); err == nil {
			v := squash
			result.NoRootSquash = &v
		}
	}

	if opts.CheckEscape {
		if escaped, err := sess.Escape(ctx); err == nil {
			v := escaped
			result.Escaped = &v
			if escaped {
				ver := client.Version()
				if strings.HasPrefix(ver, "4") {
					result.EscapeMethod = "nfsv4_putrootfh"
				} else {
					result.EscapeMethod = "knfsd_v" + ver
				}
			}
		}
	}

	_ = client.Unmount(ctx, exp.Path)
	return result
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
				fmt.Fprintf(w, "[%s]  failed: %s\n\n", h.Host, h.Error)
			}
			continue
		}

		fmt.Fprintf(w, "[%s]  NFS %s/%s\n", h.Host, h.NFSVersion, h.Transport)
		if h.Error != "" {
			fmt.Fprintf(w, "  error: %s\n", h.Error)
		}

		for _, ex := range h.Exports {
			clients := "*"
			if len(ex.AllowedClients) > 0 {
				clients = strings.Join(ex.AllowedClients, ",")
			}
			line := fmt.Sprintf("  %-32s  [%-20s]", ex.Path, clients)

			switch ex.Access {
			case AccessOK:
				accessible++
				line += "  accessible"
				if opts.CheckSquash && ex.NoRootSquash != nil {
					if *ex.NoRootSquash {
						line += "  NO_ROOT_SQUASH"
						vulnerable++
					} else {
						line += "  root_squash"
					}
				}
				if opts.CheckEscape && ex.Escaped != nil {
					if *ex.Escaped {
						line += fmt.Sprintf("  ESCAPE(%s)", ex.EscapeMethod)
					} else {
						line += "  no-escape"
					}
				}
			case AccessIPRestricted:
				restricted++
				line += "  IP_RESTRICTED"
			case AccessNotFound:
				line += "  not_found"
			case AccessError:
				line += "  error: " + ex.Error
			}
			fmt.Fprintln(w, line)
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

	fmt.Fprintf(w, "summary: %d hosts  %d NFS  %d unreachable  |  %d accessible  %d ip-restricted  %d vulnerable\n",
		len(r.Hosts), nfsHosts, unreachable, accessible, restricted, vulnerable)
}
