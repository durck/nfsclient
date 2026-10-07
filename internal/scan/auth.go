package scan

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"nfsclient/internal/nfs"
)

// spnTargetKey normalizes an explicit endpoint without resolving DNS or PTR.
// A host-only key is allowed only when that host has one distinct NFS endpoint.
func spnTargetKey(value string) (string, error) {
	host, port := value, ""
	if strings.Contains(value, ":") && net.ParseIP(value) == nil {
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil {
			return "", fmt.Errorf("target-SPN key must be HOST or HOST:PORT (bracket IPv6 with a port)")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("target-SPN port must be 1..65535")
		}
		port = strconv.Itoa(n)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else if !isHostname(host) || strings.Trim(host, ".") == "" {
		return "", fmt.Errorf("invalid target-SPN host %q", host)
	}
	if port != "" {
		return net.JoinHostPort(host, port), nil
	}
	return host, nil
}

func (opts Options) securityConfig(spn string) nfs.Config {
	k := opts.Kerberos
	k.SPN = spn
	return nfs.Config{Version: opts.NFSVersion, Transport: "tcp", Security: opts.Security, Kerberos: k}
}

func (opts Options) spnMappings() (map[string]string, error) {
	mappings := make(map[string]string)
	if len(opts.TargetSPNs) != 0 && opts.Kerberos.SPN != "" {
		return nil, fmt.Errorf("--spn and --target-spn cannot be combined")
	}
	for _, entry := range opts.TargetSPNs {
		target, spn, ok := strings.Cut(entry, "=")
		if !ok || target == "" || spn == "" {
			return nil, fmt.Errorf("--target-spn requires TARGET=nfs/server-hostname")
		}
		key, err := spnTargetKey(target)
		if err != nil {
			return nil, err
		}
		if existing, found := mappings[key]; found && existing != spn {
			return nil, fmt.Errorf("conflicting --target-spn mappings for %q", key)
		}
		if err := nfs.ValidateSecurityConfig(opts.securityConfig(spn)); err != nil {
			return nil, err
		}
		mappings[key] = spn
	}
	if len(mappings) == 0 {
		if err := nfs.ValidateSecurityConfig(opts.securityConfig(opts.Kerberos.SPN)); err != nil {
			return nil, err
		}
	}
	return mappings, nil
}

// targetSPNs binds all explicit identities before the first target is probed.
func (opts Options) targetSPNs(targets []Target) ([]string, error) {
	mappings, err := opts.spnMappings()
	if err != nil {
		return nil, err
	}
	spns := make([]string, len(targets))
	if opts.Security == "" || opts.Security == "sys" {
		return spns, nil
	}
	hosts, endpoints := make([]string, len(targets)), make([]string, len(targets))
	distinct := make(map[string]bool)
	byHost := make(map[string]map[string]bool)
	portQualified := make(map[string]bool)
	for key := range mappings {
		if host, _, err := net.SplitHostPort(key); err == nil {
			portQualified[host] = true
		}
	}
	for i, target := range targets {
		host, err := spnTargetKey(target.Host)
		if err != nil {
			return nil, err
		}
		port := target.NFSPort
		if port == 0 {
			port = opts.NFSPort
		}
		v4Only := strings.HasPrefix(opts.NFSVersion, "4") || target.DomainRoot != ""
		if port == 0 && v4Only {
			port = 2049
		}
		if port == 0 && portQualified[host] {
			// Legacy and auto negotiation may discover a different NFS port.
			// A port-qualified approval cannot bind that unknown endpoint.
			return nil, fmt.Errorf("port-qualified --target-spn for %q requires --nfs-port when legacy NFS may be discovered; use a host-only mapping", host)
		}
		endpoint := net.JoinHostPort(host, strconv.Itoa(port))
		if port == 0 {
			endpoint = host // Distinct from every explicit port, including 2049.
		}
		hosts[i], endpoints[i], distinct[endpoint] = host, endpoint, true
		if byHost[host] == nil {
			byHost[host] = make(map[string]bool)
		}
		byHost[host][endpoint] = true
	}
	if opts.Kerberos.SPN != "" {
		if len(distinct) > 1 {
			return nil, fmt.Errorf("--spn requires one target endpoint; use --target-spn for multiple targets")
		}
		for i := range spns {
			spns[i] = opts.Kerberos.SPN
		}
		return spns, nil
	}
	used := make(map[string]bool)
	for i, endpoint := range endpoints {
		host := hosts[i]
		generic, hasHost := mappings[host]
		exact, hasExact := mappings[endpoint]
		if hasHost && len(byHost[host]) > 1 {
			return nil, fmt.Errorf("ambiguous --target-spn for %q; specify HOST:PORT for each endpoint", host)
		}
		if hasHost && hasExact && generic != exact {
			return nil, fmt.Errorf("conflicting host and endpoint SPNs for %q", endpoint)
		}
		if !hasHost && !hasExact {
			return nil, fmt.Errorf("missing --target-spn for %q", endpoint)
		}
		if hasHost {
			spns[i], used[host] = generic, true
		}
		if hasExact {
			spns[i], used[endpoint] = exact, true
		}
	}
	for key := range mappings {
		if !used[key] {
			return nil, fmt.Errorf("--target-spn %q does not match a scan target", key)
		}
	}
	return spns, nil
}
