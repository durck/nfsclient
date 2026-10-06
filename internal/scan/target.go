package scan

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ParseTargets expands a list of target strings (IPs, CIDRs, dash ranges) and
// an optional file (one entry per line) into a deduplicated list of addresses.
// Lines starting with '#' are ignored.
func ParseTargets(args []string, file string) ([]string, error) {
	seen := map[string]bool{}
	var hosts []string
	add := func(ip string) {
		if !seen[ip] {
			seen[ip] = true
			hosts = append(hosts, ip)
		}
	}

	process := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return nil
		}
		ips, err := expandTarget(s)
		if err != nil {
			return fmt.Errorf("invalid target %q: %w", s, err)
		}
		for _, ip := range ips {
			add(ip)
		}
		return nil
	}

	for _, arg := range args {
		if err := process(arg); err != nil {
			return nil, err
		}
	}

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open targets file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if err := process(sc.Text()); err != nil {
				return nil, err
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read targets file: %w", err)
		}
	}

	return hosts, nil
}

func expandTarget(s string) ([]string, error) {
	// CIDR notation (contains slash)
	if strings.Contains(s, "/") {
		return expandCIDR(s)
	}
	// Dash range: 192.168.1.1-192.168.1.20 or 192.168.1.1-20
	if idx := strings.LastIndex(s, "-"); idx > 0 {
		before, after := s[:idx], s[idx+1:]
		if net.ParseIP(before) != nil {
			return expandRange(before, after)
		}
	}
	// Single IP or hostname
	if net.ParseIP(s) != nil || isHostname(s) {
		return []string{s}, nil
	}
	return nil, fmt.Errorf("not a valid IP, CIDR, range, or hostname")
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip = ip.Mask(ipnet.Mask).To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 CIDR not supported")
	}

	ones, bits := ipnet.Mask.Size()
	count := 1 << (bits - ones)
	if count > 65536 {
		return nil, fmt.Errorf("CIDR expands to %d hosts (limit 65536)", count)
	}

	cur := cloneIP(ip)
	var hosts []string
	for range count {
		hosts = append(hosts, cur.String())
		incrementIP(cur)
	}
	return hosts, nil
}

func expandRange(startStr, endStr string) ([]string, error) {
	startIP := net.ParseIP(startStr).To4()
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP %q", startStr)
	}

	var endIP net.IP
	if net.ParseIP(endStr) != nil {
		endIP = net.ParseIP(endStr).To4()
	} else {
		// Last-octet shorthand: 10.0.0.1-20
		lastOctet, err := strconv.Atoi(endStr)
		if err != nil || lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("invalid range end %q", endStr)
		}
		endIP = cloneIP(startIP)
		endIP[3] = byte(lastOctet)
	}

	start := ipToUint32(startIP)
	end := ipToUint32(endIP)
	if end < start {
		return nil, fmt.Errorf("range end %s is before start %s", endStr, startStr)
	}
	if end-start > 65535 {
		return nil, fmt.Errorf("range too large (%d hosts, limit 65536)", end-start+1)
	}

	var hosts []string
	for n := start; n <= end; n++ {
		hosts = append(hosts, uint32ToIP(n).String())
	}
	return hosts, nil
}

func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
