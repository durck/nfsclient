package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"nfsclient/internal/nfs"
	"nfsclient/internal/resolve"
	"nfsclient/internal/scan"
)

func newScanCommand(out io.Writer) *cobra.Command {
	var (
		nfsVersion  string
		portmapPort int
		nfsPort     int
		mountPort   int
		recursive   bool
		timeout     time.Duration
		concurrency int
		noSquash    bool
		noEscape    bool
		output      string
		file        string
		dnsDomain   string
		dnsServer   string
		// auth
		uid        uint32
		gid        uint32
		groups     string
		sec        string
		principal  string
		keytab     string
		ccache     string
		kcmSocket  string
		spn        string
		targetSPNs []string
		password   string
		domain     string
		krb5Cfg    string
	)
	discovery := nfs.DefaultDiscoveryOptions()

	cmd := &cobra.Command{
		Use:   "scan [flags] [targets...]",
		Short: "Scan NFS servers for exposed exports and vulnerabilities",
		Long: `Discover NFS exports and check access under the selected identity.
Squash checks create and remove a temporary file. For read-only discovery,
combine --no-squash-check and --no-escape-check.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && file == "" && dnsDomain == "" {
				return fmt.Errorf("specify at least one target or use --file or --dns-domain")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if recursive && !cmd.Flags().Changed("depth") {
				discovery.MaxDepth = 3
			}
			if pf, _ := cmd.Flags().GetString("paths-file"); pf != "" {
				if lerr := loadPathsFile(pf, &discovery); lerr != nil {
					return lerr
				}
			}
			hosts, err := scan.ParseTargets(args, file)
			if err != nil {
				return err
			}
			// Build auth
			gids, err := parseGroups(groups)
			if err != nil {
				return err
			}
			krb := qualifyKerberos(nfs.KerberosConfig{
				Principal:  principal,
				Keytab:     keytab,
				CCache:     ccache,
				KCMSocket:  kcmSocket,
				SPN:        spn,
				ConfigFile: krb5Cfg,
			}, domain, password)
			if sec == "krb5" || sec == "krb5i" || sec == "krb5p" {
				for _, name := range []string{"uid", "gid", "groups"} {
					if cmd.Flags().Changed(name) {
						return fmt.Errorf("--%s cannot select a Kerberos identity; use --principal", name)
					}
				}
			}

			opts := scan.Options{
				NFSVersion:  nfsVersion,
				PortmapPort: portmapPort,
				NFSPort:     nfsPort,
				MountPort:   mountPort,
				Discovery:   discovery,
				Timeout:     timeout,
				Concurrency: concurrency,
				CheckSquash: !noSquash,
				CheckEscape: !noEscape,
				Output:      output,
				UID:         uid,
				GID:         gid,
				Groups:      gids,
				Security:    sec,
				Kerberos:    krb,
				TargetSPNs:  targetSPNs,
				DNS:         resolve.Config{Server: dnsServer},
			}
			if err := opts.Validate(); err != nil {
				return err
			}
			targets := make([]scan.Target, 0, len(hosts))
			for _, host := range hosts {
				targets = append(targets, scan.Target{Host: host})
			}
			if dnsDomain != "" {
				if nfsVersion == "2" || nfsVersion == "3" {
					return fmt.Errorf("--dns-domain requires NFSv4 (use auto, 4, 4.0, 4.1 or 4.2)")
				}
				lookupCtx, cancel := context.WithTimeout(cmd.Context(), timeout)
				srvTargets, srvErr := lookupNFSSRVTargets(lookupCtx, dnsDomain, dnsServer)
				cancel()
				if srvErr != nil {
					return fmt.Errorf("DNS SRV lookup for %q: %w", dnsDomain, srvErr)
				}
				if nfsPort > 0 {
					for i := range srvTargets {
						srvTargets[i].NFSPort = nfsPort
					}
				}
				targets = append(targets, srvTargets...)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no targets found")
			}

			w := out
			if w == nil {
				w = os.Stdout
			}
			return scan.RunTargets(cmd.Context(), targets, opts, w)
		},
	}

	cmd.Flags().StringVar(&nfsVersion, "nfs-version", "auto", "NFS version: auto, 2, 3, 4.0, 4.1, 4.2")
	cmd.Flags().IntVar(&portmapPort, "portmap-port", 111, "portmapper port")
	cmd.Flags().IntVar(&nfsPort, "nfs-port", 0, "NFS port (0 = 2049 for NFSv4, discover for NFSv2/v3)")
	cmd.Flags().IntVar(&mountPort, "mount-port", 0, "MOUNT port for NFSv2/v3 (0 = discover)")
	discoveryFlags(cmd.Flags(), &discovery, &recursive)
	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 5*time.Second, "per-host connection timeout")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 20, "max simultaneous connections")
	cmd.Flags().BoolVar(&noSquash, "no-squash-check", false, "skip no_root_squash detection")
	cmd.Flags().BoolVar(&noEscape, "no-escape-check", false, "skip root-handle escape detection")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	cmd.Flags().StringVarP(&file, "file", "f", "", "file containing targets (one per line)")
	// auth flags
	cmd.Flags().Uint32VarP(&uid, "uid", "u", 65534, "AUTH_SYS UID")
	cmd.Flags().Uint32VarP(&gid, "gid", "g", 65534, "AUTH_SYS GID")
	cmd.Flags().StringVar(&groups, "groups", "", "AUTH_SYS supplementary GIDs, comma-separated")
	cmd.Flags().StringVarP(&sec, "sec", "s", "sys", "security: sys, krb5, krb5i, krb5p")
	cmd.Flags().StringVar(&principal, "principal", "", "Kerberos principal NAME@REALM")
	cmd.Flags().StringVar(&keytab, "keytab", "", "Kerberos keytab file")
	cmd.Flags().StringVar(&ccache, "ccache", "", "Explicit Kerberos FILE cache path, Linux KCM/KEYRING or Windows MSLSA:CURRENT")
	cmd.Flags().StringVar(&kcmSocket, "kcm-socket", "", "Explicit absolute trusted Linux KCM socket; requires --ccache KCM:name")
	cmd.Flags().StringVar(&spn, "spn", "", "Explicit Kerberos nfs/server-hostname for one target endpoint")
	cmd.Flags().StringArrayVar(&targetSPNs, "target-spn", nil, "Per-target HOST[:PORT]=nfs/server-hostname (repeatable); pin --nfs-port when the legacy port is unknown")
	cmd.Flags().StringVar(&password, "password", "", "Kerberos AS password")
	cmd.Flags().StringVar(&domain, "domain", "", "Kerberos realm / Windows domain (qualifies bare --principal)")
	cmd.Flags().StringVar(&krb5Cfg, "krb5-config", "", "Explicit krb5.conf path")
	cmd.Flags().StringVar(&dnsDomain, "dns-domain", "", "Discover NFSv4 domain roots via _nfs-domainroot._tcp.<domain> (RFC 6641)")
	cmd.Flags().StringVar(&dnsServer, "dns-server", "", "DNS server (IP or IP:PORT) for discovery, NFS connections and Kerberos")

	installScanHelp(cmd, out)
	installStartupCompletions(cmd)
	return cmd
}

// lookupNFSSRVTargets preserves each advertised endpoint and its domain-root path.
// LookupSRV already orders records by priority and weight. A scan visits all of them.
func lookupNFSSRVTargets(ctx context.Context, domain, dnsServer string) ([]scan.Target, error) {
	domain, err := dnsName(domain)
	if err != nil || net.ParseIP(domain) != nil {
		return nil, fmt.Errorf("--dns-domain must be a DNS domain name")
	}
	resolver, err := resolve.New(ctx, resolve.Config{Server: dnsServer})
	if err != nil {
		return nil, err
	}
	_, addrs, err := resolver.LookupSRV(ctx, "nfs-domainroot", "tcp", domain+".")
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no _nfs-domainroot._tcp SRV records found for %q", domain)
	}
	targets := make([]scan.Target, 0, len(addrs))
	for _, srv := range addrs {
		if srv.Target == "." {
			return nil, fmt.Errorf("NFS domain-root service is unavailable for %q (SRV target is '.')", domain)
		}
		host, err := dnsName(srv.Target)
		if err != nil || srv.Port == 0 {
			return nil, fmt.Errorf("invalid NFS SRV endpoint %q:%d", srv.Target, srv.Port)
		}
		targets = append(targets, scan.Target{Host: host + ".", NFSPort: int(srv.Port), DomainRoot: "/.domainroot/" + domain})
	}
	return targets, nil
}

func dnsName(value string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("invalid DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, ch := range label {
			if ch != '-' && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
				return "", fmt.Errorf("invalid DNS label character")
			}
		}
	}
	return name, nil
}
