package cli

import (
	"context"
	"fmt"
	"io"
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
		uid       uint32
		gid       uint32
		groups    string
		sec       string
		principal string
		keytab    string
		password  string
		domain    string
		krb5Cfg   string
	)
	discovery := nfs.DefaultDiscoveryOptions()

	cmd := &cobra.Command{
		Use:   "scan [flags] <targets...>",
		Short: "Scan NFS servers for exposed exports and vulnerabilities",
		Long: `Discover NFS exports and check access under the selected identity.
Squash checks create and remove a temporary file. For read-only discovery,
combine --no-squash-check and --no-escape-check.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && file == "" {
				return fmt.Errorf("specify at least one target or use --file")
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
			if dnsDomain != "" {
				srvHosts, srvErr := lookupNFSSRVHosts(cmd.Context(), dnsDomain, dnsServer)
				if srvErr != nil {
					return fmt.Errorf("DNS SRV lookup for %q: %w", dnsDomain, srvErr)
				}
				if len(srvHosts) == 0 {
					return fmt.Errorf("no _nfs._tcp SRV records found for %q", dnsDomain)
				}
				hosts = append(hosts, srvHosts...)
			}
			if len(hosts) == 0 {
				return fmt.Errorf("no targets found")
			}

			// Build auth
			gids, err := parseGroups(groups)
			if err != nil {
				return err
			}
			krb := nfs.KerberosConfig{
				Principal:  principal,
				Keytab:     keytab,
				Password:   password,
				ConfigFile: krb5Cfg,
			}
			// --domain qualifies a bare --principal with a realm.
			if domain != "" && krb.Principal != "" && !strings.Contains(krb.Principal, "@") {
				krb.Principal = krb.Principal + "@" + strings.ToUpper(domain)
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
			}

			w := out
			if w == nil {
				w = os.Stdout
			}
			return scan.Run(cmd.Context(), hosts, opts, w)
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
	cmd.Flags().StringVar(&password, "password", "", "Kerberos AS password")
	cmd.Flags().StringVar(&domain, "domain", "", "Kerberos realm / Windows domain (qualifies bare --principal)")
	cmd.Flags().StringVar(&krb5Cfg, "krb5-config", "", "Explicit krb5.conf path")
	cmd.Flags().StringVar(&dnsDomain, "dns-domain", "", "Discover NFS servers via DNS SRV (_nfs._tcp.<domain>), RFC 6641")
	cmd.Flags().StringVar(&dnsServer, "dns-server", "", "Custom DNS server (IP or IP:PORT) for --dns-domain lookup")

	installScanHelp(cmd, out)
	installStartupCompletions(cmd)
	return cmd
}

// lookupNFSSRVHosts resolves _nfs._tcp.<domain> SRV records and returns the
// target hostnames (RFC 6641). An empty dnsServer means use system DNS.
func lookupNFSSRVHosts(ctx context.Context, domain, dnsServer string) ([]string, error) {
	resolver, err := resolve.New(ctx, resolve.Config{Server: dnsServer})
	if err != nil {
		return nil, err
	}
	_, addrs, err := resolver.LookupSRV(ctx, "nfs", "tcp", domain)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(addrs))
	for _, srv := range addrs {
		hosts = append(hosts, strings.TrimSuffix(srv.Target, "."))
	}
	return hosts, nil
}
