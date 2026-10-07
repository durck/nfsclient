package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"nfsclient/internal/nfs"
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
		Long: `Scan one or more hosts for NFS services. For each host, lists exports,
discovers the NFSv4 namespace or NFSv2/v3 MOUNT exports, checks current-identity
access, and optionally probes no_root_squash and NFSv2/v3 root-handle escape.

Target formats:
  192.168.1.10            single IP
  192.168.1.0/24          CIDR range
  10.0.0.1-10.0.0.20     explicit range
  10.0.0.1-20             last-octet shorthand

Use -f to load targets from a file (one per line; lines starting with # ignored).

Permission denied does not establish an IP restriction. Advertised MOUNT client
rules are shown separately; NFSv4 does not advertise these rules. Discovery is
bounded and reports partial results. Use --recursive or --depth for deeper walks.
Squash checks create and remove a temporary file; use --no-squash-check and
--no-escape-check for read-only discovery under the selected identity.

AUTH_SYS example:
  nfsclient scan 192.168.1.0/24 --uid 0

Kerberos example (keytab):
  nfsclient scan 192.168.1.0/24 --sec krb5 --principal user@CORP.LOCAL --keytab user.keytab

Kerberos example (password):
  nfsclient scan 192.168.1.0/24 --sec krb5 --principal user --domain CORP.LOCAL --password Secret123`,
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
			hosts, err := scan.ParseTargets(args, file)
			if err != nil {
				return err
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
	cmd.Flags().Uint32VarP(&uid, "uid", "u", 65534, "AUTH_SYS UID (default nobody/65534)")
	cmd.Flags().Uint32VarP(&gid, "gid", "g", 65534, "AUTH_SYS GID (default nobody/65534)")
	cmd.Flags().StringVar(&groups, "groups", "", "AUTH_SYS supplementary GIDs, comma-separated")
	cmd.Flags().StringVarP(&sec, "sec", "s", "sys", "security: sys, krb5, krb5i, krb5p")
	cmd.Flags().StringVar(&principal, "principal", "", "Kerberos principal NAME@REALM")
	cmd.Flags().StringVar(&keytab, "keytab", "", "Kerberos keytab file")
	cmd.Flags().StringVar(&password, "password", "", "Kerberos AS password")
	cmd.Flags().StringVar(&domain, "domain", "", "Kerberos realm / Windows domain (qualifies bare --principal)")
	cmd.Flags().StringVar(&krb5Cfg, "krb5-config", "", "Explicit krb5.conf path")

	return cmd
}
