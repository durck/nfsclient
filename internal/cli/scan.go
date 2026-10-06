package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"nfs-viewer/internal/scan"
)

func newScanCommand(out io.Writer) *cobra.Command {
	var (
		nfsVersion  string
		portmapPort int
		nfsPort     int
		timeout     time.Duration
		concurrency int
		noSquash    bool
		noEscape    bool
		output      string
		file        string
	)

	cmd := &cobra.Command{
		Use:   "scan [flags] <targets...>",
		Short: "Scan NFS servers for exposed exports and vulnerabilities",
		Long: `Scan one or more hosts for NFS services. For each host, lists exports,
detects IP restrictions, and checks for no_root_squash and root-handle
escape vulnerabilities (NFSv2/v3 knfsd heuristic, NFSv4 PUTROOTFH).

Target formats:
  192.168.1.10            single IP
  192.168.1.0/24          CIDR range
  10.0.0.1-10.0.0.20     explicit range
  10.0.0.1-20             last-octet shorthand

Use -f to load targets from a file (one per line; lines starting with # ignored).

IP restrictions (whitelist) are detected automatically: if the server
returns NFS status 13 (permission denied) on mount, the export is marked
IP_RESTRICTED. The advertised client list from showmount is also shown.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && file == "" {
				return fmt.Errorf("specify at least one target or use --file")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, err := scan.ParseTargets(args, file)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				return fmt.Errorf("no targets found")
			}

			opts := scan.Options{
				NFSVersion:  nfsVersion,
				PortmapPort: portmapPort,
				NFSPort:     nfsPort,
				Timeout:     timeout,
				Concurrency: concurrency,
				CheckSquash: !noSquash,
				CheckEscape: !noEscape,
				Output:      output,
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
	cmd.Flags().IntVar(&nfsPort, "nfs-port", 0, "NFS port (0 = discover via portmapper)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-host connection timeout")
	cmd.Flags().IntVar(&concurrency, "concurrency", 20, "max simultaneous connections")
	cmd.Flags().BoolVar(&noSquash, "no-squash-check", false, "skip no_root_squash detection")
	cmd.Flags().BoolVar(&noEscape, "no-escape-check", false, "skip root-handle escape detection")
	cmd.Flags().StringVar(&output, "output", "text", "output format: text or json")
	cmd.Flags().StringVarP(&file, "file", "f", "", "file containing targets (one per line)")

	return cmd
}
