package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type startupHelpGroup struct {
	name, title string
	flags       []string
}

// Groups select existing parser metadata; they never register or hide flags.
var startupHelpGroups = []startupHelpGroup{
	{"connection", "Connection and export selection", []string{"export", "nfs-version", "transport", "timeout"}},
	{"auth", "Identity and Kerberos authentication", []string{"sec", "uid", "gid", "groups", "auto-uid", "auto-uid-scan", "principal", "domain", "password", "keytab", "ccache", "krb5-config", "krb5-provider", "spn", "kcm-socket", "as-alias", "enterprise-upn", "as-start-realm", "as-referral-realms", "require-fast", "as-helper", "fast-armor", "pkinit-cert", "pkinit-key", "pkinit-ca", "pkinit-crl", "pkinit-pfx", "pkinit-pfx-password", "rpcsec-gss-version"}},
	{"tls", "TLS transport security", []string{"tls", "tls-insecure", "tls-ca", "tls-server-name", "tls-cert", "tls-key"}},
	{"network", "DNS, ports and transport tuning", []string{"dns-server", "dns-tcp", "portmap-port", "mount-port", "nfs-port", "nlm-port", "reserved-port", "udp-size"}},
	{"session", "Commands, shell and output", []string{"command", "batch", "history", "color", "progress", "no-banner", "help", "help-all"}},
	{"recovery", "Durable evidence and recovery", []string{"offload-journal", "offload-reconcile", "offload-session-recovery", "recover-locks", "recover-offload", "offload-operation", "nlm-client-ip", "nlm-reclaim", "nlm-auto-recover", "nlm-auto-notify", "nlm-listen-ip", "nlm-state-dir"}},
	{"advanced", "Root probing and optional NFS features", []string{"auto-escape", "pnfs", "offload"}},
}

var scanHelpGroups = []startupHelpGroup{
	{"targets", "Targets and connection", []string{"file", "dns-domain", "dns-server", "nfs-version", "timeout", "concurrency", "portmap-port", "nfs-port", "mount-port"}},
	{"discovery", "Discovery and checks", []string{"path", "paths-file", "recursive", "depth", "max-entries", "discovery-timeout", "no-squash-check", "no-escape-check"}},
	{"auth", "Identity and Kerberos authentication", []string{"uid", "gid", "groups", "sec", "principal", "keytab", "password", "domain", "krb5-config"}},
	{"output", "Output and help", []string{"output", "help", "help-all"}},
}

func helpAllRequested(cmd *cobra.Command) bool {
	all, _ := cmd.Flags().GetBool("help-all")
	return all
}

func installStartupHelp(root *cobra.Command, out io.Writer, colorMode *string, noBanner *bool) {
	root.Flags().Bool("help-all", false, "Show all startup flags grouped by topic")
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd != root {
			defaultHelp(cmd, args)
			return
		}
		ansi, restore := enableANSI(out)
		defer restore()
		color := useColor(*colorMode, ansi)
		if !*noBanner {
			printBanner(out, color)
		}
		if helpAllRequested(root) {
			printStartupTopic(root, out, "all")
			return
		}
		fmt.Fprintln(out, "Browse NFS shares without mounting them. Windows + Linux.\n\nUsage:\n  nfsclient HOST [flags]\n  nfsclient <command> [flags]")
		fmt.Fprintln(out, "\nCommon flags:")
		printSelectedFlags(out, root, []string{"export", "nfs-version", "sec", "uid", "gid", "timeout", "command", "batch", "help", "help-all"})
		fmt.Fprintln(out, "\nCommands:\n  scan           Discover exports and check access\n  offload-state  Inspect or acknowledge local offload evidence\n  block-state    Inspect or acknowledge local block evidence\n  lock-state     Inspect durable lock evidence offline\n  completion     Generate terminal completion scripts")
		fmt.Fprintln(out, "\nExamples:\n  nfsclient nfs.example.test\n  nfsclient nfs.example.test -e /data -c 'ls'\n  nfsclient scan 192.168.1.0/24")
		fmt.Fprintln(out, "\nDetailed help: nfsclient help TOPIC\n  connection  auth  tls  network  session  recovery  advanced  all\n  nfsclient help scan       All scan options\n  nfsclient help shell [COMMAND|TOPIC]   Shell help without connecting\n  nfsclient help COMMAND    Command help (nested commands also work)\n  nfsclient completion SHELL --help   Install for bash, zsh, fish or powershell\n\nIn the shell: help, help TOPIC, or help COMMAND")
	})
	root.SetHelpCommand(&cobra.Command{
		Use: "help [topic | command...]", Short: "Show startup topics or command help",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return root.Help()
			}
			if args[0] == "shell" {
				if len(args) > 2 {
					return fmt.Errorf("usage: nfsclient help shell [COMMAND|TOPIC]")
				}
				topic := ""
				if len(args) == 2 {
					topic = args[1]
				}
				if err := (&Shell{Out: out}).printCommandHelp(topic); err != nil {
					return fmt.Errorf("%w; use nfsclient help shell", err)
				}
				return nil
			}
			if len(args) == 1 && printStartupTopic(root, out, args[0]) {
				return nil
			}
			target, rest, err := root.Find(args)
			if err != nil || target == root || len(rest) != 0 {
				return fmt.Errorf("unknown help topic or command %q; use nfsclient help (topics: connection, auth, tls, network, session, recovery, advanced, all)", strings.Join(args, " "))
			}
			if target.Name() == "scan" {
				printScanHelp(target, out, true)
				return nil
			}
			return target.Help()
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 && args[0] == "shell" {
				if len(args) == 1 {
					return shellHelpTopics(), cobra.ShellCompDirectiveNoFileComp
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var choices []string
			if len(args) == 0 {
				choices = append(choices, "all", "shell")
				for _, group := range startupHelpGroups {
					choices = append(choices, group.name)
				}
			}
			target, rest, err := root.Find(args)
			if err == nil && len(rest) == 0 {
				for _, child := range target.Commands() {
					if !child.Hidden {
						choices = append(choices, child.Name())
					}
				}
			}
			return choices, cobra.ShellCompDirectiveNoFileComp
		},
	})
}

func printStartupTopic(cmd *cobra.Command, out io.Writer, topic string) bool {
	if topic != "all" {
		found := false
		for _, group := range startupHelpGroups {
			found = found || group.name == topic
		}
		if !found {
			return false
		}
	}
	fmt.Fprintln(out, "Usage: nfsclient HOST [flags]")
	for _, group := range startupHelpGroups {
		if topic == "all" || topic == group.name {
			fmt.Fprintf(out, "\n%s (help %s):\n", group.title, group.name)
			printSelectedFlags(out, cmd, group.flags)
		}
	}
	fmt.Fprintln(out, "\nUse nfsclient help for the overview; nfsclient help all for every startup flag.")
	return true
}

func printSelectedFlags(out io.Writer, cmd *cobra.Command, names []string) {
	cmd.InitDefaultHelpFlag()
	selected := pflag.NewFlagSet("help", pflag.ContinueOnError)
	selected.SortFlags = false
	for _, name := range names {
		if flag := cmd.Flags().Lookup(name); flag != nil {
			selected.AddFlag(flag)
		}
	}
	fmt.Fprint(out, selected.FlagUsagesWrapped(96))
}

func installScanHelp(cmd *cobra.Command, out io.Writer) {
	cmd.Flags().Bool("help-all", false, "Show all scan flags grouped by topic")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printScanHelp(cmd, out, helpAllRequested(cmd))
	})
	args, run := cmd.Args, cmd.RunE
	cmd.Args = func(cmd *cobra.Command, values []string) error {
		if helpAllRequested(cmd) {
			return nil
		}
		return args(cmd, values)
	}
	cmd.RunE = func(cmd *cobra.Command, values []string) error {
		if helpAllRequested(cmd) {
			return cmd.Help()
		}
		return run(cmd, values)
	}
}

func printScanHelp(cmd *cobra.Command, out io.Writer, all bool) {
	fmt.Fprintln(out, cmd.Long)
	fmt.Fprintln(out, "\nUsage:\n  nfsclient scan [flags] <targets...>\n\nTargets: IP, CIDR, IP range, last-octet range, or --file PATH.")
	if all {
		fmt.Fprintln(out, "\nTarget examples:\n  192.168.1.10          Single IP\n  192.168.1.0/24        CIDR range\n  10.0.0.1-10.0.0.20   Explicit range\n  10.0.0.1-20          Last-octet range\nTarget files contain one target per line; lines starting with # are ignored.")
		fmt.Fprintln(out, "\nPermission denied does not establish an IP restriction. Advertised MOUNT client\nrules are shown separately; NFSv4 does not advertise these rules. Discovery is\nbounded and reports partial results. Use --recursive or --depth for deeper walks.")
		for _, group := range scanHelpGroups {
			fmt.Fprintf(out, "\n%s:\n", group.title)
			printSelectedFlags(out, cmd, group.flags)
		}
	} else {
		fmt.Fprintln(out, "\nTargets and output:")
		printSelectedFlags(out, cmd, []string{"file", "nfs-version", "timeout", "concurrency", "output"})
		fmt.Fprintln(out, "\nDiscovery and identity:")
		printSelectedFlags(out, cmd, []string{"recursive", "path", "no-squash-check", "no-escape-check", "uid", "sec"})
	}
	fmt.Fprintln(out, "\nExamples:\n  nfsclient scan 192.168.1.0/24\n  nfsclient scan --file hosts.txt --output json\n  nfsclient scan 192.168.1.10 --no-squash-check --no-escape-check\n\nAll scan options: nfsclient help scan  (or nfsclient scan --help-all)")
}
