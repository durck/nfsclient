package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
	"nfs-viewer/internal/nfs"
	"nfs-viewer/internal/session"
)

func NewCommand(in io.Reader, out, errOut io.Writer) *cobra.Command {
	var cfg nfs.Config
	var export, groups, history, colorMode, progressMode, recoverLocks string
	var recoverOffload, offloadOperation string
	var autoUID, autoEscape, autoUIDScan, batch, noBanner bool
	var lines []string
	cmd := &cobra.Command{Use: "nfs-viewer HOST", Short: "Interactive NFS client for Windows and Linux", Args: cobra.MaximumNArgs(1), SilenceUsage: true, SilenceErrors: true}
	cmd.SetIn(in)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.AddCommand(newOffloadStateCommand(out), newBlockStateCommand(out), newLockStateCommand(out))
	f := cmd.Flags()
	f.StringVarP(&export, "export", "e", "", "Export to select; otherwise try advertised exports in order")
	f.StringVar(&cfg.Version, "nfs-version", "auto", "NFS version: auto, 2, 3, 4.0, 4.1, 4.2")
	f.StringVar(&cfg.Transport, "transport", "tcp", "RPC transport: tcp, udp (v2/v3), iwarp (software inline RDMA; explicit v4, AUTH_SYS)")
	f.Uint32Var(&cfg.UDPSize, "udp-size", 0, "UDP data/directory limit: 512..4096 bytes (0 = 4096); try 1024 on fragmented paths")
	f.BoolVar(&cfg.TLS.Enabled, "tls", false, "Require RPC-over-TLS 1.3 on all RPC services")
	f.BoolVar(&cfg.PNFS, "pnfs", false, "Enable pNFS file-layout transfers (explicit v4.1/4.2 TCP; sys or Kerberos)")
	f.BoolVar(&cfg.Offload, "offload", false, "Enable COPY/WRITE_SAME callbacks (explicit v4.2 TCP; sys or Kerberos)")
	f.StringVar(&cfg.OffloadJournal, "offload-journal", "", "Absolute persistent offload evidence file; blocks replay after an unknown result")
	f.BoolVar(&cfg.OffloadReconcile, "offload-reconcile", false, "Record expected bytes and durable completion receipts for synchronous whole-file COPY/CLONE reconciliation")
	f.BoolVar(&cfg.OffloadSessionRecovery, "offload-session-recovery", false, "Retain offload session evidence for crash recovery; requires --offload and --offload-journal")
	f.StringVar(&recoverLocks, "recover-locks", "", "Recover NFSv4.1/4.2 lock state and recorded pending phases in the original live session")
	f.StringVar(&recoverOffload, "recover-offload", "", "Recover an offload through its original protected session and exact saved request")
	f.StringVar(&offloadOperation, "offload-operation", "", "Pending operation ID required with --recover-offload")
	f.BoolVar(&cfg.TLS.InsecureSkipVerify, "tls-insecure", false, "Skip TLS certificate chain, validity and hostname checks (requires --tls)")
	f.StringVar(&cfg.TLS.CAFile, "tls-ca", "", "TLS trust anchors in PEM (default: system roots)")
	f.StringVar(&cfg.TLS.ServerName, "tls-server-name", "", "Expected TLS server DNS name (default: HOST)")
	f.StringVar(&cfg.TLS.CertFile, "tls-cert", "", "Optional TLS client certificate PEM")
	f.StringVar(&cfg.TLS.KeyFile, "tls-key", "", "TLS client private key paired with --tls-cert")
	f.StringVar(&cfg.DNS.Server, "dns-server", "", "DNS server IP[:PORT] (default: system DNS; port 53)")
	f.BoolVar(&cfg.DNS.TCP, "dns-tcp", false, "Use TCP for DNS lookups, including Kerberos KDC discovery")
	f.StringVar(&cfg.Security, "sec", "sys", "Security: sys, krb5 (authentication), krb5i (integrity), krb5p (privacy); Kerberos: v2/v3/v4 TCP, v2/v3 UDP")
	f.StringVar(&cfg.Kerberos.Provider, "krb5-provider", "", "Kerberos provider: portable (default) or Windows sspi current logon; explicit principal/SPN")
	f.StringVar(&cfg.Kerberos.ConfigFile, "krb5-config", "", "Explicit krb5.conf path")
	f.StringVar(&cfg.Kerberos.Keytab, "keytab", "", "Kerberos client keytab path")
	f.StringVar(&cfg.Kerberos.CCache, "ccache", "", "Explicit FILE path (formats 3/4), Linux KCM/KEYRING or Windows MSLSA:CURRENT; alternative to --keytab")
	f.StringVar(&cfg.Kerberos.KCMSocket, "kcm-socket", "", "Explicit absolute trusted Linux KCM daemon socket; requires --ccache KCM:name")
	f.StringVar(&cfg.Kerberos.Principal, "principal", "", "Kerberos client NAME@REALM")
	f.StringVar(&cfg.Kerberos.ASAlias, "as-alias", "", "Explicit same-realm AS alias; pins --principal and requires keytab plus protected reply")
	f.StringVar(&cfg.Kerberos.EnterpriseUPN, "enterprise-upn", "", "Explicit enterprise USER@SUFFIX; pins canonical --principal and requires keytab/protected AS reply")
	f.StringVar(&cfg.Kerberos.ASStartRealm, "as-start-realm", "", "Explicit initial mapping realm for enterprise AS lookup")
	f.StringSliceVar(&cfg.Kerberos.ASReferralRealms, "as-referral-realms", nil, "Approved enterprise AS realms, comma separated; include start and canonical home realm")
	f.BoolVar(&cfg.Kerberos.RequireFAST, "require-fast", false, "Require FAST armoring; portable pure-Go exchange without unarmored AS fallback")
	f.StringVar(&cfg.Kerberos.ASHelper, "as-helper", "", "Optional absolute trusted MIT AS helper executable for Linux compatibility")
	f.StringVar(&cfg.Kerberos.PKINIT.Cert, "pkinit-cert", "", "Absolute PKINIT client PEM certificate")
	f.StringVar(&cfg.Kerberos.PKINIT.Key, "pkinit-key", "", "Absolute PKINIT client PEM private key; no password prompt")
	f.StringVar(&cfg.Kerberos.PKINIT.CA, "pkinit-ca", "", "Absolute explicit PKINIT KDC CA PEM bundle")
	f.StringVar(&cfg.Kerberos.PKINIT.CRL, "pkinit-crl", "", "Absolute PKINIT CRL PEM bundle; if selected, revocation checking is required")
	f.StringVar(&cfg.Kerberos.FASTArmor, "fast-armor", "", "Explicit absolute private FILE armor TGT cache for --require-fast")
	f.StringVar(&cfg.Kerberos.SPN, "spn", "", "Kerberos service principal nfs/server-hostname")
	f.Uint32Var(&cfg.Kerberos.RPCVersion, "rpcsec-gss-version", 1, "RPCSEC_GSS version: 1 (default), 3 (explicit v4.2 krb5p/TCP; no pNFS)")
	f.IntVar(&cfg.PortmapPort, "portmap-port", 111, "Portmapper port on the selected transport")
	f.IntVar(&cfg.MountPort, "mount-port", 0, "Mount port (0 = discover)")
	f.IntVar(&cfg.NFSPort, "nfs-port", 0, "NFS port (0 = discover)")
	f.IntVar(&cfg.NLMPort, "nlm-port", 0, "NLM port (0 = discover on the connected NFS peer; retained locks use TCP control)")
	f.StringVar(&cfg.NLMClientIP, "nlm-client-ip", "", "Explicit dedicated client IPv4 identity for monitored legacy locks (owns TCP/UDP port 111)")
	f.BoolVar(&cfg.NLMReclaim, "nlm-reclaim", false, "Allow one legacy lock reclaim after a server restart; requires a server that rejects reclaim outside grace")
	f.BoolVar(&cfg.NLMAutoRecover, "nlm-auto-recover", false, "Release confirmed pre-crash NLM locks before the first new lock; requires the same fixed identity")
	f.BoolVar(&cfg.NLMAutoNotify, "nlm-auto-notify", false, "Send one crash notification after exact-owner cleanup; receipt cannot prove server cleanup, so retain journal and quarantine new locks; requires --nlm-auto-recover and a dedicated identity/address")
	f.StringVar(&cfg.NLMListenIP, "nlm-listen-ip", "", "Local NSM bind IPv4 address (default: nlm-client-ip); forwarding must preserve TCP/UDP port 111")
	f.StringVar(&cfg.NLMStateDir, "nlm-state-dir", "", "Absolute persistent NSM state directory; never delete after uncertain locks")
	f.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Timeout per RPC request and for complete Kerberos setup")
	f.BoolVar(&cfg.ReservedPort, "reserved-port", false, "Bind source ports 900-1023 (may require privileges)")
	f.Uint32Var(&cfg.Auth.UID, "uid", 0, "Initial AUTH_SYS UID")
	f.Uint32Var(&cfg.Auth.GID, "gid", 0, "Initial AUTH_SYS GID")
	f.StringVar(&groups, "groups", "", "Supplementary GIDs, comma-separated (max 16)")
	f.BoolVar(&autoUID, "auto-uid", true, "NFSv3: use each object's owner UID/GID while navigating")
	f.BoolVar(&autoEscape, "auto-escape", true, "NFSv2/v3: knfsd root-handle heuristic; NFSv4: PUTROOTFH pseudo-root probe")
	f.BoolVar(&autoUIDScan, "auto-uid-scan", false, "on EACCES: probe owner UID to find one with read access (requires AUTH_SYS)")
	f.BoolVar(&batch, "batch", false, "Read commands from stdin; stop on the first error")
	f.StringArrayVarP(&lines, "command", "c", nil, "Run one command; repeat to execute a sequence and exit")
	f.StringVar(&history, "history", "", "Optional history file (default: memory only)")
	f.StringVar(&colorMode, "color", "auto", "Color output: auto, always, never (auto honors NO_COLOR)")
	f.StringVar(&progressMode, "progress", "auto", "Transfer progress: auto, always, never (written to stderr)")
	f.BoolVar(&noBanner, "no-banner", false, "Hide the startup/help banner")
	defaultHelp := cmd.HelpFunc()
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd.Parent() != nil {
			defaultHelp(cmd, args)
			return
		}
		ansi, restore := enableANSI(out)
		defer restore()
		color := useColor(colorMode, ansi)
		if !noBanner {
			printBanner(out, color)
		}
		fmt.Fprint(out, "  Browse NFS shares without mounting them. Windows + Linux.\n\n")
		fmt.Fprintln(out, paint(color, bold, "Usage:")+"\n  nfs-viewer HOST [flags]\n")
		fmt.Fprint(out, "  nfs-viewer offload-state inspect ABSOLUTE_FILE\n  nfs-viewer offload-state ack ABSOLUTE_FILE OPERATION_ID --server-quiesced --destination-verified\n\n")
		fmt.Fprint(out, "  nfs-viewer block-state inspect ABSOLUTE_FILE\n  nfs-viewer block-state ack ABSOLUTE_FILE OPERATION_ID --storage-quiesced --destination-verified\n\n")
		fmt.Fprintln(out, paint(color, bold, "Examples:")+"\n  nfs-viewer nfs.example.test\n  nfs-viewer nfs.example.test --export /data\n  nfs-viewer nfs.example.test -e /data -c 'ls'\n")
		fmt.Fprintln(out, paint(color, bold, "In the shell:")+"\n  ls · cd · cat · hex · get · put · chmod · exports · help\n")
		fmt.Fprintln(out, paint(color, bold, "Flags:"))
		fmt.Fprint(out, cmd.Flags().FlagUsagesWrapped(96))
	})
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if colorMode != "auto" && colorMode != "always" && colorMode != "never" {
			return fmt.Errorf("--color must be auto, always, or never")
		}
		if progressMode != "auto" && progressMode != "always" && progressMode != "never" {
			return fmt.Errorf("--progress must be auto, always, or never")
		}
		if len(args) == 0 {
			return cmd.Help()
		}
		outANSI, restoreOut := enableANSI(out)
		defer restoreOut()
		errANSI, restoreErr := enableANSI(errOut)
		defer restoreErr()
		outColor, errColor := useColor(colorMode, outANSI), useColor(colorMode, errANSI)
		cfg.Host = args[0]
		if cfg.OffloadSessionRecovery && (!cfg.Offload || cfg.OffloadJournal == "") {
			return fmt.Errorf("--offload-session-recovery requires --offload and --offload-journal")
		}
		if cfg.OffloadReconcile && (!cfg.Offload || cfg.OffloadJournal == "") {
			return fmt.Errorf("--offload-reconcile requires --offload and --offload-journal")
		}
		if cfg.OffloadJournal != "" && (autoUID || autoEscape) {
			return fmt.Errorf("--offload-journal requires --auto-uid=false and --auto-escape=false")
		}
		if cfg.NLMAutoRecover && (autoUID || autoEscape) {
			return fmt.Errorf("--nlm-auto-recover requires --auto-uid=false and --auto-escape=false")
		}
		if cfg.Security == "krb5" || cfg.Security == "krb5i" || cfg.Security == "krb5p" {
			for _, name := range []string{"uid", "gid", "groups", "auto-uid"} {
				if f.Changed(name) && (name != "auto-uid" || autoUID) {
					return fmt.Errorf("--%s cannot select a Kerberos identity; use --principal", name)
				}
			}
			autoUID = false
		}
		var err error
		cfg.Auth.Groups, err = parseGroups(groups)
		if err != nil {
			return err
		}
		if batch && len(lines) > 0 {
			return fmt.Errorf("--batch and --command cannot be combined")
		}
		if cfg.Timeout <= 0 {
			return fmt.Errorf("timeout must be positive")
		}
		for name, port := range map[string]int{"portmap": cfg.PortmapPort, "mount": cfg.MountPort, "nfs": cfg.NFSPort, "nlm": cfg.NLMPort} {
			if port < 0 || port > 65535 || name == "portmap" && port == 0 {
				return fmt.Errorf("invalid %s port: %d", name, port)
			}
		}
		localDir, err := os.Getwd()
		if err != nil {
			return err
		}
		if history != "" {
			history, err = filepath.Abs(history)
			if err != nil {
				return err
			}
		}
		inputFile, terminal := in.(*os.File)
		terminal = terminal && readline.IsTerminal(int(inputFile.Fd()))
		interactive := terminal && !batch && len(lines) == 0
		ctx, stopSignals := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer stopSignals()
		if recoverOffload != "" || offloadOperation != "" {
			if recoverOffload == "" || offloadOperation == "" || autoUID || autoEscape || export != "" || recoverLocks != "" || batch || len(lines) != 0 {
				return fmt.Errorf("--recover-offload and --offload-operation require fixed identity, no export, commands, batch or lock recovery")
			}
			record, err := nfs.RecoverOffload(ctx, cfg, recoverOffload, offloadOperation)
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(record)
		}
		if interactive && !noBanner {
			printBanner(errOut, errColor)
		}
		if interactive {
			fmt.Fprintln(errOut, "  "+paint(errColor, muted, "Target ")+label(cfg.Host))
		}
		var client *nfs.Client
		var sess *session.Session
		if recoverLocks != "" {
			if autoUID || autoEscape || export != "" {
				return fmt.Errorf("--recover-locks requires fixed identity and uses its saved export; omit --export")
			}
			sess, err = session.RecoverLocks(ctx, cfg, recoverLocks, io.Discard)
			if err == nil {
				client = sess.Client
			}
		} else {
			client, err = nfs.Connect(ctx, cfg)
			if err == nil {
				sess = session.New(client, cfg.Host, autoUID, autoEscape, io.Discard)
				sess.AutoUIDScan = autoUIDScan
			}
		}
		if err != nil {
			return err
		}
		defer func() { sess.Client.Close() }()
		sh := &Shell{Session: sess, Out: out, Err: errOut, LocalDir: localDir, Terminal: isTerminal(out), Color: outColor, ErrColor: errColor, ErrTerminal: isTerminal(errOut), ProgressMode: progressMode}
		if export != "" {
			if err := sess.Use(ctx, export); err != nil {
				return fmt.Errorf("select export %q: %w", export, err)
			}
		} else if len(lines) == 0 && recoverLocks == "" {
			exports, err := client.Exports(ctx)
			if err != nil {
				fmt.Fprintf(errOut, "Export listing unavailable: %v; select a known path with use.\n", err)
			} else {
				if !interactive {
					printExports(errOut, exports, errColor)
				}
				for _, e := range exports {
					if err := sess.Use(ctx, e.Path); err != nil {
						fmt.Fprintf(errOut, "Cannot use %q: %v\n", e.Path, err)
						continue
					}
					break
				}
				if interactive && sess.Export == "" {
					printExports(errOut, exports, errColor)
				}
			}
		}
		if interactive {
			if err := sh.printReady(errOut, errColor); err != nil {
				return err
			}
		} else if sess.ProbeError != nil {
			fmt.Fprintf(errOut, "Root probe: %v\n", sess.ProbeError)
		}
		for _, line := range lines {
			exit, err := sh.Execute(ctx, line)
			if err != nil {
				return err
			}
			if exit {
				return nil
			}
		}
		if len(lines) > 0 {
			return nil
		}
		if batch || !terminal {
			return sh.RunBatch(ctx, in)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		stopSignals()
		fmt.Fprintln(errOut, "  "+paint(errColor, muted, "help · id · exports   /   Ctrl+C twice to quit")+"\n")
		return sh.RunInteractive(cmd.Context(), history)
	}
	return cmd
}
