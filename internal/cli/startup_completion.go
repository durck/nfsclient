package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// These are suggestions, not validators: existing parsing and aliases stay intact.
var startupCompletionValues = map[string][]string{
	"nfs-version":        {"auto", "2", "3", "4", "4.0", "4.1", "4.2"},
	"sec":                {"sys", "krb5", "krb5i", "krb5p"},
	"transport":          {"tcp", "udp", "iwarp"},
	"krb5-provider":      {"portable", "sspi"},
	"rpcsec-gss-version": {"1", "3"},
	"color":              {"auto", "always", "never"},
	"progress":           {"auto", "always", "never"},
	"output":             {"text", "json"},
}

func installStartupCompletions(cmd *cobra.Command) {
	// Hosts and remote targets must never fall back to local filenames.
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		values, enum := startupCompletionValues[flag.Name]
		if flag.Value.Type() == "bool" {
			values, enum = []string{"true", "false"}, true
		}
		completion := cobra.NoFileCompletions
		if enum {
			completion = func(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
				var matches []string
				for _, value := range values {
					if strings.HasPrefix(value, prefix) {
						matches = append(matches, value)
					}
				}
				return matches, cobra.ShellCompDirectiveNoFileComp
			}
		} else {
			switch flag.Name {
			case "file", "paths-file", "history", "tls-ca", "tls-cert", "tls-key", "krb5-config", "keytab", "kcm-socket", "as-helper", "fast-armor", "pkinit-cert", "pkinit-key", "pkinit-ca", "pkinit-crl", "pkinit-pfx", "offload-journal", "recover-locks", "recover-offload":
				completion = func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
					return nil, cobra.ShellCompDirectiveDefault
				}
			case "nlm-state-dir":
				completion = func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
					return nil, cobra.ShellCompDirectiveFilterDirs
				}
			case "ccache":
				completion = completeStartupCCache
			}
		}
		// Flags are registered above, once per command; duplicate registration is a bug.
		if err := cmd.RegisterFlagCompletionFunc(flag.Name, completion); err != nil {
			panic(err)
		}
	})
}

func completeStartupCCache(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
	// Named cache backends are not filesystem paths. Plain paths (including Windows
	// drive letters) still use the shell's native file completion.
	for _, backend := range []string{"KCM:", "KEYRING:", "MSLSA:"} {
		if strings.HasPrefix(prefix, backend) {
			if strings.HasPrefix("MSLSA:CURRENT", prefix) {
				return []string{"MSLSA:CURRENT"}, cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}
	return nil, cobra.ShellCompDirectiveDefault
}
