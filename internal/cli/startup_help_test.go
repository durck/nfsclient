package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func executeStartupHelp(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, notices bytes.Buffer
	cmd := NewCommand(strings.NewReader(""), &out, &notices)
	cmd.SetArgs(args)
	err := cmd.Execute()
	if notices.Len() != 0 {
		t.Fatalf("help wrote to stderr: %s", notices.String())
	}
	return out.String(), err
}

func TestStartupHelpOverview(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}, {"help"}} {
		out, err := executeStartupHelp(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		if lines := strings.Count(strings.TrimSpace(out), "\n") + 1; lines > 65 {
			t.Errorf("overview has %d lines, want <=65", lines)
		}
		for _, want := range []string{"Usage:", "--export", "--command", "nfsclient help TOPIC", "connection", "auth", "tls", "network", "session", "recovery", "advanced", "all"} {
			if !strings.Contains(out, want) {
				t.Errorf("overview missing %q", want)
			}
		}
		for _, advanced := range []string{"--pkinit-cert", "--offload-journal", "--nlm-auto-notify"} {
			if strings.Contains(out, advanced) {
				t.Errorf("overview contains advanced flag %s", advanced)
			}
		}
	}
}

func TestStartupHelpFlagCoverage(t *testing.T) {
	root := NewCommand(strings.NewReader(""), io.Discard, io.Discard)
	scan, _, err := root.Find([]string{"scan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cmd    *cobra.Command
		groups []startupHelpGroup
		args   []string
	}{
		{root, startupHelpGroups, []string{"help", "all"}},
		{scan, scanHelpGroups, []string{"help", "scan"}},
	} {
		t.Run(tc.cmd.Name(), func(t *testing.T) {
			tc.cmd.InitDefaultHelpFlag()
			assigned := map[string]int{}
			for _, group := range tc.groups {
				for _, name := range group.flags {
					assigned[name]++
					if tc.cmd.Flags().Lookup(name) == nil {
						t.Errorf("help documents nonexistent flag --%s", name)
					}
				}
			}
			out, err := executeStartupHelp(t, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			tc.cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				if assigned[flag.Name] != 1 {
					t.Errorf("--%s belongs to %d groups", flag.Name, assigned[flag.Name])
				}
				if flag.Hidden || !strings.Contains(out, "--"+flag.Name) {
					t.Errorf("--%s is hidden or missing from full help", flag.Name)
				}
			})
		})
	}
}

func TestStartupHelpTopicsAndWidth(t *testing.T) {
	for _, group := range startupHelpGroups {
		out, err := executeStartupHelp(t, "help", group.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range group.flags {
			if !strings.Contains(out, "--"+name) {
				t.Errorf("topic %s missing --%s", group.name, name)
			}
		}
		assertHelpWidth(t, out)
	}
	for _, args := range [][]string{{"--help", "--no-banner", "--color", "never"}, {"--help-all", "--no-banner"}, {"scan", "--help"}, {"scan", "--help-all"}, {"help", "scan"}} {
		out, err := executeStartupHelp(t, args...)
		if err != nil {
			t.Fatal(err)
		}
		assertHelpWidth(t, out)
	}
}

func assertHelpWidth(t *testing.T, out string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if utf8.RuneCountInString(line) > 100 {
			t.Errorf("help line exceeds 100 columns: %q", line)
		}
	}
}

func TestStartupHelpRoutes(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"help", "offload-state", "inspect"}, "ABSOLUTE_FILE"},
		{[]string{"help", "block-state", "ack"}, "--storage-quiesced"},
		{[]string{"help", "lock-state"}, "inspect"},
		{[]string{"scan", "--help-all"}, "--krb5-config"},
		{[]string{"help", "scan"}, "--discovery-timeout"},
		{[]string{"unreachable.invalid", "--help-all"}, "--pkinit-cert"},
	} {
		out, err := executeStartupHelp(t, tc.args...)
		if err != nil || !strings.Contains(out, tc.want) {
			t.Errorf("%v: error %v, missing %q in %s", tc.args, err, tc.want, out)
		}
	}
	for _, args := range [][]string{{"help", "aut"}, {"help", "connection", "extra"}, {"help", "offload-state", "missing"}} {
		out, err := executeStartupHelp(t, args...)
		if err == nil || !strings.Contains(err.Error(), "unknown help topic or command") || !strings.Contains(err.Error(), "nfsclient help") || out != "" {
			t.Errorf("%v: expected explicit help error, got %v and %q", args, err, out)
		}
	}
}

func TestStartupHelpCompletionKeepsAdvancedFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"__complete", "help", "au"}, "auth"},
		{[]string{"__complete", "--pkinit-c"}, "--pkinit-cert"},
		{[]string{"__complete", "help", "offload-state", "i"}, "inspect"},
		{[]string{"__complete", "help", "sh"}, "shell"},
		{[]string{"__complete", "help", "shell", "getp"}, "getpnfs"},
	} {
		var out bytes.Buffer
		cmd := NewCommand(strings.NewReader(""), &out, io.Discard)
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), tc.want) {
			t.Errorf("completion %v: %v, %s", tc.args, err, out.String())
		}
	}
}

func TestStartupHelpShellOffline(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"help", "shell"}, "SHELL COMMANDS"},
		{[]string{"help", "shell", "getpnfs"}, "--layout"},
		{[]string{"help", "shell", "transfer"}, "get REMOTE"},
		{[]string{"help", "shell", "all"}, "offload-reconcile"},
	} {
		out, err := executeStartupHelp(t, tc.args...)
		if err != nil || !strings.Contains(out, tc.want) {
			t.Errorf("%v: %v, missing %q in %s", tc.args, err, tc.want, out)
		}
	}
	for _, args := range [][]string{{"help", "shell", "unknown"}, {"help", "shell", "get", "extra"}} {
		out, err := executeStartupHelp(t, args...)
		if err == nil || !strings.Contains(err.Error(), "nfsclient help shell") || out != "" {
			t.Errorf("%v: expected shell help error, got %v and %q", args, err, out)
		}
	}
}
