package cli

import (
	"bytes"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func startupCompletions(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	var out bytes.Buffer
	cmd := NewCommand(strings.NewReader(""), &out, io.Discard)
	cmd.SetArgs(append([]string{"__complete"}, args...))
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, ":") {
		t.Fatalf("missing completion directive: %q", out.String())
	}
	n, err := strconv.Atoi(strings.TrimPrefix(last, ":"))
	if err != nil {
		t.Fatal(err)
	}
	return lines[:len(lines)-1], cobra.ShellCompDirective(n)
}

func TestStartupCompletionEnums(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"--nfs-version", "4"}, []string{"4", "4.0", "4.1", "4.2"}},
		{[]string{"--sec", "krb5"}, []string{"krb5", "krb5i", "krb5p"}},
		{[]string{"unreachable.invalid", "--transport", ""}, []string{"tcp", "udp", "iwarp"}},
		{[]string{"--krb5-provider", "s"}, []string{"sspi"}},
		{[]string{"--rpcsec-gss-version", ""}, []string{"1", "3"}},
		{[]string{"--color", "a"}, []string{"auto", "always"}},
		{[]string{"--progress", "n"}, []string{"never"}},
		{[]string{"--tls=f"}, []string{"false"}},
		{[]string{"scan", "--output", ""}, []string{"text", "json"}},
		{[]string{"scan", "--sec", "s"}, []string{"sys"}},
		{[]string{"scan", "--nfs-version", "a"}, []string{"auto"}},
	} {
		got, directive := startupCompletions(t, tc.args...)
		if !reflect.DeepEqual(got, tc.want) || directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("%v: %v, directive %v; want %v, NoFileComp", tc.args, got, directive, tc.want)
		}
	}
}

func TestStartupCompletionPathsAndPrivateValues(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want cobra.ShellCompDirective
	}{
		{[]string{"--tls-ca", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"--keytab", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"--recover-locks", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"--ccache", "C:\\"}, cobra.ShellCompDirectiveDefault},
		{[]string{"--ccache", "KCM:"}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"--nlm-state-dir", ""}, cobra.ShellCompDirectiveFilterDirs},
		{[]string{"--password", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"--pkinit-pfx-password", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"--principal", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"--export", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"--timeout", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"scan", "--file", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"scan", "--paths-file", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"scan", "--paths-file=pa"}, cobra.ShellCompDirectiveDefault},
		{[]string{"scan", "--krb5-config", ""}, cobra.ShellCompDirectiveDefault},
		{[]string{"scan", "--password", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"scan", "--path", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"scan", "192.0.2."}, cobra.ShellCompDirectiveNoFileComp},
	} {
		got, directive := startupCompletions(t, tc.args...)
		if len(got) != 0 || directive != tc.want {
			t.Errorf("%v: %v, directive %v; want no values, %v", tc.args, got, directive, tc.want)
		}
	}
	got, directive := startupCompletions(t, "--ccache", "MSLSA:")
	if !reflect.DeepEqual(got, []string{"MSLSA:CURRENT"}) || directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("MSLSA: %v, %v", got, directive)
	}
}

func TestStartupCompletionScripts(t *testing.T) {
	for _, tc := range []struct{ shell, want string }{
		{"bash", "_nfsclient"},
		{"zsh", "#compdef nfsclient"},
		{"fish", "complete -c nfsclient"},
		{"powershell", "Register-ArgumentCompleter"},
	} {
		out, err := executeStartupHelp(t, "completion", tc.shell)
		if err != nil || !strings.Contains(out, tc.want) {
			t.Errorf("completion %s: %v; missing %q", tc.shell, err, tc.want)
		}
	}
}
