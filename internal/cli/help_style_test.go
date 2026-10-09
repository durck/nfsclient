package cli

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
)

var helpANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestStartupHelpColorsPreserveText(t *testing.T) {
	// Explicit always must still work when automatic color is disabled.
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "dumb")
	for _, args := range [][]string{
		{"--help", "--no-banner"}, {"--help-all", "--no-banner"},
		{"help", "auth"}, {"help", "all"},
		{"scan", "--help"}, {"scan", "--help-all"}, {"help", "scan"},
		{"help", "shell"}, {"help", "shell", "getpnfs"}, {"help", "shell", "all"},
		{"help", "offload-state", "inspect"}, {"block-state", "ack", "--help"},
		{"completion", "bash", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			plain, err := executeStartupHelp(t, append([]string{"--color=never"}, args...)...)
			if err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"auto", "always"} {
				colored, err := executeStartupHelp(t, append(args, "--color="+mode)...)
				if err != nil {
					t.Fatal(err)
				}
				if (strings.Contains(colored, "\x1b[")) != (mode == "always") {
					t.Fatalf("help did not honor --color=%s", mode)
				}
				if stripped := helpANSI.ReplaceAllString(colored, ""); stripped != plain {
					t.Fatalf("--color=%s changed help text or alignment", mode)
				}
			}
		})
	}
}

func TestShellHelpColorsPreserveTextAndWidth(t *testing.T) {
	for _, topic := range append([]string{""}, shellHelpTopics()...) {
		t.Run(topic, func(t *testing.T) {
			var plain, colored bytes.Buffer
			for _, shell := range []*Shell{{Out: &plain}, {Out: &colored, Color: true}} {
				if _, err := shell.Execute(context.Background(), "help "+topic); err != nil {
					t.Fatal(err)
				}
			}
			if !strings.Contains(colored.String(), "\x1b["+cyan+"m") {
				t.Fatal("missing command colors")
			}
			if stripped := helpANSI.ReplaceAllString(colored.String(), ""); stripped != plain.String() {
				t.Fatal("color changed shell help text or alignment")
			}
			assertHelpWidth(t, plain.String())
		})
	}
}

func TestHelpSemanticColors(t *testing.T) {
	out, err := executeStartupHelp(t, "--color=always", "--no-banner", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		paint(true, bold+";"+cyan, "Usage:"), paint(true, cyan, "nfsclient"),
		paint(true, cyan, "--export"), paint(true, warm, "HOST"),
		paint(true, warm, "/data"), paint(true, muted, "["),
		"Discover exports and check access", "Export to select; otherwise try advertised exports in order",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing semantic span %q", want)
		}
	}
	usage := "getpnfs REMOTE LOCAL [--read-failover|--mirror-failover] [--parallel 1..8]"
	styled := colorHelpSyntax(usage, true)
	for _, want := range []string{paint(true, cyan, "getpnfs"), paint(true, cyan, "--mirror-failover"), paint(true, warm, "1..8"), paint(true, muted, "|")} {
		if !strings.Contains(styled, want) {
			t.Errorf("syntax missing semantic span %q", want)
		}
	}
	if helpANSI.ReplaceAllString(styled, "") != usage {
		t.Fatal("styling changed syntax")
	}
	if got := colorHelpSyntax("--color=always --", true); got != paint(true, cyan, "--color")+paint(true, muted, "=")+paint(true, warm, "always")+" "+paint(true, muted, "--") {
		t.Fatalf("flag assignment or option terminator has wrong colors: %q", got)
	}
	prose := "Never overwrite files; --merge reuses directories."
	if got := colorHelpProse(prose, true); got != "Never overwrite files; "+paint(true, cyan, "--merge")+" reuses directories." {
		t.Fatalf("prose received argument colors: %q", got)
	}
}

func TestHelpAutoColorToPipe(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	for _, args := range [][]string{{"--help"}, {"help", "auth"}, {"scan", "--help"}, {"help", "shell"}, {"lock-state", "--help"}} {
		out, err := executeStartupHelp(t, args...)
		if err != nil || strings.Contains(out, "\x1b") {
			t.Errorf("help %v should be plain when redirected: %v", args, err)
		}
	}
}
