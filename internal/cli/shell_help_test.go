package cli

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestShellHelpRoutingWithoutSession(t *testing.T) {
	var out bytes.Buffer
	shell := &Shell{Out: &out}
	var lines []string
	for _, command := range shellCommandNames() {
		lines = append(lines, command+" --help", command+" -h", "help "+command)
	}
	for _, group := range shellHelpGroups {
		lines = append(lines, "help "+group.name)
	}
	lines = append(lines, "help", "help all")
	for _, line := range lines {
		out.Reset()
		quit, err := shell.Execute(context.Background(), line)
		if err != nil || quit || out.Len() == 0 {
			t.Errorf("%q: quit=%v error=%v output=%q", line, quit, err, out.String())
		}
	}
	for _, line := range []string{"help missing-topic", "help get extra", "absent-command --help"} {
		out.Reset()
		if quit, err := shell.Execute(context.Background(), line); err == nil || quit || out.Len() != 0 {
			t.Errorf("invalid help %q: quit=%v error=%v output=%q", line, quit, err, out.String())
		}
	}
}

func TestShellHelpOverviewAndTopics(t *testing.T) {
	var out bytes.Buffer
	shell := &Shell{Out: &out}
	if err := shell.printHelp(); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(out.String(), "\n"); lines > 65 {
		t.Fatalf("overview has %d lines", lines)
	}
	for _, want := range []string{"help COMMAND", "help TOPIC", "help all", "Tab", "get REMOTE [LOCAL]", "uid-scan", "squash"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("overview missing %q", want)
		}
	}
	for _, topic := range append([]string{""}, shellHelpTopics()...) {
		out.Reset()
		if err := shell.printCommandHelp(topic); err != nil {
			t.Fatalf("topic %q: %v", topic, err)
		}
		for _, line := range strings.Split(out.String(), "\n") {
			if len(line) > 100 {
				t.Errorf("topic %q has wide line (%d): %s", topic, len(line), line)
			}
		}
	}
	for topic, wants := range map[string][]string{
		"getpnfs":      {"--layout block", "--layout object", "--block-alternate", "--block-security", "--osd-security"},
		"putrangepnfs": {"--object-write", "--block-resume", "--extend"},
		"reget":        {"--referral", "--failover", "--reclaim-locks", "cannot be combined"},
		"lock":         {"--wait DURATION", "--wait-native DURATION", "OFFSET LENGTH|eof"},
		"root":         {"info|verify|reset|discovered|probe", "independent server-side"},
		"exports":      {"--max-entries", "--discovery-timeout", "--path"},
		"uid-scan":     {"START [END]", "65535", "20 matches"},
		"quit":         {"Close the session", "alias: quit"},
	} {
		out.Reset()
		if err := shell.printCommandHelp(topic); err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s missing %q", topic, want)
			}
		}
	}
	out.Reset()
	if err := shell.printCommandHelp("does-not-exist"); err == nil || !strings.Contains(err.Error(), "use help") || out.Len() != 0 {
		t.Fatalf("unknown help topic: %v, %q", err, out.String())
	}
}

// Catch new parser commands accidentally omitted from both discovery and help.
func TestShellCatalogCoversDispatch(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "shell.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		sw, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		index, ok := sw.Tag.(*ast.IndexExpr)
		if !ok {
			return true
		}
		name, ok := index.X.(*ast.Ident)
		if !ok || name.Name != "a" {
			return true
		}
		literal, ok := index.Index.(*ast.BasicLit)
		if !ok || literal.Value != "0" {
			return true
		}
		for _, item := range sw.Body.List {
			for _, expr := range item.(*ast.CaseClause).List {
				if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					name, _ := strconv.Unquote(literal.Value)
					want[name] = true
				}
			}
		}
		return false
	})
	for _, name := range shellCommandNames() {
		if !want[name] {
			t.Errorf("duplicate or unsupported command in catalog: %s", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("missing command in catalog: %s", name)
	}
}

type shellHelpFailWriter struct{}

func (shellHelpFailWriter) Write([]byte) (int, error) { return 0, errors.New("help output failed") }

func TestShellHelpReportsOutputFailure(t *testing.T) {
	if err := (&Shell{Out: shellHelpFailWriter{}}).printCommandHelp("get"); err == nil {
		t.Fatal("output failure ignored")
	}
}
