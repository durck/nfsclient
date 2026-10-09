package cli

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var (
	helpTokens = regexp.MustCompile(`[^\s\[\]<>|,]+|[\[\]<>|,]`)
	helpFlags  = regexp.MustCompile(`--[a-z][a-z0-9-]*`)
)

// Help reuses the terminal palette: cyan names, warm arguments, muted syntax.
// Apply styling only after wrapping/padding so ANSI bytes never affect layout.
func colorHelpSyntax(text string, color bool) string {
	if !color {
		return text
	}
	return helpTokens.ReplaceAllStringFunc(text, func(token string) string {
		tone := warm
		switch {
		case strings.ContainsAny(token, "[]<>|,") || token == "..." || token == "--":
			tone = muted
		case strings.HasPrefix(token, "-"):
			if flag, value, assigned := strings.Cut(token, "="); assigned {
				return paint(true, cyan, flag) + paint(true, muted, "=") + paint(true, warm, value)
			}
			tone = cyan
		case isHelpName(token):
			tone = cyan
		}
		return paint(true, tone, token)
	})
}

func isHelpName(token string) bool {
	switch token {
	case "nfsclient", "scan", "shell", "completion", "offload-state", "block-state", "lock-state", "inspect", "ack", "all":
		return true
	}
	for _, command := range shellCommandCatalog {
		if token == command.Name {
			return true
		}
		for _, alias := range command.Aliases {
			if token == alias {
				return true
			}
		}
	}
	for _, group := range startupHelpGroups {
		if token == group.name {
			return true
		}
	}
	for _, group := range shellHelpGroups {
		if token == group.name {
			return true
		}
	}
	return false
}

func colorHelpProse(text string, color bool) string {
	if !color {
		return text
	}
	return helpFlags.ReplaceAllStringFunc(text, func(flag string) string {
		return paint(true, cyan, flag)
	})
}

func colorHelpColumns(line string, color bool) string {
	content := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(content)]
	if end := strings.Index(content, "  "); end >= 0 {
		return indent + colorHelpSyntax(content[:end], color) + colorHelpProse(content[end:], color)
	}
	return indent + colorHelpSyntax(content, color)
}

// Style the already laid-out startup/Cobra help. Prose and wrapped flag
// descriptions remain neutral; only syntax rows receive argument colors.
func colorStartupHelp(text string, color bool) string {
	if !color {
		return text
	}
	lines := strings.Split(text, "\n")
	section := ""
	for i, line := range lines {
		content := strings.TrimSpace(line)
		if content == "" {
			continue
		}
		if line == content {
			if strings.HasSuffix(line, ":") {
				section = strings.TrimSuffix(line, ":")
				lines[i] = paint(true, bold+";"+cyan, line)
				continue
			}
			label, rest, _ := strings.Cut(line, ":")
			switch label {
			case "Usage", "Detailed help", "All scan options", "In the shell":
				section = label
				lines[i] = paint(true, bold+";"+cyan, label+":") + colorHelpSyntax(rest, true)
				continue
			}
			section = ""
		} else {
			switch section {
			case "Usage", "Examples", "Target examples", "Commands", "Available Commands", "Additional help topics":
				lines[i] = colorHelpColumns(line, true)
				continue
			case "Detailed help":
				if strings.HasPrefix(content, "nfsclient ") {
					lines[i] = colorHelpColumns(line, true)
				} else {
					lines[i] = colorHelpSyntax(line, true)
				}
				continue
			}
			if strings.HasPrefix(content, "-") {
				lines[i] = colorHelpColumns(line, true)
				continue
			}
		}
		lines[i] = colorHelpProse(line, true)
	}
	return strings.Join(lines, "\n")
}

func helpColor(cmd *cobra.Command, out io.Writer) (bool, func()) {
	mode, _ := cmd.Root().PersistentFlags().GetString("color")
	ansi, restore := enableANSI(out)
	return useColor(mode, ansi), restore
}

func printStyledHelp(out io.Writer, color bool, render func(io.Writer)) {
	var text strings.Builder
	render(&text)
	fmt.Fprint(out, colorStartupHelp(text.String(), color))
}
