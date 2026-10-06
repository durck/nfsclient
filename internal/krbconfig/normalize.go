package krbconfig

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

type relation struct {
	name, value string
	children    []*relation
	block       bool
}
type profile struct{ sections []*relation }

// Normalize coalesces sections for parsers that otherwise overwrite repeated
// [realms]. Text input cannot resolve includes; file users must supply Load's
// snapshot. Unknown syntax is refused rather than silently losing trust policy.
func Normalize(text string) (string, error) {
	var p profile
	if err := p.parse(text, nil); err != nil {
		return "", err
	}
	result := p.text()
	if strings.TrimSpace(result) == "" {
		return "", errors.New("empty Kerberos configuration")
	}
	return result, nil
}

func (p *profile) parse(text string, include func(string, string) error) error {
	if len(text) > MaxBytes {
		return errors.New("kerberos configuration exceeds 1 MiB")
	}
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return errors.New("invalid Kerberos configuration text")
	}
	var section *relation
	var stack []*relation
	scan := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scan.Scan() {
		lineNo++
		line := scan.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fail := func(reason string) error { return fmt.Errorf("line %d: %s", lineNo, reason) }
		first := strings.Fields(line)[0]
		if first == "module" {
			return fail("dynamic Kerberos modules are unsupported")
		}
		if first == "include" || first == "includedir" {
			if include == nil {
				return fail("include directives require an explicit file snapshot")
			}
			if len(stack) > 0 {
				return fail("includes inside a relation block are unsupported")
			}
			target := strings.TrimSpace(strings.TrimPrefix(line, first))
			if target == "" {
				return fail("missing include path")
			}
			if err := include(first, target); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			if len(stack) > 0 || !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return fail("invalid section or final marker")
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" || name != strings.ToLower(name) || strings.ContainsAny(name, "*{} \t") {
				return fail("section names must be lowercase without final markers")
			}
			section = nil
			for _, s := range p.sections {
				if s.name == name {
					section = s
					break
				}
			}
			if section == nil {
				section = &relation{name: name, block: true}
				p.sections = append(p.sections, section)
			}
			continue
		}
		if section == nil {
			return fail("each configuration file must begin with a section header")
		}
		if line == "}" {
			if len(stack) == 0 {
				return fail("unexpected closing brace")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" || value == "" || strings.ContainsAny(name, "*{}[]\t ") {
			return fail("invalid relation or final marker")
		}
		if value != "{" && strings.ContainsAny(value, "{}") {
			return fail("inline blocks and final markers are unsupported")
		}
		parent := section
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		if section.name == "libdefaults" || section.name == "realms" && len(stack) > 0 {
			name = strings.ToLower(name)
		}
		block := value == "{"
		var prior *relation
		for _, r := range parent.children {
			if r.name == name {
				prior = r
				break
			}
		}
		if prior != nil {
			if prior.block != block {
				return fail("conflicting scalar and block relation: " + name)
			}
			if !block {
				multi := section.name == "realms" && len(stack) == 1 && (name == "kdc" || name == "admin_server" || name == "kpasswd_server") || section.name == "capaths" && len(stack) == 1
				if !multi {
					return fail("duplicate or conflicting relation: " + name)
				}
			}
		}
		node := prior
		if node == nil || !block {
			node = &relation{name: name, value: value, block: block}
			parent.children = append(parent.children, node)
		}
		if block {
			if len(stack) >= MaxDepth {
				return fail("configuration block depth exceeds 8")
			}
			stack = append(stack, node)
		}
	}
	if err := scan.Err(); err != nil {
		return err
	}
	if len(stack) != 0 {
		return errors.New("unclosed Kerberos relation block")
	}
	return nil
}

func (p *profile) text() string {
	var b strings.Builder
	var write func([]*relation, int)
	write = func(nodes []*relation, depth int) {
		for _, n := range nodes {
			indent := strings.Repeat(" ", depth)
			if n.block {
				fmt.Fprintf(&b, "%s%s = {\n", indent, n.name)
				write(n.children, depth+1)
				fmt.Fprintf(&b, "%s}\n", indent)
			} else {
				fmt.Fprintf(&b, "%s%s = %s\n", indent, n.name, n.value)
			}
		}
	}
	for _, section := range p.sections {
		fmt.Fprintf(&b, "[%s]\n", section.name)
		write(section.children, 1)
	}
	return b.String()
}
