package cli

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"nfsclient/internal/session"
)

type completer struct {
	shell *Shell
	ctx   context.Context
}

type completionKind uint8

const (
	completeNone completionKind = iota
	completeLocal
	completeRemote
	completeLocalDir
	completeRemoteDir
	completeLocalMapping // TARGET=local security profile
)

type completionArgument struct {
	kind   completionKind
	values []string
}

type completionFlag struct {
	completionArgument
	arity int
}

type completionSpec struct {
	args  []completionArgument
	flags map[string]completionFlag
}

func completionMetadata(command string) completionSpec {
	r, l := completionArgument{kind: completeRemote}, completionArgument{kind: completeLocal}
	none := completionArgument{}
	spec := completionSpec{flags: map[string]completionFlag{"--help": {}, "-h": {}}}
	flags := func(arity int, names ...string) {
		for _, name := range names {
			spec.flags[name] = completionFlag{arity: arity}
		}
	}
	values := func(items ...string) completionArgument { return completionArgument{values: items} }
	switch command {
	case "cd":
		spec.args = []completionArgument{{kind: completeRemoteDir}}
	case "lcd":
		spec.args = []completionArgument{{kind: completeLocalDir}}
	case "lls", "lock-save":
		spec.args = []completionArgument{l}
	case "ls", "stat":
		spec.args = []completionArgument{r}
		flags(0, "--offline")
	case "access", "capabilities":
		spec.args = []completionArgument{r}
		flags(0, "--json")
	case "info":
		flags(0, "--json")
	case "acl", "label", "setlabel", "xattrs", "getxattr", "removexattr", "cat", "hex", "mkdir", "rm", "rmdir", "namedattrs", "uid-scan", "allocate", "deallocate", "writesame":
		spec.args = []completionArgument{r}
	case "get", "getplus", "getrange", "reget", "gettree", "getpnfs", "getacl", "setacl":
		spec.args = []completionArgument{r, l}
		if command == "getacl" {
			spec.args = append(spec.args, values("acl", "dacl", "sacl"))
		}
	case "put", "putrange", "reput", "replace", "puttree", "putpnfs", "putrangepnfs":
		spec.args = []completionArgument{l, r}
	case "mv", "copyrange", "clonerange", "copyasync":
		spec.args = []completionArgument{r, r}
	case "copyfrom":
		// SOURCE is on another approved server; only DESTINATION belongs to
		// this session. Never query the current server for source paths.
		spec.args = []completionArgument{none, none, none, r}
		flags(1, "--source-spn", "--copy-user", "--source-tls-name")
	case "chmod":
		spec.args = []completionArgument{none, r}
	case "getnamedattr":
		spec.args = []completionArgument{r, none, l}
	case "offload-reconcile":
		spec.args = []completionArgument{l, none, r}
	case "lock", "locktest":
		spec.args = []completionArgument{r, values("read", "write"), none, values("eof")}
		if command == "lock" {
			flags(1, "--wait", "--wait-native")
		}
	case "setxattr":
		spec.args = []completionArgument{r, none, values("create", "replace", "either")}
	case "seek":
		spec.args = []completionArgument{r, none, values("data", "hole")}
	case "advise":
		spec.args = []completionArgument{r, none, none, values("normal", "sequential", "sequential-backwards", "random", "willneed", "willneed-opportunistic", "dontneed", "noreuse", "read", "write", "init-proximity")}
	case "auto-uid", "auto-uid-scan", "auto-escape":
		spec.args = []completionArgument{values("on", "off")}
	case "root":
		spec.args = []completionArgument{values("info", "verify", "reset", "discovered", "probe")}
	case "reconnect":
		flags(0, "--discard-locks", "--reclaim-locks")
	case "migrate":
		flags(0, "--status", "--source-unavailable", "--arm-failover")
	case "writeadb":
		spec.args = []completionArgument{r}
		flags(2, "--number", "--pattern")
	case "exports":
		flags(0, "--recursive", "--json")
		flags(1, "--path", "--depth", "--max-entries", "--discovery-timeout")
		spec.flags["--paths-file"] = completionFlag{arity: 1, completionArgument: l}
	}
	if command == "reget" {
		flags(0, "--reclaim-locks")
		flags(1, "--retries", "--failover", "--referral")
	}
	if command == "gettree" || command == "puttree" {
		flags(0, "--merge", "--links", "--hardlinks", "--preserve-mode", "--preserve-mtime")
		if command == "gettree" {
			flags(0, "--skip-offline")
		}
	}
	if command == "getpnfs" || command == "putpnfs" || command == "putrangepnfs" {
		flags(0, "--refresh-devices")
		flags(1, "--ds-spn", "--block-target", "--block-initiator")
		spec.flags["--layout"] = completionFlag{arity: 1, completionArgument: values("file", "flex", "block")}
		spec.flags["--parallel"] = completionFlag{arity: 1, completionArgument: values("1", "2", "3", "4", "5", "6", "7", "8")}
		spec.flags["--block-volume"] = completionFlag{arity: 1, completionArgument: l}
		spec.flags["--block-security"] = completionFlag{arity: 1, completionArgument: completionArgument{kind: completeLocalMapping}}
		if command != "putpnfs" {
			spec.flags["--layout"] = completionFlag{arity: 1, completionArgument: values("file", "flex", "block", "object")}
			flags(0, "--osd-secure")
			flags(1, "--osd-target", "--osd-initiator")
			spec.flags["--osd-security"] = completionFlag{arity: 1, completionArgument: completionArgument{kind: completeLocalMapping}}
		}
		if command == "getpnfs" {
			flags(0, "--read-failover", "--mirror-failover", "--session-trunking")
			flags(1, "--block-alternate")
		} else {
			flags(0, "--write-failover", "--block-write")
			spec.flags["--block-journal"] = completionFlag{arity: 1, completionArgument: l}
			if command == "putrangepnfs" {
				flags(0, "--extend", "--block-resume", "--object-write")
			}
		}
	}
	return spec
}

// completionWords mirrors SplitLine's quoting rules but accepts the open quote
// at the cursor. start is a rune offset, as required by readline's menu API.
func completionWords(line []rune) (words []string, quote rune, start int, ok bool) {
	var word strings.Builder
	started := false
	for i := 0; i < len(line); i++ {
		r := line[i]
		if r == 0 {
			return nil, 0, 0, false
		}
		if !started && !unicode.IsSpace(r) {
			start, started = i, true
		}
		if r == '\\' && quote != '\'' && i+1 < len(line) {
			next := line[i+1]
			if next == '"' || quote == 0 && (next == '\'' || unicode.IsSpace(next)) {
				word.WriteRune(next)
				i++
				continue
			}
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
		} else if unicode.IsSpace(r) {
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
			start = i + 1
		} else {
			word.WriteRune(r)
		}
	}
	words = append(words, word.String())
	return words, quote, start, true
}

func (c *completer) Do(line []rune, pos int) ([][]rune, int) {
	if pos < 0 || pos > len(line) {
		return nil, 0
	}
	words, quote, start, ok := completionWords(line[:pos])
	if !ok {
		return nil, 0
	}
	// readline appends our suffix at the cursor; it cannot replace an
	// existing token tail. Avoid duplicating a filename or closing quote.
	if pos < len(line) && (quote != 0 || !unicode.IsSpace(line[pos])) {
		return nil, 0
	}
	prefix := words[len(words)-1]
	var candidates []string
	if len(words) == 1 {
		candidates = shellCommandNames()
	} else if words[0] == "help" && len(words) == 2 {
		candidates = shellHelpTopics()
	} else if slices.Contains(shellCommandNames(), words[0]) {
		candidates = c.arguments(words[0], words[1:])
	}
	slices.Sort(candidates)
	candidates = slices.Compact(candidates)
	var out [][]rune
	for _, value := range candidates {
		if !strings.HasPrefix(value, prefix) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			continue
		}
		directory := strings.HasSuffix(value, "/") || strings.HasSuffix(value, "\\")
		suffix := completionSuffix(strings.TrimPrefix(value, prefix), quote, directory)
		// A literal trailing backslash in a partial token can change the
		// meaning of an appended quote. Never offer a corrupt filename.
		check, _, _, valid := completionWords(append(slices.Clone(line[start:pos]), []rune(suffix)...))
		if !valid || len(check) == 0 || check[0] != value {
			continue
		}
		out = append(out, []rune(suffix))
	}
	return out, pos - start
}

func completionSuffix(suffix string, quote rune, directory bool) string {
	var out strings.Builder
	runes := []rune(suffix)
	for i, r := range runes {
		switch quote {
		case '\'':
			if r == '\'' {
				out.WriteString("'\\''")
			} else {
				out.WriteRune(r)
			}
		case '"':
			switch r {
			case '\\':
				out.WriteString("\"'\\'\"")
			case '"':
				out.WriteString("\\\"")
			default:
				out.WriteRune(r)
			}
		default:
			if r == '\\' && !(directory && i == len(runes)-1) {
				out.WriteString("'\\'")
			} else {
				if r == '\'' || r == '"' || unicode.IsSpace(r) {
					out.WriteRune('\\')
				}
				out.WriteRune(r)
			}
		}
	}
	if !directory {
		if quote != 0 {
			out.WriteRune(quote)
		}
		out.WriteRune(' ')
	}
	return out.String()
}

func (c *completer) arguments(command string, words []string) []string {
	spec := completionMetadata(command)
	if len(words) > 1 {
		delete(spec.flags, "--help")
		delete(spec.flags, "-h")
	}
	prefix := words[len(words)-1]
	position, pending := 0, 0
	options := true
	used := make(map[string]int)
	var argument completionArgument
	for _, word := range words[:len(words)-1] {
		if pending > 0 {
			pending--
			continue
		}
		if options && word == "--" {
			if !slices.Contains([]string{"ls", "stat", "access", "capabilities", "exports", "gettree", "puttree"}, command) {
				return nil
			}
			options = false
			continue
		}
		if options && strings.HasPrefix(word, "-") {
			name, _, attached := strings.Cut(word, "=")
			flag, known := spec.flags[name]
			if !known || !completionFlagAllowed(command, name, position) || !completionFlagAvailable(command, name, used) || attached && !completionEqualsAllowed(command) {
				return nil
			}
			used[name]++
			pending, argument = flag.arity, flag.completionArgument
			if attached && pending > 0 {
				pending--
			}
			continue
		}
		position++
	}
	if pending > 0 {
		return c.argumentValues(argument, prefix)
	}
	for name := range spec.flags {
		if !completionFlagAvailable(command, name, used) {
			delete(spec.flags, name)
		}
	}
	if options && strings.HasPrefix(prefix, "-") {
		if name, value, attached := strings.Cut(prefix, "="); attached {
			flag, known := spec.flags[name]
			if !known || name == "--help" || name == "-h" || !completionEqualsAllowed(command) || !completionFlagAllowed(command, name, position) {
				return nil
			}
			if flag.arity == 0 {
				return []string{name + "=true", name + "=false"}
			}
			return prefixedValues(name+"=", c.argumentValues(flag.completionArgument, value))
		}
		var names []string
		for name := range spec.flags {
			if completionFlagAllowed(command, name, position) {
				names = append(names, name)
			}
		}
		return names
	}
	if command == "unlock" && position == 0 && c.shell != nil && c.shell.Session != nil && c.shell.Session.Client != nil {
		var ids []string
		for _, lock := range c.shell.Session.Client.Locks() {
			ids = append(ids, strconv.FormatUint(lock.ID, 10))
		}
		return ids
	}
	if command == "use" && position == 0 {
		return c.exports()
	}
	var result []string
	if position < len(spec.args) {
		argument = spec.args[position]
		if command == "advise" && position == 3 {
			if i := strings.LastIndexByte(prefix, ','); i >= 0 {
				return prefixedValues(prefix[:i+1], argument.values)
			}
		}
		result = c.argumentValues(argument, prefix)
	}
	if prefix == "" && options {
		for name := range spec.flags {
			if completionFlagAllowed(command, name, position) {
				result = append(result, name)
			}
		}
	}
	return result
}

func completionEqualsAllowed(command string) bool {
	return command == "gettree" || command == "puttree" || command == "exports" || command == "access"
}

func completionFlagAvailable(command, flag string, used map[string]int) bool {
	if len(used) > 0 {
		switch command {
		case "lock", "reconnect", "migrate":
			return false
		case "reget":
			return (flag == "--failover" || flag == "--referral") && used[flag] > 0 && used[flag] < 8
		}
	}
	if used[flag] == 0 {
		return true
	}
	if command == "exports" && flag == "--path" {
		return true
	}
	if command == "getpnfs" || command == "putpnfs" || command == "putrangepnfs" {
		return slices.Contains([]string{"--block-volume", "--block-target", "--block-security", "--block-alternate", "--osd-target", "--osd-security", "--ds-spn"}, flag)
	}
	return false
}

// Handwritten command parsers have deliberately narrower option placement
// than pflag. Complete only syntax that Execute can actually accept.
func completionFlagAllowed(command, flag string, position int) bool {
	if flag == "--help" || flag == "-h" {
		return position == 0
	}
	switch command {
	case "reget", "lock", "reconnect", "migrate", "info", "exports":
		return position == 0
	case "getpnfs", "putpnfs":
		return position >= 2
	case "putrangepnfs":
		return position >= 3
	case "copyfrom":
		return position >= 9
	case "writeadb":
		return position >= 5
	case "ls", "stat", "access", "capabilities":
		return position <= 1
	case "gettree", "puttree":
		return position <= 2
	}
	return false
}

func prefixedValues(prefix string, values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = prefix + value
	}
	return out
}

func (c *completer) argumentValues(arg completionArgument, prefix string) []string {
	if arg.kind == completeNone {
		return slices.Clone(arg.values)
	}
	if c.shell == nil {
		return nil
	}
	if arg.kind == completeLocalMapping {
		mapping, filename, ok := strings.Cut(prefix, "=")
		if !ok {
			return nil
		}
		return prefixedValues(mapping+"=", c.argumentValues(completionArgument{kind: completeLocal}, filename))
	}
	if arg.kind == completeLocal || arg.kind == completeLocalDir {
		dir, _ := filepath.Split(prefix)
		entries, err := os.ReadDir(c.shell.local(dir))
		if err != nil {
			return nil
		}
		var values []string
		for _, entry := range entries {
			if arg.kind == completeLocalDir && !entry.IsDir() {
				continue
			}
			name := dir + entry.Name()
			if entry.IsDir() {
				name += string(filepath.Separator)
			}
			values = append(values, name)
		}
		return values
	}
	inspection := c.inspection()
	if inspection == nil {
		return nil
	}
	ctx, cancel := c.timeout()
	defer cancel()
	base, _ := path.Split(prefix)
	dir := base
	if dir == "" {
		dir = "."
	}
	entries, err := inspection.LS(ctx, dir)
	if err != nil {
		return nil
	}
	var values []string
	for _, entry := range entries {
		if arg.kind == completeRemoteDir && entry.Attr.Type != 2 {
			continue
		}
		name := base + entry.Name
		if entry.Attr.Type == 2 {
			name += "/"
		}
		values = append(values, name)
	}
	return values
}

// Tab uses the already selected root and identity. In particular it must not
// trigger identity scanning, switch AUTH_SYS credentials, or discover a root.
func (c *completer) inspection() *session.Session {
	if c.shell == nil || c.shell.Session == nil || c.shell.Session.Client == nil {
		return nil
	}
	inspection := *c.shell.Session
	inspection.AutoUID, inspection.AutoUIDScan, inspection.AutoEscape = false, false, false
	return &inspection
}

func (c *completer) timeout() (context.Context, context.CancelFunc) {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, 2*time.Second)
}

func (c *completer) exports() []string {
	inspection := c.inspection()
	if inspection == nil {
		return nil
	}
	ctx, cancel := c.timeout()
	defer cancel()
	exports, err := inspection.Client.Exports(ctx)
	if err != nil {
		return nil
	}
	var values []string
	for _, export := range exports {
		values = append(values, export.Path)
	}
	return values
}
