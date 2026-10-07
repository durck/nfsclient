package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/chzyer/readline"
	"nfsclient/internal/nfs"
	"nfsclient/internal/session"
)

const (
	cyan   = "36"
	blue   = "34"
	green  = "32"
	yellow = "33"
	red    = "1;31"
	dim    = "2"
	bold   = "1"
)

func paint(enabled bool, tone, text string) string {
	if !enabled || tone == "" {
		return text
	}
	return "\x1b[" + tone + "m" + text + "\x1b[0m"
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && readline.IsTerminal(int(f.Fd()))
}

func useColor(mode string, tty bool) bool {
	if mode == "always" {
		return true
	}
	if mode == "never" {
		return false
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	return tty && !noColor && os.Getenv("TERM") != "dumb"
}

// Keep ordinary names readable, but quote whitespace and escape any controls or
// invisible formatting characters supplied by the remote filesystem.
func label(s string) string {
	if s == "" || !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) || unicode.IsSpace(r) || r == '"' || r == '\\' }) >= 0 {
		return strconv.Quote(s)
	}
	return s
}

func humanSize(size uint64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	value := float64(size) / 1024
	i := 0
	for value >= 1024 && i < len(units)-1 {
		value /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", value, units[i])
}

func permissions(a nfs.Attr) string {
	kind := byte('?')
	if a.Type >= 1 && a.Type <= 7 {
		kind = "-dbclsp"[a.Type-1]
	}
	p := []byte{kind, '-', '-', '-', '-', '-', '-', '-', '-', '-'}
	for i := 0; i < 9; i++ {
		if a.Mode&(1<<(8-i)) != 0 {
			p[i+1] = "rwx"[i%3]
		}
	}
	for _, bit := range []struct {
		mask    uint32
		pos     int
		on, off byte
	}{{04000, 3, 's', 'S'}, {02000, 6, 's', 'S'}, {01000, 9, 't', 'T'}} {
		if a.Mode&bit.mask != 0 {
			if p[bit.pos] == 'x' {
				p[bit.pos] = bit.on
			} else {
				p[bit.pos] = bit.off
			}
		}
	}
	return string(p)
}

type cell struct{ text, tone string }

// Pad plain text before applying color so ANSI bytes cannot shift columns.
func table(w io.Writer, rows [][]cell, color bool) error {
	if len(rows) == 0 {
		return nil
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, c := range row {
			widths[i] = max(widths[i], (readline.Runes{}).WidthAll([]rune(c.text)))
		}
	}
	for rowIndex, row := range rows {
		var line strings.Builder
		line.WriteString("  ")
		for i, c := range row {
			padding := widths[i] - (readline.Runes{}).WidthAll([]rune(c.text))
			if rows[0][i].text == "SIZE" {
				line.WriteString(strings.Repeat(" ", padding))
				padding = 0
			}
			line.WriteString(paint(color, c.tone, c.text))
			if i < len(row)-1 {
				line.WriteString(strings.Repeat(" ", padding+2))
			}
		}
		if _, err := fmt.Fprintln(w, line.String()); err != nil {
			return err
		}
		if rowIndex == 0 && row[0].text == "NAME" {
			width := 2 * (len(widths) - 1)
			for _, n := range widths {
				width += n
			}
			if _, err := fmt.Fprintln(w, "  "+paint(color, dim, strings.Repeat("-", width))); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Shell) printEntries(entries []nfs.Entry, linkMaps ...map[string]session.LinkInfo) error {
	links := map[string]session.LinkInfo{}
	if len(linkMaps) > 0 {
		links = linkMaps[0]
	}
	now := time.Now()
	sort.SliceStable(entries, func(i, j int) bool {
		if (entries[i].Attr.Type == 2) != (entries[j].Attr.Type == 2) {
			return entries[i].Attr.Type == 2
		}
		return entries[i].Name < entries[j].Name
	})
	rows := [][]cell{{{"NAME", bold}, {"SIZE", bold}, {"PERMISSIONS", muted}, {"OWNER", muted}, {"MODIFIED", bold}}}
	dirs := 0
	for _, e := range entries {
		name, tone, size := label(e.Name), fileTone(e), humanSize(e.Attr.Size)
		metadata, modifiedTone := muted, dateTone(e.Attr.MTime, now)
		switch e.Attr.Type {
		case 2:
			name += "/"
			size = "-"
			dirs++
		case 5:
			name += "@"
			info, ok := links[e.Name]
			if !ok {
				info.State = "unchecked"
			}
			if info.Target != "" {
				name += " -> " + label(info.Target)
			}
			if info.State != "reachable" {
				state := map[string]string{"missing": "missing", "denied": "access denied", "loop": "link loop", "unavailable": "unverified", "unchecked": "unchecked"}[info.State]
				name += " [" + state + "]"
				if info.State != "unchecked" {
					tone, metadata, modifiedTone = faint, faint, faint
				}
			}
		}
		if e.Attr.Offline != "" {
			name += " [" + string(e.Attr.Offline) + "]"
		}
		rows = append(rows, []cell{{name, tone}, {size, metadata}, {permissions(e.Attr), metadata}, {ownerLabel(e.Attr), metadata}, {e.Attr.MTime.Local().Format("2006-01-02 15:04"), modifiedTone}})
	}
	if err := table(s.Out, rows, s.Color); err != nil {
		return err
	}
	_, err := fmt.Fprintln(s.Out, "\n  "+paint(s.Color, muted, fmt.Sprintf("%d entries · %d directories · %d other", len(entries), dirs, len(entries)-dirs))+"\n")
	return err
}

func printExports(w io.Writer, exports []nfs.Export, color bool) {
	if len(exports) == 1 && exports[0].Namespace {
		section(w, "NFSv4 NAMESPACE", color)
		fmt.Fprint(w, "  /  · server pseudo-root\n  Use / to browse, or use an NFSv4 export path.\n  NFSv4 does not advertise mountd client rules.\n")
		return
	}
	section(w, fmt.Sprintf("EXPORTS / %d", len(exports)), color)
	for i, e := range exports {
		fmt.Fprintf(w, "  %s  %s\n", paint(color, muted, fmt.Sprintf("%02d", i+1)), paint(color, warm, label(e.Path)))
		fmt.Fprintln(w, paint(color, dim, fmt.Sprintf("      Client rules (%d)", len(e.Clients))))
		if len(e.Clients) == 0 {
			fmt.Fprintln(w, "      <none advertised>")
		}
		width := 0
		for _, rule := range e.Clients {
			width = max(width, (readline.Runes{}).WidthAll([]rune(label(rule))))
		}
		columns := max(1, min(3, 70/(width+3)))
		for j, rule := range e.Clients {
			if j%columns == 0 {
				fmt.Fprint(w, "      ")
			}
			value := label(rule)
			fmt.Fprint(w, value)
			if j%columns == columns-1 || j == len(e.Clients)-1 {
				fmt.Fprintln(w)
			} else {
				fmt.Fprint(w, strings.Repeat(" ", width-(readline.Runes{}).WidthAll([]rune(value))+3))
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "  "+paint(color, dim, "Advertised rules; effective access may differ.")+"\n")
}

func section(w io.Writer, title string, color bool) {
	tone := bold
	if strings.HasPrefix(title, "EXPORTS") || title == "BROWSE" {
		tone = warm
	}
	if title == "SESSION" {
		tone = lavender
	}
	if title == "FILES" {
		tone = green
	}
	fmt.Fprintln(w, "\n  "+paint(color, tone, title)+"\n  "+paint(color, muted, strings.Repeat("-", 48)))
}

func printBanner(w io.Writer, color bool) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, paint(color, warm, `   _  _ ___ ___`))
	fmt.Fprintln(w, paint(color, warm, `  | \| | __/ __|`)+"  "+paint(color, bold, "client"))
	fmt.Fprintln(w, paint(color, warm, `  | .`+"`"+` | _|\__ \`)+"  "+paint(color, muted, "© durck"))
	fmt.Fprintln(w, paint(color, warm, `  |_|\_|_| |___/`))
	fmt.Fprintln(w)
}

// Keep startup and export changes compact; full details remain available in id.
func (s *Shell) printReady(w io.Writer, color bool) error {
	state := s.Session
	if state.Export == "" {
		_, err := fmt.Fprintln(w, "  "+paint(color, yellow, "No export selected")+" · use EXPORT or exports")
		return err
	}
	identity := fmt.Sprintf("uid %d:%d", state.Client.Auth.UID, state.Client.Auth.GID)
	if state.Client.Security() != "sys" {
		identity = state.Client.Identity()
	}
	if _, err := fmt.Fprintf(w, "  %s %s · %s · NFSv%s/%s\n", paint(color, green, "Connected"), paint(color, warm, label(state.Export)), label(identity), state.Client.Version(), strings.ToUpper(state.Client.Transport())); err != nil {
		return err
	}
	if state.Escaped {
		if _, err := fmt.Fprintln(w, "  "+paint(color, yellow, "Root: discovered directory; location unverified (root info)")); err != nil {
			return err
		}
	}
	if state.Client.Version() == "2" {
		fmt.Fprintln(w, "  NFSv2 legacy mode: uploads and downloads below 2 GiB.")
	}
	if state.ProbeError != nil {
		_, err := fmt.Fprintln(w, "  "+paint(color, yellow, "Root probe: ")+label(state.ProbeError.Error()))
		return err
	}
	return nil
}

func (s *Shell) printSession(w io.Writer, color bool) error {
	section(w, "SESSION", color)
	state := s.Session
	root, rootTone := "Export root", ""
	if state.Export == "" {
		root = "No export selected"
	}
	if state.Escaped {
		root, rootTone = "Discovered directory (location unverified)", yellow
	}
	mode := func(on bool) string {
		if on {
			return "on"
		}
		return "off"
	}
	groups := "none"
	if len(state.Client.Auth.Groups) > 0 {
		values := make([]string, len(state.Client.Auth.Groups))
		for i, g := range state.Client.Auth.Groups {
			values[i] = strconv.FormatUint(uint64(g), 10)
		}
		groups = strings.Join(values, ", ")
	}
	rows := [][]cell{
		{{"Server", dim}, {label(state.Host) + "  (NFSv" + state.Client.Version() + " / " + strings.ToUpper(state.Client.Transport()) + ")", bold}},
		{{"Export", muted}, {label(state.Export), warm}},
		{{"Root", dim}, {root, rootTone}},
		{{"Identity", dim}, {label(state.Client.Identity()), ""}},
		{{"Groups", dim}, {groups, ""}},
		{{"Automatic", dim}, {"UID/GID " + mode(state.AutoUID) + "  |  root probe " + mode(state.AutoEscape), ""}},
		{{"Remote cwd", muted}, {label(state.CWD), warm}},
		{{"Local cwd", dim}, {label(s.LocalDir), ""}},
	}
	if state.Client.Security() != "sys" {
		rows[4][1].text = "Mapped by server"
		protection := "Authentication only; no GSS payload integrity or encryption"
		if state.Client.Security() == "krb5i" {
			protection = "Integrity: NFS arguments and results signed; no GSS encryption"
		}
		if state.Client.Security() == "krb5p" {
			protection = "Privacy: NFS arguments and results encrypted and authenticated"
		}
		rows = append(rows, []cell{{"Protection", dim}, {protection, yellow}})
		if expiry := state.Client.KerberosExpiry(); !expiry.IsZero() {
			status := expiry.Local().Format("2006-01-02 15:04:05 MST")
			if !time.Now().Before(expiry) {
				status += "; expired"
			}
			rows = append(rows, []cell{{"Ticket ends", dim}, {status, yellow}})
		}
		rows = append(rows, []cell{{"Renewals", dim}, {fmt.Sprintf("%d (automatic before RPC)", state.Client.KerberosRenewals()), ""}})
	}
	if state.Client.TLSActive() {
		protection := "TLS 1.3; server certificate verified"
		if !state.Client.TLSCertificateVerified() {
			protection = "TLS 1.3; certificate verification disabled (--tls-insecure)"
		}
		rows = append(rows, []cell{{"Transport security", dim}, {protection, yellow}})
	}
	if state.ProbeError != nil {
		rows = append(rows, []cell{{"Probe", dim}, {label(state.ProbeError.Error()), yellow}})
	}
	if err := table(w, rows, color); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}

func (s *Shell) prompt(ctx context.Context) string {
	if s.promptServer == "" || s.promptClient != s.Session.Client || s.promptHost != s.Session.Host {
		lookup, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		name, ip := s.Session.Client.ServerInfo(lookup)
		cancel()
		server := name
		if server == "" {
			server = ip
		}
		if server == "" {
			server = s.Session.Host
		}
		if server == "" {
			server = "unknown"
		}
		s.promptServer = label(server)
		if name != "" && ip != "" && name != ip {
			s.promptServer += " (" + label(ip) + ")"
		}
		s.promptClient, s.promptHost = s.Session.Client, s.Session.Host
	}
	return paint(s.Color, muted, "nfs") + " " + paint(s.Color, cyan, s.promptServer) + " " + paint(s.Color, warm, label(s.Session.CWD)) + " " + paint(s.Color, green, "> ")
}

func (s *Shell) printLegend() error {
	section(s.Out, "FILE COLORS", s.Color)
	rows := [][]cell{
		{{"Directories", warm}, {"Warm yellow; trailing /", ""}},
		{{"Common files", muted}, {"README, licenses, images, fonts, libraries, lockfiles", ""}},
		{{"Config / key hints", magenta}, {".env, .conf, .ini, private-key names, keystores", ""}},
		{{"Data / backup hints", lavender}, {"Databases, backups, archives, logs, documents", ""}},
		{{"Executable", green}, {"Other regular files with executable mode bits", ""}},
		{{"Modified this year", orange}, {fmt.Sprintf("Local modification year = %d", time.Now().Year()), ""}},
		{{"Symbolic link", linkTone}, {"name@ -> target; checked within the current session root", ""}},
		{{"Unavailable link", faint}, {"[missing], [access denied], [link loop], or [unverified]", ""}},
	}
	if err := table(s.Out, rows, s.Color); err != nil {
		return err
	}
	_, err := fmt.Fprint(s.Out, "\n  Filename hints only: file contents are never inspected.\n  Up to 32 links are inspected per ls; the rest show [unchecked].\n  Use ls LINK to inspect one link, or ls LINK/ to list its directory.\n\n")
	return err
}

func (s *Shell) printHelp() error {
	return s.printCommandHelp("")
}

func ownerLabel(a nfs.Attr) string {
	if a.Owner != "" || a.Group != "" {
		return label(a.Owner) + ":" + label(a.Group)
	}
	return fmt.Sprintf("%d:%d", a.UID, a.GID)
}
