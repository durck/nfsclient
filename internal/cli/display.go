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
	groups := []struct {
		title string
		items [][2]string
	}{
		{"BROWSE", [][2]string{
			{"exports", "List exports and client rules"},
			{"use EXPORT", "Select an export"},
			{"pwd | cd [PATH]", "Show / change remote directory"},
			{"ls [PATH] | stat PATH", "List files / show attributes"},
			{"acl PATH", "Read NFSv2/v3 ACLs or ordered NFSv4 ACL JSON"},
			{"getacl PATH LOCAL [acl|dacl|sacl]", "Export versioned ACL JSON; dacl/sacl require NFSv4"},
			{"setacl PATH LOCAL", "Apply complete ACL JSON with exact readback; fixed identity"},
			{"legend", "Explain file colors and link states"},
		}},
		{"FILES", [][2]string{
			{"cat PATH", "Safe text preview"},
			{"hex PATH", "Hex preview (256 bytes)"},
			{"get REMOTE [LOCAL]", "Download with progress"},
			{"getplus REMOTE LOCAL", "Download using v4.2 data/hole replies"},
			{"getpnfs REMOTE LOCAL [--layout file|flex] [--read-failover|--mirror-failover|--refresh-devices|--session-trunking] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] DS=TARGET [...]", "Download through approved pNFS data servers; recovery options require krb5i/krb5p"},
			{"getpnfs REMOTE LOCAL --layout block [--block-volume IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN]", "Download through signature-verified images or approved iSCSI storage; server fencing required"},
			{"--block-security TARGET_URL=PROFILE_FILE / --osd-security TARGET_URL=PROFILE_FILE", "Explicit per-target CHAP and digest policy; profile references separate secret files"},
			{"getpnfs ... --layout block --read-failover [--block-alternate PRIMARY_URL=ALTERNATE_URL ...]", "Bounded read-only recovery with pinned device, geometry, signatures and security; requires a valid layout and lease"},
			{"getpnfs REMOTE LOCAL --layout object [--osd-secure] --osd-target iscsi://IP:PORT/IQN/LUN ... --osd-initiator IQN", "Download dense RAID0 OSD-1 objects through identity-verified approved iSCSI LUNs"},
			{"putrangepnfs LOCAL REMOTE OFFSET --layout object --object-write [--osd-secure] --osd-target URL ... --osd-initiator IQN [--osd-security URL=PROFILE_FILE]", "Secured finite writes to an existing OSD file under a whole-file lock; no creation or growth"},
			{"reput LOCAL REMOTE", "Verify prefix and resume upload under a whole-file write lock"},
			{"reget [--retries N] REMOTE [LOCAL]", "Verify partial content; optional bounded reconnects (0..30)"},
			{"reget --failover HOST:PORT,SPN,TLS_NAME REMOTE [LOCAL]", "Approved protected read target; repeat up to eight times"},
			{"reget --referral SERVER=HOST:PORT,SPN,TLS_NAME REMOTE [LOCAL]", "Follow protected fs_locations/MOVED through approved servers; repeat up to eight approvals"},
			{"migrate [--source-unavailable|--arm-failover] SERVER=HOST:PORT,SPN,TLS_NAME", "Move retained state, continue without the source, or arm one exact-session automatic failover"},
			{"migrate --status", "Show whether the automatic failover approval is armed or consumed"},
			{"lock-save ABSOLUTE_JOURNAL", "Save locks or arm an empty namespace; record acquisition/release phases for live-session recovery"},
			{"offload-reconcile JOURNAL ID DESTINATION", "Verify a durable completion receipt and complete destination bytes after a process crash"},
			{"reget --reclaim-locks REMOTE [LOCAL]", "Verify partial content; one restart reclaim (NFSv4 or --nlm-reclaim)"},
			{"getrange REMOTE LOCAL OFFSET LENGTH", "Download bytes covered by one held lock"},
			{"putrange LOCAL REMOTE OFFSET", "Write bytes in place under a covering write lock"},
			{"putrangepnfs LOCAL REMOTE OFFSET [--layout file|flex|block] [--block-write] [--block-volume IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN] [--extend] [--block-journal STATE] [--block-resume] [--write-failover] [--refresh-devices] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] DS=TARGET [...]", "Write through approved pNFS storage; resume requires a fresh whole-file lock"},
			{"putpnfs LOCAL REMOTE [--layout file|flex|block] [--block-write] [--block-volume IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN] [--block-journal STATE] [--write-failover] [--refresh-devices] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] DS=TARGET [...]", "Create and upload a new file through approved pNFS storage"},
			{"gettree [OPTIONS] REMOTE LOCAL", "Download tree: --merge --links --hardlinks --preserve-mode --preserve-mtime"},
			{"puttree [OPTIONS] LOCAL REMOTE", "Upload tree: --merge --links --hardlinks --preserve-mode --preserve-mtime"},
			{"put LOCAL [REMOTE]", "Upload with progress"},
			{"replace LOCAL REMOTE", "Explicit ACL-preserving replacement (v3 requires NFSACL)"},
			{"chmod OCTAL PATH", "Change permissions"},
			{"mkdir PATH", "Create a directory"},
			{"rm PATH", "Unlink one file or symlink; never recursive"},
			{"rmdir PATH", "Remove one empty directory"},
			{"mv SOURCE DESTINATION", "Rename to an exact name; may replace destination"},
			{"seek PATH OFFSET data|hole", "Find the next data/hole boundary (v4.2)"},
			{"advise PATH OFFSET LENGTH HINT[,HINT...]", "Suggest I/O hints on a held whole-file lock (v4.2)"},
			{"copyrange SRC DST SRC_OFFSET DST_OFFSET LENGTH", "Server copy into an existing file (v4.2)"},
			{"copyasync SRC DST SRC_OFFSET DST_OFFSET LENGTH WAIT", "Server copy with bounded callback waiting (--offload)"},
			{"copyfrom SOURCE_IP:PORT EXPORT SRC DST SRC_OFFSET DST_OFFSET LENGTH WAIT DEST_IP:PORT [SOURCE_IP:PORT ...] [--source-spn nfs/HOST --copy-user USER@DOMAIN] [--source-tls-name HOST]", "Copy from another explicit server/export (--offload; sys or explicit GSSv3 krb5p/TCP)"},
			{"writesame PATH OFFSET REPEAT_COUNT HEX_PATTERN WAIT", "Repeat a block at the server (--offload, v4.2)"},
			{"writeadb PATH OFFSET BLOCK_SIZE BLOCK_COUNT WAIT [--number OFFSET FIRST] [--pattern OFFSET HEX]", "Initialize application data blocks (--offload, v4.2)"},
			{"clonerange SRC DST SRC_OFFSET DST_OFFSET LENGTH", "Server clone into an existing file (v4.2)"},
			{"allocate PATH OFFSET LENGTH", "Reserve storage; may extend file size (v4.2)"},
			{"deallocate PATH OFFSET LENGTH", "Discard range bytes into a hole (v4.2)"},
		}},
		{"SESSION", [][2]string{
			{"id", "Show connection and identity"},
			{"reconnect [--discard-locks|--reclaim-locks]", "Fresh connection, explicit discard, or bounded server-restart reclaim"},
			{"lock [--wait|--wait-native DURATION] PATH read|write [OFFSET LENGTH|eof]", "Obtain a lock; --wait polls conflicts, --wait-native waits for legacy NLM GRANTED or GRANTED_MSG callbacks"},
			{"nlmrecover", "Release durably confirmed NLM locks from a crashed session; requires a fresh connection"},
			{"label PATH", "Read an opaque NFSv4.2 security label as format/policy/hex JSON"},
			{"setlabel PATH FORMAT POLICY HEX", "Set and verify one NFSv4.2 security label (up to 4096 bytes)"},
			{"xattrs PATH", "List RFC 8276 user attribute names as JSON"},
			{"getxattr PATH KEY", "Read one user attribute as key/hex JSON"},
			{"setxattr PATH KEY create|replace|either HEX", "Write and verify a user attribute (up to 65536 bytes)"},
			{"removexattr PATH KEY", "Remove one user attribute and verify absence"},
			{"locks / unlock ID", "List held/uncertain locks or release a lock"},
			{"locktest PATH read|write [OFFSET LENGTH|eof]", "Observe NFSv2/v3 NLM conflicts without acquiring a lock (AUTH_SYS)"},
			{"uid UID [GID [G1,G2]]", "Set identity; disable auto-uid"},
			{"auto-uid on|off", "Toggle owner UID/GID selection"},
			{"root info|verify|reset", "Inspect / verify / restore root"},
			{"root discovered|probe", "Select saved discovery / probe"},
			{"escape", "Alias for root probe"},
			{"auto-escape on|off", "Toggle probe on subsequent use"},
			{"lpwd | lcd PATH", "Show / change local directory"},
			{"lls [PATH]", "List local files"},
			{"help | exit | quit", "Show help / close session"},
		}},
	}
	width := 26
	for _, group := range groups {
		for _, item := range group.items {
			width = max(width, len(item[0])+2)
		}
	}
	for _, group := range groups {
		section(s.Out, group.title, s.Color)
		for _, item := range group.items {
			if _, err := fmt.Fprintf(s.Out, "  %s%s%s\n", paint(s.Color, bold, item[0]), strings.Repeat(" ", width-len(item[0])), item[1]); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(s.Out, "\n  "+paint(s.Color, dim, "Tab  complete   |   Up/Down  history   |   Ctrl+C twice  quit")+"\n  "+paint(s.Color, muted, "Quote paths with spaces. Conflicts offer rename / cancel; overwrite where supported.")+"\n")
	return err
}

func ownerLabel(a nfs.Attr) string {
	if a.Owner != "" || a.Group != "" {
		return label(a.Owner) + ":" + label(a.Group)
	}
	return fmt.Sprintf("%d:%d", a.UID, a.GID)
}
