package cli

import (
	"fmt"
	"strings"
)

var shellHelpGroups = []struct{ name, summary string }{
	{"browse", "Navigate remote and local files"},
	{"transfer", "Download, upload, resume and transfer trees"},
	{"metadata", "Manage files, permissions, ACLs and attributes"},
	{"identity", "Inspect identity, UID selection and session roots"},
	{"session", "Inspect connections, recovery and locks"},
	{"advanced", "Server-side copy, offload and storage operations"},
}

func shellCommandNames() []string {
	var names []string
	for _, command := range shellCommandCatalog {
		names = append(names, command.Name)
		names = append(names, command.Aliases...)
	}
	return names
}

func shellHelpTopics() []string {
	topics := []string{"all"}
	for _, group := range shellHelpGroups {
		topics = append(topics, group.name)
	}
	return append(topics, shellCommandNames()...)
}

// Wrap before adding ANSI styling so plain and colored help share a readable width.
func shellHelpLine(out *strings.Builder, text, indent string) {
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line) > len(indent) && len(line)+1+len(word) > 96 {
			out.WriteString(line + "\n")
			line = indent
		}
		if len(line) > len(indent) {
			line += " "
		}
		line += word
	}
	out.WriteString(line + "\n")
}

func (s *Shell) printCommandHelp(topic string) error {
	var out strings.Builder
	heading := func(title string) {
		out.WriteString("\n  " + paint(s.Color, bold+";"+cyan, title) + "\n")
	}
	line := func(text, indent string, syntax bool) {
		var wrapped strings.Builder
		shellHelpLine(&wrapped, text, indent)
		if syntax {
			out.WriteString(colorHelpSyntax(wrapped.String(), s.Color))
		} else {
			out.WriteString(colorHelpProse(wrapped.String(), s.Color))
		}
	}
	show := func(command shellCommandSpec) {
		for _, usage := range command.Usage {
			line(usage, "  ", true)
		}
		line(command.Summary, "    ", false)
		for _, note := range command.Notes {
			line(note, "    ", false)
		}
		out.WriteByte('\n')
	}
	if topic == "" {
		heading("SHELL COMMANDS")
		out.WriteString(colorHelpSyntax("  help COMMAND  |  help TOPIC  |  help all  |  COMMAND --help\n", s.Color))
		out.WriteString("  [] optional; | alternatives; ... repeatable. Quote paths containing spaces.\n")
		for _, group := range shellHelpGroups {
			heading(group.name + " - " + group.summary)
			var names []string
			for _, command := range shellCommandCatalog {
				if command.Group == group.name {
					names = append(names, command.Name)
					names = append(names, command.Aliases...)
				}
			}
			line(strings.Join(names, "  "), "    ", true)
		}
		heading("QUICK START")
		for _, row := range []string{
			"  exports                 Discover available resources\n",
			"  use /export             Select a remote export\n",
			"  ls [PATH]               List remote files\n",
			"  get REMOTE [LOCAL]      Download a file\n",
			"  put LOCAL [REMOTE]      Upload a file\n",
			"  help getpnfs            View advanced transfer options\n",
		} {
			out.WriteString(colorHelpColumns(row, s.Color))
		}
		out.WriteString(paint(s.Color, muted, "\n  Tab complete  |  Up/Down history  |  Ctrl+C twice quit\n"))
		out.WriteString("  Conflicts offer rename / cancel; overwrite where supported.\n\n")
	} else {
		found := false
		for _, command := range shellCommandCatalog {
			match := command.Name == topic
			for _, alias := range command.Aliases {
				match = match || alias == topic
			}
			if match {
				heading("HELP / " + topic)
				show(command)
				found = true
				break
			}
		}
		if !found {
			for _, group := range shellHelpGroups {
				if topic != "all" && topic != group.name {
					continue
				}
				found = true
				heading(strings.ToUpper(group.name) + " / " + group.summary)
				for _, command := range shellCommandCatalog {
					if command.Group == group.name {
						show(command)
					}
				}
			}
		}
		if !found {
			return fmt.Errorf("unknown help topic or command %q; use help to list topics", topic)
		}
	}
	_, err := fmt.Fprint(s.Out, out.String())
	return err
}

// shellCommandCatalog is the shared source of command names and discoverable help.
type shellCommandSpec struct {
	Name    string
	Aliases []string
	Group   string
	Usage   []string
	Summary string
	Notes   []string
}

var shellCommandCatalog = []shellCommandSpec{
	{Name: "exports", Group: "browse", Summary: "Discover resources and current-identity access (bounded)",
		Usage: []string{"exports [--recursive] [--depth N] [--path PATH ...] [--paths-file FILE]", "        [--max-entries N] [--discovery-timeout D] [--json]"},
		Notes: []string{"Repeat --path for known absolute paths. --recursive defaults to depth 3 unless --depth is set.", "--paths-file reads a local file of absolute server paths, one per line; relative filenames follow lcd. Surrounding whitespace, blank lines and full-line # comments are ignored. UTF-8 BOM and CRLF are accepted. The file is limited to 16 MiB, lines to less than 64 KiB, and combined paths to --max-entries."},
	},
	{Name: "use", Group: "browse", Summary: "Select an export",
		Usage: []string{"use EXPORT"},
	},
	{Name: "pwd", Group: "browse", Summary: "Show the remote working directory",
		Usage: []string{"pwd"},
	},
	{Name: "cd", Group: "browse", Summary: "Change remote directory (default: session root)",
		Usage: []string{"cd [PATH]"},
	},
	{Name: "ls", Group: "browse", Summary: "List remote files; optionally include archive status",
		Usage: []string{"ls [--offline] [PATH]"},
		Notes: []string{"Options may appear before or after PATH. Use -- before a literal path starting with -."},
	},
	{Name: "stat", Group: "browse", Summary: "Show remote attributes; optionally include archive status",
		Usage: []string{"stat [--offline] PATH"},
		Notes: []string{"Options may appear before or after PATH. Use -- before a literal path starting with -."},
	},
	{Name: "cat", Group: "browse", Summary: "Safe text preview",
		Usage: []string{"cat PATH"},
	},
	{Name: "hex", Group: "browse", Summary: "Hex preview (256 bytes)",
		Usage: []string{"hex PATH"},
	},
	{Name: "lpwd", Group: "browse", Summary: "Show the local working directory",
		Usage: []string{"lpwd"},
	},
	{Name: "lcd", Group: "browse", Summary: "Change the local working directory",
		Usage: []string{"lcd PATH"},
	},
	{Name: "lls", Group: "browse", Summary: "List local files",
		Usage: []string{"lls [PATH]"},
	},
	{Name: "legend", Group: "browse", Summary: "Explain file colors and link states",
		Usage: []string{"legend [PATH]"},
		Notes: []string{"With PATH, explain the filename/path hint using metadata only; does not read file contents. Use -- before a literal path starting with -."},
	},
	{Name: "get", Group: "transfer", Summary: "Download with progress",
		Usage: []string{"get REMOTE [LOCAL]"},
	},
	{Name: "put", Group: "transfer", Summary: "Upload with progress",
		Usage: []string{"put LOCAL [REMOTE]"},
	},
	{Name: "reget", Group: "transfer", Summary: "Verify partial content; optional bounded reconnects (0..30)",
		Usage: []string{"reget [--retries N] REMOTE [LOCAL]", "reget --failover HOST:PORT,SPN,TLS_NAME REMOTE [LOCAL]", "reget --referral SERVER=HOST:PORT,SPN,TLS_NAME REMOTE [LOCAL]", "reget --reclaim-locks REMOTE [LOCAL]"},
		Notes: []string{"Recovery modes cannot be combined. --retries accepts 0..30 reconnects.", "--failover approves protected read targets; --referral approves fs_locations/MOVED servers.", "Repeat --failover or --referral up to eight times. Each requires its own target argument.", "--reclaim-locks allows one restart reclaim (NFSv4 or startup --nlm-reclaim)."},
	},
	{Name: "reput", Group: "transfer", Summary: "Verify prefix and resume upload under a whole-file write lock",
		Usage: []string{"reput LOCAL REMOTE"},
	},
	{Name: "replace", Group: "transfer", Summary: "Explicit ACL-preserving replacement (v3 requires NFSACL)",
		Usage: []string{"replace LOCAL REMOTE"},
	},
	{Name: "gettree", Group: "transfer", Summary: "Download a directory tree",
		Usage: []string{"gettree [OPTIONS] REMOTE LOCAL"},
		Notes: []string{"--merge: reuse existing directories; never overwrite files or follow destination links.", "--links: preserve symbolic links as links, including dangling links; never follow them.", "--hardlinks: preserve hard-link relationships within the transferred tree.", "--preserve-mode: preserve ordinary POSIX permission bits; requires a Unix client.", "--preserve-mtime: preserve modification times. ACLs, ownership and special mode bits are not preserved.", "--skip-offline: skip only files confirmed offline. Unknown states download normally; metadata errors fail.", "Options may appear before or after paths. Use -- before literal paths starting with -."},
	},
	{Name: "puttree", Group: "transfer", Summary: "Upload a directory tree",
		Usage: []string{"puttree [OPTIONS] LOCAL REMOTE"},
		Notes: []string{"--merge: reuse existing directories; never overwrite files or follow destination links.", "--links: preserve symbolic links as links, including dangling links; never follow them.", "--hardlinks: preserve hard-link relationships within the transferred tree.", "--preserve-mode: preserve ordinary POSIX permission bits; requires a Unix client.", "--preserve-mtime: preserve modification times. ACLs, ownership and special mode bits are not preserved.", "Options may appear before or after paths. Use -- before literal paths starting with -."},
	},
	{Name: "getrange", Group: "transfer", Summary: "Download bytes covered by one held lock",
		Usage: []string{"getrange REMOTE LOCAL OFFSET LENGTH"},
	},
	{Name: "putrange", Group: "transfer", Summary: "Write bytes in place under a covering write lock",
		Usage: []string{"putrange LOCAL REMOTE OFFSET"},
	},
	{Name: "getplus", Group: "transfer", Summary: "Download using v4.2 data/hole replies",
		Usage: []string{"getplus REMOTE LOCAL"},
	},
	{Name: "getpnfs", Group: "transfer", Summary: "Download through approved pNFS data servers; recovery options require krb5i/krb5p",
		Usage: []string{"getpnfs REMOTE LOCAL [--layout file|flex] [--read-failover|--mirror-failover|--refresh-devices|--session-trunking] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] DS=TARGET [...]", "getpnfs REMOTE LOCAL --layout block [--block-volume IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN]", "getpnfs ... --layout block --read-failover [--block-alternate PRIMARY_URL=ALTERNATE_URL ...]", "getpnfs REMOTE LOCAL --layout object [--osd-secure] --osd-target iscsi://IP:PORT/IQN/LUN ... --osd-initiator IQN"},
		Notes: []string{"Download through signature-verified images or approved iSCSI storage; server fencing required", "Bounded read-only recovery with pinned device, geometry, signatures and security; requires a valid layout and lease", "Download dense RAID0 OSD-1 objects through identity-verified approved iSCSI LUNs", "DS=TARGET means ADVERTISED_IP:PORT=APPROVED_IP:PORT[@TLS_NAME].", "--block-security TARGET_URL=PROFILE_FILE sets per-target CHAP and digest policy; profiles reference separate secret files.", "Block storage requires 1..64 approved images or iSCSI targets and server fencing.", "--osd-security TARGET_URL=PROFILE_FILE sets OSD target security; --osd-secure requires secure OSD access."},
	},
	{Name: "putrangepnfs", Group: "transfer", Summary: "Write a range through approved pNFS storage",
		Usage: []string{"putrangepnfs LOCAL REMOTE OFFSET --layout object --object-write [--osd-secure] --osd-target URL ... --osd-initiator IQN [--osd-security URL=PROFILE_FILE]", "putrangepnfs LOCAL REMOTE OFFSET [--layout file|flex|block] [--block-write] [--block-volume IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN] [--extend] [--block-journal STATE] [--block-resume] [--write-failover] [--refresh-devices] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] DS=TARGET [...]"},
		Notes: []string{"Write through approved pNFS storage; resume requires a fresh whole-file lock", "DS=TARGET means ADVERTISED_IP:PORT=APPROVED_IP:PORT[@TLS_NAME].", "--block-security TARGET_URL=PROFILE_FILE sets per-target CHAP and digest policy; profiles reference separate secret files.", "Block storage requires 1..64 approved images or iSCSI targets and server fencing.", "--osd-security TARGET_URL=PROFILE_FILE sets OSD target security; --osd-secure requires secure OSD access.", "Object writes require --layout object --object-write, an existing file and a whole-file lock; no creation or growth.", "--block-resume requires --block-journal and a fresh whole-file lock."},
	},
	{Name: "putpnfs", Group: "transfer", Summary: "Create and upload a new file through approved pNFS storage",
		Usage: []string{"putpnfs LOCAL REMOTE [--layout file|flex|block] [--block-write] [--block-volume IMAGE ... | --block-target iscsi://IP:PORT/IQN/LUN ... --block-initiator IQN] [--block-journal STATE] [--write-failover] [--refresh-devices] [--parallel 1..8] [--ds-spn TARGET=nfs/HOST] DS=TARGET [...]"},
		Notes: []string{"DS=TARGET means ADVERTISED_IP:PORT=APPROVED_IP:PORT[@TLS_NAME].", "--block-security TARGET_URL=PROFILE_FILE sets per-target CHAP and digest policy; profiles reference separate secret files.", "Block storage requires 1..64 approved images or iSCSI targets and server fencing.", "Object layout is not supported by putpnfs. Use putrangepnfs for finite object writes."},
	},
	{Name: "chmod", Group: "metadata", Summary: "Change permissions",
		Usage: []string{"chmod OCTAL PATH"},
	},
	{Name: "ln", Group: "metadata", Summary: "Create a hard link or a symbolic link (NFSv3/v4)",
		Usage: []string{"ln SOURCE DESTINATION", "ln -s TARGET LINK"},
		Notes: []string{"Destination is an exact new name; existing entries are never replaced. Hard-link sources must be regular files, not symlinks.", "Symbolic-link targets are stored verbatim and may be missing. Use -- before paths beginning with -.", "Uses the current identity without automatic UID selection; held locks must be released."},
	},
	{Name: "readlink", Group: "browse", Summary: "Show the stored target of a symbolic link without following it",
		Usage: []string{"readlink PATH"},
		Notes: []string{"Control characters are escaped for terminal display."},
	},
	{Name: "chown", Group: "metadata", Summary: "Set and verify the owner and optionally the group",
		Usage: []string{"chown OWNER[:GROUP] PATH"},
		Notes: []string{"NFSv2/v3 use numeric IDs; NFSv4 uses exact owner/group strings accepted by the server.", "The final path must not be a symlink. Uses the current identity; held locks must be released.", "A lost mutation reply or failed readback reports an uncertain result and is never blindly retried."},
	},
	{Name: "chgrp", Group: "metadata", Summary: "Set and verify the group without changing the owner",
		Usage: []string{"chgrp GROUP PATH"},
		Notes: []string{"Uses the same version, identity, symlink and readback rules as chown."},
	},
	{Name: "mkdir", Group: "metadata", Summary: "Create a directory",
		Usage: []string{"mkdir PATH"},
	},
	{Name: "rm", Group: "metadata", Summary: "Unlink one file or symlink; never recursive",
		Usage: []string{"rm PATH"},
	},
	{Name: "rmdir", Group: "metadata", Summary: "Remove one empty directory",
		Usage: []string{"rmdir PATH"},
	},
	{Name: "mv", Group: "metadata", Summary: "Rename to an exact name; may replace destination",
		Usage: []string{"mv SOURCE DESTINATION"},
	},
	{Name: "acl", Group: "metadata", Summary: "Read NFSv2/v3 ACLs or ordered NFSv4 ACL JSON",
		Usage: []string{"acl PATH"},
	},
	{Name: "getacl", Group: "metadata", Summary: "Export versioned ACL JSON; dacl/sacl require NFSv4",
		Usage: []string{"getacl PATH LOCAL [acl|dacl|sacl]"},
	},
	{Name: "setacl", Group: "metadata", Summary: "Apply complete ACL JSON with exact readback; fixed identity",
		Usage: []string{"setacl PATH LOCAL"},
	},
	{Name: "label", Group: "metadata", Summary: "Read an opaque NFSv4.2 security label as format/policy/hex JSON",
		Usage: []string{"label PATH"},
	},
	{Name: "setlabel", Group: "metadata", Summary: "Set and verify one NFSv4.2 security label (up to 4096 bytes)",
		Usage: []string{"setlabel PATH FORMAT POLICY HEX"},
	},
	{Name: "xattrs", Group: "metadata", Summary: "List RFC 8276 user attribute names as JSON",
		Usage: []string{"xattrs PATH"},
	},
	{Name: "getxattr", Group: "metadata", Summary: "Read one user attribute as key/hex JSON",
		Usage: []string{"getxattr PATH KEY"},
	},
	{Name: "setxattr", Group: "metadata", Summary: "Write and verify a user attribute (up to 65536 bytes)",
		Usage: []string{"setxattr PATH KEY create|replace|either HEX"},
	},
	{Name: "removexattr", Group: "metadata", Summary: "Remove one user attribute and verify absence",
		Usage: []string{"removexattr PATH KEY"},
	},
	{Name: "namedattrs", Group: "metadata", Summary: "List NFSv4 named attributes as JSON",
		Usage: []string{"namedattrs PATH"},
	},
	{Name: "getnamedattr", Group: "metadata", Summary: "Export one named attribute to a new local file",
		Usage: []string{"getnamedattr PATH NAME LOCAL"},
	},
	{Name: "id", Group: "identity", Summary: "Show connection and identity",
		Usage: []string{"id"},
	},
	{Name: "uid", Group: "identity", Summary: "Set identity; disable auto-uid",
		Usage: []string{"uid UID [GID [G1,G2]]"},
		Notes: []string{"UID and GID are unsigned 32-bit integers. Groups are comma-separated. Requires AUTH_SYS.", "Changing identity requires no held locks; Kerberos identity is fixed for the connection."},
	},
	{Name: "uid-scan", Group: "identity", Summary: "Find UIDs with read access (AUTH_SYS)",
		Usage: []string{"uid-scan PATH [START [END]]"},
		Notes: []string{"Default range: 0..65535; with START only, END remains 65535. Stops after 20 matches."},
	},
	{Name: "auto-uid", Group: "identity", Summary: "Toggle owner UID/GID selection",
		Usage: []string{"auto-uid on|off"},
		Notes: []string{"Owner UID/GID selection is available only for NFSv3 AUTH_SYS."},
	},
	{Name: "auto-uid-scan", Group: "identity", Summary: "Toggle automatic UID scanning after access denial (AUTH_SYS)",
		Usage: []string{"auto-uid-scan on|off"},
	},
	{Name: "root", Group: "identity", Summary: "Inspect, verify, restore, select, or probe the session root",
		Usage: []string{"root [info|verify|reset|discovered|probe]"},
		Notes: []string{"No action means info. reset restores the export root; discovered selects the saved discovery.", "verify reports evidence; independent server-side confirmation is required to verify location."},
	},
	{Name: "escape", Group: "identity", Summary: "Alias for root probe",
		Usage: []string{"escape"},
	},
	{Name: "auto-escape", Group: "identity", Summary: "Toggle probe on subsequent use",
		Usage: []string{"auto-escape on|off"},
	},
	{Name: "squash", Group: "identity", Summary: "Probe whether the server remaps UID 0",
		Usage: []string{"squash"},
		Notes: []string{"Creates a temporary probe file as UID 0, checks ownership, then removes it. Requires AUTH_SYS."},
	},
	{Name: "info", Group: "session", Summary: "Inspect connection, identity and server claims",
		Usage: []string{"info [--json]"},
	},
	{Name: "mounts", Group: "session", Summary: "Inspect legacy MOUNT records (NFSv2/v3)",
		Usage: []string{"mounts [--json]"},
		Notes: []string{"Historical records may be stale or incomplete; they do not prove active clients or describe NFSv4 sessions.", "Read-only, bounded to 4096 records and 5 seconds. NFSv4 does not contact mountd."},
	},
	{Name: "handle", Group: "session", Summary: "Inspect an opaque filehandle with its connection context",
		Usage: []string{"handle [PATH] [--json]"},
		Notes: []string{"PATH defaults to the current directory. The final symbolic link is not followed; trailing slashes are rejected except for /. Identity stays fixed.", "Hex contains protocol bytes, not process memory. JSON is diagnostic export only; handles may become stale and cannot be imported."},
	},
	{Name: "capabilities", Group: "session", Summary: "Inspect advertised features without mutation probes",
		Usage: []string{"capabilities [PATH] [--json]"},
		Notes: []string{"--json may appear before or after PATH. Use -- before a literal path starting with -."},
	},
	{Name: "access", Group: "session", Summary: "Observe server permissions under the current identity",
		Usage: []string{"access PATH [--json]"},
		Notes: []string{"--json may appear before or after PATH. Use -- before a literal path starting with -."},
	},
	{Name: "reconnect", Group: "session", Summary: "Fresh connection, explicit discard, or bounded server-restart reclaim",
		Usage: []string{"reconnect [--discard-locks|--reclaim-locks]"},
	},
	{Name: "migrate", Group: "session", Summary: "Move retained state, continue without the source, or arm one exact-session automatic failover",
		Usage: []string{"migrate [--source-unavailable|--arm-failover] SERVER=HOST:PORT,SPN,TLS_NAME", "migrate --status"},
		Notes: []string{"Show whether the automatic failover approval is armed or consumed"},
	},
	{Name: "lock-save", Group: "session", Summary: "Save locks or arm an empty namespace; record acquisition/release phases for live-session recovery",
		Usage: []string{"lock-save ABSOLUTE_JOURNAL"},
	},
	{Name: "offload-reconcile", Group: "session", Summary: "Verify a durable completion receipt and complete destination bytes after a process crash",
		Usage: []string{"offload-reconcile ABSOLUTE_JOURNAL OPERATION_ID DESTINATION"},
	},
	{Name: "lock", Group: "session", Summary: "Obtain a lock; --wait polls conflicts, --wait-native waits for legacy NLM GRANTED or GRANTED_MSG callbacks",
		Usage: []string{"lock [--wait DURATION|--wait-native DURATION] PATH read|write [OFFSET LENGTH|eof]"},
		Notes: []string{"Omit OFFSET and LENGTH to lock the whole file. Use OFFSET eof for a range to end of file.", "DURATION uses a unit, for example 5s. --wait polls; --wait-native uses legacy NLM callbacks."},
	},
	{Name: "locktest", Group: "session", Summary: "Observe NLM (v2/v3 AUTH_SYS) or NFSv4 LOCKT conflicts; no lock acquired",
		Usage: []string{"locktest PATH read|write [OFFSET LENGTH|eof]"},
		Notes: []string{"Omit OFFSET and LENGTH for the whole file; OFFSET eof tests a range to end of file."},
	},
	{Name: "nlmrecover", Group: "session", Summary: "Release durably confirmed NLM locks from a crashed session; requires a fresh connection",
		Usage: []string{"nlmrecover"},
	},
	{Name: "locks", Group: "session", Summary: "List held and uncertain locks",
		Usage: []string{"locks"},
	},
	{Name: "unlock", Group: "session", Summary: "Release a lock by its displayed ID",
		Usage: []string{"unlock ID"},
	},
	{Name: "help", Group: "session", Summary: "Show the overview, one category, one command, or the full reference",
		Usage: []string{"help [TOPIC|COMMAND|all]"},
		Notes: []string{"COMMAND --help and COMMAND -h show command help without contacting the server."},
	},
	{Name: "exit", Aliases: []string{"quit"}, Group: "session", Summary: "Close the session (alias: quit)",
		Usage: []string{"exit"},
	},
	{Name: "seek", Group: "advanced", Summary: "Find the next data/hole boundary (v4.2)",
		Usage: []string{"seek PATH OFFSET data|hole"},
	},
	{Name: "advise", Group: "advanced", Summary: "Suggest I/O hints on a held whole-file lock (v4.2)",
		Usage: []string{"advise PATH OFFSET LENGTH HINT[,HINT...]"},
	},
	{Name: "copyrange", Group: "advanced", Summary: "Server copy into an existing file (v4.2)",
		Usage: []string{"copyrange SRC DST SRC_OFFSET DST_OFFSET LENGTH"},
	},
	{Name: "copyasync", Group: "advanced", Summary: "Server copy with bounded callback waiting (--offload)",
		Usage: []string{"copyasync SRC DST SRC_OFFSET DST_OFFSET LENGTH WAIT"},
	},
	{Name: "copyfrom", Group: "advanced", Summary: "Copy from another explicit server/export (--offload; sys or explicit GSSv3 krb5p/TCP)",
		Usage: []string{"copyfrom SOURCE_IP:PORT EXPORT SRC DST SRC_OFFSET DST_OFFSET LENGTH WAIT DEST_IP:PORT [SOURCE_IP:PORT ...] [--source-spn nfs/HOST --copy-user USER@DOMAIN] [--source-tls-name HOST]"},
	},
	{Name: "writesame", Group: "advanced", Summary: "Repeat a block at the server (--offload, v4.2)",
		Usage: []string{"writesame PATH OFFSET REPEAT_COUNT HEX_PATTERN WAIT"},
	},
	{Name: "writeadb", Group: "advanced", Summary: "Initialize application data blocks (--offload, v4.2)",
		Usage: []string{"writeadb PATH OFFSET BLOCK_SIZE BLOCK_COUNT WAIT [--number OFFSET FIRST] [--pattern OFFSET HEX]"},
	},
	{Name: "clonerange", Group: "advanced", Summary: "Server clone into an existing file (v4.2)",
		Usage: []string{"clonerange SRC DST SRC_OFFSET DST_OFFSET LENGTH"},
	},
	{Name: "allocate", Group: "advanced", Summary: "Reserve storage; may extend file size (v4.2)",
		Usage: []string{"allocate PATH OFFSET LENGTH"},
	},
	{Name: "deallocate", Group: "advanced", Summary: "Discard range bytes into a hole (v4.2)",
		Usage: []string{"deallocate PATH OFFSET LENGTH"},
	},
}
