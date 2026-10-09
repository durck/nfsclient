# Using nfsclient

[Quick start](../README.md) | [Advanced operations](ADVANCED.md)

Detailed interactive behavior, discovery and scanning options. Use `help COMMAND`
inside the client or `nfsclient help shell COMMAND` before connecting for syntax.

## Contents

- [Everyday use](#everyday-use)
- [Help and completion](#help-and-completion)
- [Resource discovery](#resource-discovery)
- [Identity and connection policy](#identity-and-connection-policy)
- [Network scan](#network-scan)

## Everyday use

```text
exports
use /data
info
capabilities .
ls
cd documents
stat notes.txt
access notes.txt
cat notes.txt
get notes.txt local-notes.txt
put "local report.txt" "new report.txt"
chmod 640 "new report.txt"
ln notes.txt notes-copy.txt
ln -s notes.txt latest.txt
readlink latest.txt
handle notes.txt --json
id
exit
```

`ln` creates an exact new name without replacing existing entries (NFSv3/v4).
Hard-link sources must be regular files; `ln -s` stores its target literally,
including missing targets. Use `ln [-s] -- SOURCE DESTINATION` for names starting
with `-`. `readlink` displays the stored target with terminal controls escaped.
`chown OWNER[:GROUP] PATH` and `chgrp GROUP PATH` change ownership and verify it:
v2/v3 require numeric IDs; v4 sends exact server-recognized owner/group strings.
They reject final symlinks and trailing slashes except for `/`. Mutations keep
the current identity, require held locks to be released, and do not automatically retry an
uncertain result. See [ownership semantics](ADVANCED.md#permissions-and-replacement).

`info` includes the requested host, actual NFS/MOUNT peers and identity.
`mounts [--json]` reads legacy MOUNT records with a five-second/4096-entry bound;
records may be stale or incomplete and do not prove active clients. NFSv4 returns
unavailable without contacting mountd. `handle [PATH] [--json]` exports the
opaque handle as hex with connection context; it does not follow the final
symlink or accept trailing slashes except for `/`. This is diagnostic output,
not a restorable session or an import format. Handles can become stale.

The interactive prompt shows the current server name and connected IP, followed
by the remote directory: `nfs nas.example.test (192.0.2.10) /documents >`.
For an IP target, a best-effort reverse DNS lookup uses the selected DNS settings
and a 250 ms deadline. If no name is available, only the IP is shown. The display
is cached per connection and refreshed after reconnect or server changes.

Remote paths use `/`; relative paths and symlinks are interpreted within the
selected root. Commands do not invoke a local shell or expand wildcards and
environment variables. Quote names containing spaces. Tab completes commands,
help topics, options, supported values and local/remote paths, including quoted
paths. Remote suggestions use the current identity with a two-second deadline;
completion never switches UID or probes for another root. Optional `--history
FILE` persists history, otherwise it stays in memory.

### Help and completion

The default help is a short overview. Open the relevant topic or command for
its complete syntax; existing option names remain supported.

```text
nfsclient --help
nfsclient help auth
nfsclient help tls
nfsclient --help-all
nfsclient help scan
nfsclient help shell gettree
```

Inside the client, use `help`, `help transfer`, `help gettree`, or `gettree --help`.
`help all` prints the full shell reference. Standalone `COMMAND -h` also works.
The same reference is available before connecting via `nfsclient help shell`.

Help uses cyan for headings, command names and flags, warm yellow for arguments
and example values, and gray for syntax separators and keyboard hints. Descriptions
stay neutral. Colors follow the same policy as listings: `--color=auto` colors
terminal output, `--color=always` forces colors, and `--color=never` disables them.
Automatic colors are also disabled by `NO_COLOR`, `TERM=dumb`, or redirected output.
The color option works with every help route, for example
`nfsclient help shell gettree --color=always` and `nfsclient scan --help --color=never`.
Tree-transfer options may precede or follow paths. For `ls`, `stat`, inspection
and tree-transfer commands, `--` ends options so a filename such as `--offline`
can be used literally. Other commands show their required option positions in
their individual help.

Interactive Tab completion works immediately. For operating-system shell
completion, install the executable as `nfsclient.exe` on Windows or `nfsclient`
on Linux: generated scripts register that command name. Generate its script
with `nfsclient completion bash`, `zsh`, `fish` or `powershell`. See
`nfsclient completion SHELL --help` for installation instructions. For the
current PowerShell session:

```powershell
.\nfsclient.exe completion powershell | Out-String | Invoke-Expression
```

Listings escape control characters and show link targets. `cat` validates a
bounded UTF-8 preview before printing to a terminal; redirected output retains
raw bytes. `hex` provides a bounded binary preview. `lls`, `lpwd` and `lcd` operate
on local files. `legend` explains colors; `--color=never` or `NO_COLOR` disables them.

Remote and local listings use the same palette. Directories are warm yellow,
configuration names blue, credential-related names pink, and data/backup names
lavender. Familiar system and boilerplate names are pale gray: for example,
`Windows`, `ProgramData`, `Program Files`, `System Volume Information`,
`desktop.ini`, `Thumbs.db`, and `README.md`. These are case-insensitive exact
basename hints, not an assessment of contents or safety; directory children
keep their own colors. **Modification dates in the current local calendar year
are always orange**, including gray entries and links with unavailable targets.
Link status labels distinguish missing/looping targets (red), denied/unverified
targets (amber), and unchecked targets (gray). Active transfers are turquoise,
successful completion green, and failures red; status text remains available
without color.

The listing's `OWNER` column omits the local placeholder suffixes `@localhost`
and `@localdomain` from owner/group names (for example, `root:root`). Other
domains remain visible; `stat` JSON retains the exact server-provided values.

Hints cover on-premises infrastructure as well as cloud tooling:

- AD/Samba identity stores, GPP files under `Preferences`, Windows deployment
  files, IIS/Java service configuration, Oracle wallets and DB connection profiles.
- Jenkins keys, network configurations, administrative scripts, command history,
  mail archives, database/1C dumps, virtual disks and backup formats.
- AWS, Docker, Kubernetes, Azure, Google Cloud and Terraform configuration/state.

Known paths refine ambiguous names: `.docker/config.json` gets a credential hint,
while an ordinary `config.json` remains a data file. Matching uses the known
listing/export path without extra network probes; it cannot identify paths above
an export or infer a server's real storage layout. Directory hints do not propagate
to children. Repeated backup/archive suffixes preserve the underlying hint
(`id_rsa.bak.old`, `credentials.xml.tar.gz`); explicit `.example`, `.sample`,
`.template`, `.dist` and `.default` suffixes receive a configuration hint.
Use `legend PATH` to explain one remote entry, including with color disabled.
These are name/path hints, never confirmation that credentials exist or are valid.

Transfers display progress on stderr, with `--progress=auto|always|never`.
Completion includes stable writes or local sync/publication. Interactive
collisions offer overwrite where supported, rename or cancel; batch commands
refuse collisions. Press Ctrl+C twice consecutively to exit the shell; the
first press cancels the current operation. `reconnect` restores a closed connection.

### Resource discovery

`exports` checks advertised MOUNT exports on NFSv2/v3 and explores the visible
server namespace on NFSv4, without requiring rpcbind or mountd for NFSv4.
It reports paths, discovery source, the current identity, directory listing and
traversal permissions, filesystem boundaries, and per-path failures.

```text
exports
exports --recursive --depth 5 --max-entries 5000 --discovery-timeout 20s
exports --json
exports --path /backup --path /home/team
exports --paths-file paths.txt
```

The default NFSv4 depth is 1; `--recursive` selects 3 unless `--depth` is given.
Repeated `--path` checks known absolute server paths before enumeration, even
when a parent denies listing. Explicit paths are independent of traversal depth
but share the time/entry budget and are limited to 64 components. NFSv2/v3 use
the longest advertised ancestor export or try the supplied path as a MOUNT root;
a hidden mount root cannot be inferred from an arbitrary file path.
`--paths-file` adds paths from a local UTF-8 file,
one absolute server path per line. An initial UTF-8 BOM and CRLF are accepted;
surrounding whitespace, blank lines and full-line `#` comments are ignored.
Relative filenames in the shell use the directory selected by `lcd`. File paths
and repeated `--path` values share `--max-entries`; duplicate lines count too.
Files are limited to 16 MiB, raw lines to less than 64 KiB and paths to 4096 bytes.
Invalid input rejects the whole list before discovery; no partial list is used.
Discovery defaults to 1000 examined entries (files count too) and 10 seconds.
Depth is limited to 64 and the entry budget to 100000. Legacy temporary MOUNT
registrations get up to 2 additional seconds for cleanup. Existing mounts,
UID/GID, security flavor, selected export and working directory are preserved.
Cancellation during an RPC can close that connection; use `reconnect` if needed.

Denied paths, required security changes, referrals, and depth/time/entry limits
produce partial results. Referrals are reported without following another server.
Symlinks are not followed. NFSv2 lacks ACCESS, so permissions remain unknown.
JSON retains `source` and adds merged `sources`, security/referral markers and
advertised SECINFO modes where available; no authentication fallback is attempted.
`listed_entries` and `listing_complete` add actual NFSv4 READDIR evidence:
zero entries means an empty directory only when listing completed. Absent fields
mean no enumeration; a partial zero-entry result does not prove emptiness.
These counts include files, even though discovery primarily presents directories.
Legacy MOUNT/access checks do not enumerate directory contents. Text reports
explain path sources, unknown permissions and reasons for partial traversal.
`fsid` changes identify filesystem boundaries, not necessarily export boundaries.
The NFSv4 result does not merge MOUNT paths or client rules: those may describe a
different namespace. Select NFSv3 separately to inspect its advertised exports.
Even a completed walk cannot enumerate names hidden by the server. A known path
may remain usable when its parent cannot be listed. No UID switching, security
downgrade or write probes are performed by `exports`.

## Identity and connection policy

Use `uid UID [GID [G1,G2]]` to set AUTH_SYS identity and disable automatic
owner selection. `uid-scan PATH [START [END]]` searches for IDs with read access
(default 0..65535, up to 20 matches). `auto-uid on|off` selects observed owner
UID/GID only on NFSv3 AUTH_SYS; `auto-uid-scan on|off` controls scanning after
access denial. Identity changes require no held locks. Kerberos identity stays
fixed for the connection.

For a fixed AUTH_SYS identity use `--uid`, `--gid`, `--groups`,
`--auto-uid=false` and `--auto-escape=false`. NFSv3 automatic owner selection
uses server-observed IDs; it does not override export permissions or root squash.
`root info|verify|reset|discovered|probe` reports bounded namespace observations.
Root probing does not establish the server host's `/`.

`--transport=udp` supports explicit NFSv2/v3. `--udp-size` bounds transfer payloads.
`--reserved-port` binds source ports 900-1023 and can require privileges.
`--nfs-port`, `--mount-port`, `--portmap-port`, `--timeout`, `--dns-server` and
`--dns-tcp` control discovery, deadlines and invocation-scoped DNS.

Require encrypted RPC with `--tls`; set `--tls-ca` and `--tls-server-name` as
needed. Optional `--tls-cert`/`--tls-key` supply a client certificate. Verified
TLS requires exact RPC identity and an accepted RPC/server certificate purpose.
`--tls-insecure` deliberately disables certificate verification. TLS 1.3 and
sunrpc ALPN remain mandatory; no plaintext fallback or UDP/DTLS is provided.

## Network scan

The `scan` subcommand probes one or more hosts for NFS services, lists their exports and
checks for common misconfigurations without requiring an OS-level mount:

```sh
# single host
nfsclient scan 192.168.1.10

# CIDR range under AUTH_SYS UID 0
nfsclient scan 192.168.0.0/24 --uid 0

# Kerberos: one endpoint with an explicit service identity
nfsclient scan nas.example.test --sec krb5p --principal alice@EXAMPLE.TEST --krb5-config krb5.conf --keytab alice.keytab --spn nfs/nas.example.test --no-squash-check --no-escape-check

# targets from file, JSON output
nfsclient scan -f targets.txt --output json

# domain-root discovery
nfsclient scan --dns-domain example.test --dns-server 192.0.2.53 --no-squash-check --no-escape-check

# known paths, including paths below directories that cannot be listed
nfsclient scan 192.168.1.10 --paths-file paths.txt --no-squash-check --no-escape-check
```

Target formats accepted as positional arguments or via `--file`:

| Syntax | Example |
| --- | --- |
| Single IP | `192.168.1.10` |
| CIDR block | `10.0.0.0/24` |
| Explicit range | `10.0.0.1-10.0.0.20` |
| Last-octet shorthand | `10.0.0.1-20` |
| Hostname | `nfs.example.test` |
| File (`-f`) | one target per line; `#` comments ignored |

`--dns-domain` can supply all targets or supplement positional/file targets.
It queries `_nfs-domainroot._tcp.DOMAIN`, as specified by
[RFC 6641](https://www.rfc-editor.org/rfc/rfc6641.html#section-3), preserving each
advertised hostname and port. Auto negotiation for these targets tries NFSv4.2,
4.1 and 4.0 only; explicit NFSv2/v3 is rejected. Each discovered server also gets
an explicit check of `/.domainroot/DOMAIN` within the normal discovery budget.
The scan visits all published endpoints; DNS domain roots are not an inventory
of every NFS server or export in the domain.

A positive `--nfs-port` overrides SRV ports; zero keeps the advertised ports.
Equivalent endpoints are coalesced, while different ports/domain roots remain
distinct. Missing SRV records, a `.` target (service unavailable), or malformed
endpoints stop the invocation before any NFS probes, including when other
targets were supplied. `--timeout` also bounds the SRV lookup. `--dns-server`
is used throughout discovery and subsequent connection name resolution, with
no fallback to system DNS when an explicit server is selected. These options
and `--paths-file` are included in v0.2.0 and later.

For each reachable host the scan reports:

- Discovered NFS version and transport.
- Advertised NFSv2/v3 MOUNT exports and client rules, or discovered NFSv4 paths.
- Current identity, observed access, and partial discovery reasons. Permission
  denied is reported as `denied`; it does not prove an IP restriction.
- **no\_root\_squash** — a temporary file is created as UID 0; if the server reports
  stored UID 0 the flag is active.
- **Root-handle escape** — NFSv2/v3 uses the knfsd v1 handle heuristic.
  Ordinary NFSv4 pseudo-root access is not classified as a vulnerability.

Output is a human-readable table (default) or structured JSON (`--output json`).
Scan supports `--uid`, `--gid`, `--groups`, `--sec`, `--principal`, `--keytab`,
`--ccache`, `--kcm-socket`, `--password`, `--domain` and `--krb5-config`.
Kerberos also requires an explicit service identity. Use `--spn nfs/HOST` for
one distinct endpoint, or repeat `--target-spn HOST[:PORT]=nfs/HOST` for several.
Do not combine these forms. Every target must resolve to one unambiguous service
identity; redundant identical mappings are allowed, while unused mappings are
rejected before target probes. A host-only mapping is accepted only when that
host has one endpoint; multiple ports require port
qualification (IPv6: `[ADDRESS]:PORT`). DNS names compare case-insensitively
without the final dot. DNS resolution never supplies a guessed SPN.
If v2/v3 or `auto` may discover the NFS port through rpcbind, use a host-only
mapping or pin `--nfs-port`; a port-qualified SPN cannot approve an unknown port.
Explicit NFSv4 can use its default port 2049; DNS domain-root targets use their
advertised SRV port (or the explicit `--nfs-port` override).
Choose exactly one credential source: keytab, ccache or password. Scan and
interactive connection share credential validation; scan does not expose all
advanced authentication profiles of the main command.

```sh
nfsclient scan nas.example.test --sec krb5p --principal alice@EXAMPLE.TEST \
  --krb5-config krb5.conf --ccache alice.ccache --spn nfs/nas.example.test \
  --no-squash-check --no-escape-check
```
`--concurrency` (default 20) controls simultaneous connections; `--timeout`
(default 5 s) limits individual connection/probe attempts. `--recursive`,
`--depth`, `--max-entries` and `--discovery-timeout` use the same discovery
semantics as `exports`. RPC work per host has a budget of three times
`--timeout` plus `--discovery-timeout`, with bounded MOUNT cleanup as above.
`--nfs-port` and `--mount-port` together bypass rpcbind for NFSv2/v3.
Use `--no-squash-check --no-escape-check` for read-only discovery. Optional
probes run on advertised exports or observed filesystem boundaries, not every
directory. JSON includes `source`, `identity`, `discovery_complete`,
`discovery_issues`, `can_list` and `can_traverse`; `allowed_clients` is retained
for compatibility and contains only advertised MOUNT rules.
Host results also include `nfs_port` when a port was explicitly selected or
advertised by SRV, and `domain_root` for DNS-discovered targets.
