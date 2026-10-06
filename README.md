# nfs-viewer

An interactive NFS client for Windows and Linux. It connects directly through
RPC without an OS NFS client or mount. Ordinary operations support NFSv3 and
NFSv4.0/4.1/4.2 over TCP, plus bounded NFSv2 and v2/v3 UDP profiles.

The Go executable is CGO-free, including the opt-in FAST and PKINIT profiles
on Windows and Linux. See [authentication](docs/AUTHENTICATION.md) for their
explicit credential and server requirements.

See [documentation](docs/INDEX.md), [current compatibility](docs/COMPATIBILITY.md)
and the [client implementation plan](docs/PLAN.md). Detailed operation contracts are organized
by topic. See [contributing](CONTRIBUTING.md) and the [security policy](SECURITY.md).

Licensed under [MIT](LICENSE). Adapted GSS/Kerberos components retain their
original notices; binary distributions also include third-party licenses.

[Watch the terminal demo](docs/assets/demo.cast) with
`asciinema play docs/assets/demo.cast`: a real local NFSv4.1 upload, listing,
preview and download. Command captions and pauses were added for readability;
output comes from the disposable Ganesha fixture. Downloaded bytes were verified.

## Install from a release

No tagged release is declared by this source snapshot. Until the first release,
build from source below or download a successful GitHub Actions build from the
repository's **Actions → CI → Artifacts** page. CI artifacts are development
builds identified by their workflow commit.

When a tagged release is available, use its **Releases → Assets** downloads.
Select `nfs-viewer-windows-amd64.exe` for Windows x64 or
`nfs-viewer-linux-amd64` for Linux x64, and retain the accompanying `LICENSE`
and `THIRD-PARTY-LICENSES.txt`. Extract the artifact and compare the binary's
SHA-256 digest with its `SHA256SUMS` entry:

```powershell
Get-FileHash .\nfs-viewer-windows-amd64.exe -Algorithm SHA256
.\nfs-viewer-windows-amd64.exe --help
```

```sh
sha256sum -c SHA256SUMS
chmod +x nfs-viewer-linux-amd64
./nfs-viewer-linux-amd64 --help
```

A checksum detects corrupted downloads; it is not a publisher signature.

## Build and start

Go 1.26 is required; `go.mod` selects patched Go 1.26.8 automatically.

```powershell
$previousCGOEnabled = $env:CGO_ENABLED
try {
  $env:CGO_ENABLED = "0"
  go build -trimpath -o bin/nfs-viewer-windows-amd64.exe .
} finally {
  $env:CGO_ENABLED = $previousCGOEnabled
}
.\bin\nfs-viewer-windows-amd64.exe nfs.example.test --export /data
```

```sh
CGO_ENABLED=0 go build -trimpath -o bin/nfs-viewer-linux-amd64 .
./bin/nfs-viewer-linux-amd64 nfs.example.test --export /data
```

Launching without arguments displays help. By default, AUTH_SYS/TCP probes
4.2, 4.1, 4.0, 3 and 2. Select `--nfs-version` explicitly to require a version.
NFSv4 uses the server's pseudo-root; v2/v3 use export discovery/MOUNT.

Before redistributing binaries, run `python -B tests/package_licenses.py` and
include the root `LICENSE` and generated `bin/THIRD-PARTY-LICENSES.txt`. It includes all modules
linked into either platform, the Go runtime and local GSS/Kerberos adaptations.
The self-check generates this file automatically.

## Everyday use

```text
exports
use /data
ls
cd documents
stat notes.txt
cat notes.txt
get notes.txt local-notes.txt
put "local report.txt" "new report.txt"
chmod 640 "new report.txt"
id
exit
```

Remote paths use `/`; relative paths and symlinks are interpreted within the
selected root. Commands do not invoke a local shell or expand wildcards and
environment variables. Quote names containing spaces. Tab completes commands
and paths; optional `--history FILE` persists history, otherwise it stays in memory.

Listings escape control characters and show link targets. `cat` validates a
bounded UTF-8 preview before printing to a terminal; redirected output retains
raw bytes. `hex` provides a bounded binary preview. `lls`, `lpwd` and `lcd` operate
on local files. `legend` explains colors; `--color=never` or `NO_COLOR` disables them.

Transfers display progress on stderr, with `--progress=auto|always|never`.
Completion includes stable writes or local sync/publication. Interactive
collisions offer overwrite where supported, rename or cancel; batch commands
refuse collisions. Press Ctrl+C twice consecutively to exit the shell; the
first press cancels the current operation. `reconnect` restores a closed connection.

## Identity and connection policy

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

## Kerberos

```sh
# keytab
./bin/nfs-viewer-linux-amd64 nfs.example.test --export /data \
  --nfs-version 4.1 --sec krb5p --principal alice@EXAMPLE.TEST \
  --spn nfs/nfs.example.test --krb5-config /absolute/krb5.conf \
  --keytab /absolute/alice.keytab --auto-escape=false

# password / Windows domain
./bin/nfs-viewer-linux-amd64 nfs.example.test --export /data \
  --nfs-version 4.1 --sec krb5 --principal alice --domain CORP.LOCAL \
  --password "s3cr3t"

# PKCS12/PFX certificate
./bin/nfs-viewer-linux-amd64 nfs.example.test --export /data \
  --nfs-version 4.1 --sec krb5p --principal alice@EXAMPLE.TEST \
  --pkinit-pfx alice.pfx --pkinit-pfx-password "pfxpassword"
```

`krb5`, `krb5i` and `krb5p` select authentication, integrity and privacy.
The principal selects identity; numeric UID/GID options cannot select a Kerberos
user. Explicit `--ccache FILE:/absolute/cache` is an alternative to a keytab.
Authentication denial does not fall back to AUTH_SYS or weaker protection.
For explicit foreign-realm allowlisting and ordered routes, see the
[bounded client capaths policy](docs/AUTHENTICATION.md#client-trust-paths).

| Credential/policy extension | Contract |
| --- | --- |
| Linux explicit KCM | [KCM cache profile](docs/AUTHENTICATION.md#linux-kcm) |
| Linux explicit session/process/user KEYRING | [KEYRING profile](docs/AUTHENTICATION.md#linux-keyring) |
| Windows current-logon exportable home TGT | [LSA profile](docs/AUTHENTICATION.md#windows-lsa) |
| Pinned same-realm canonical AS alias | [AS canonicalization](docs/AUTHENTICATION.md#pinned-as-aliases) |
| Explicit approved enterprise-UPN realm routing | [Enterprise UPN](docs/AUTHENTICATION.md#enterprise-upn-routing) |
| Windows/Linux required FAST with keytab and FILE armor | [FAST profile](docs/AUTHENTICATION.md#linux-required-fast) |
| Windows/Linux PKINIT with file certificate/key (PEM) or PKCS12/PFX (`--pkinit-pfx`) | [PKINIT profile](docs/AUTHENTICATION.md#linux-pkinit) |
| Kerberos password authentication via `--password`; `--domain` qualifies a bare principal | n/a — AS-REQ password sent to KDC directly |

These profiles have explicit bounds; they do not promise universal SSPI,
directory/forest, smart-card or NAS interoperability.

## Network scan

The `scan` subcommand probes one or more hosts for NFS services, lists their exports and
checks for common misconfigurations without requiring an OS-level mount:

```sh
# single host
nfs-viewer scan 192.168.1.10

# CIDR range under AUTH_SYS UID 0
nfs-viewer scan 192.168.0.0/24 --uid 0

# Kerberos password auth
nfs-viewer scan 10.0.0.0/24 --sec krb5 --principal user --domain CORP.LOCAL --password Secret

# targets from file, JSON output
nfs-viewer scan -f targets.txt --output json
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

For each reachable host the scan reports:

- Discovered NFS version and transport.
- All advertised exports with the client-allow list from `showmount`.
- **IP restriction** — NFS status 13 returned by `MOUNT` is detected automatically
  and the export is marked `IP_RESTRICTED`.
- **no\_root\_squash** — a temporary file is created as UID 0; if the server reports
  stored UID 0 the flag is active.
- **Root-handle escape** — NFSv2/v3 uses the knfsd v1 handle heuristic;
  NFSv4 probes the pseudo-root via `PUTROOTFH`.

Output is a human-readable table (default) or structured JSON (`--output json`).
Scan supports the same auth flags as the main command: `--uid`, `--gid`, `--groups`,
`--sec`, `--principal`, `--keytab`, `--password`, `--domain` and `--krb5-config`.
`--concurrency` (default 20) controls simultaneous connections; `--timeout`
(default 5 s) limits per-host attempts.  `--no-squash-check` and `--no-escape-check`
skip the respective probes when speed is more important than coverage.

## Advanced commands

Use shell `help` for exact syntax. These operations require explicit approvals,
protocol versions, credentials and often confirmed locks.

| Commands | Contract and purpose |
| --- | --- |
| `getplus`, `seek`, `allocate`, `deallocate`, `advise` | [NFSv4.2 operations](docs/OFFLOAD.md#nfsv42-operations) |
| `lock`, `locks`, `unlock`, `getrange`, `putrange` | [Advisory locks and ranges](docs/LOCKS.md#locks-ranges-and-ownership) |
| `locktest`, `nlmrecover` | [Legacy NLM](docs/LOCKS.md#locks-ranges-and-ownership) and [crash notification](docs/LOCKS.md#client-crash-notification) |
| `reget`, `reput`, `reconnect` | [Transfer recovery](docs/TRANSFERS.md#reconnect-and-transfer-recovery) and [explicit reclaim](docs/STATE_RECOVERY.md#server-restart-reclaim) |
| `migrate` | [Protected OPEN/LOCK session migration](docs/STATE_RECOVERY.md#open-and-lock-migration) |
| `lock-save`, startup `--recover-locks` | [Durable lock lifecycle and process recovery](docs/STATE_RECOVERY.md#retained-lock-process-recovery) |
| `reget --referral` | [Approved namespace referrals](docs/STATE_RECOVERY.md#approved-namespace-referrals) |
| `getpnfs`, `putrangepnfs`, `putpnfs` | [pNFS](docs/PNFS_FILES.md#file-downloads), [block writes](docs/PNFS_BLOCK.md#range-writes-and-cow), [block uploads/growth](docs/PNFS_BLOCK.md#new-files-and-growth) |
| `getpnfs --layout object`, `putrangepnfs --layout object --object-write` | [OSD reads and secured range writes](docs/PNFS_OBJECT.md), [iSCSI backend](docs/PNFS_BLOCK.md#iscsi-storage) |
| `copyrange`, `clonerange`, `copyasync`, `copyfrom`, `writesame`, `writeadb` | [Offload operations](docs/OFFLOAD.md#nfsv42-operations); [receipt reconciliation](docs/OFFLOAD.md#receipt-confirmed-reconciliation) |
| `--recover-offload`, `offload-reconcile` | Recover an original saved offload session or verify eligible completion receipts |
| `gettree`, `puttree` | Explicit bounded tree merge, links, hardlinks, mode and mtime; no whole-tree atomicity |
| `replace` | [NFSv2 ACL replacement](docs/REPLACEMENT.md#explicit-nfsv2-replacement), [NFSv3 ACL replacement](docs/REPLACEMENT.md#explicit-nfsv3-replacement) or [NFSv4 replacement attributes](docs/REPLACEMENT.md#extended-and-named-attributes) |
| `acl`, `getacl`, `setacl` | [NFSv4 ordered ACL management](docs/REPLACEMENT.md#native-nfsv4-acl-management), [NFSv2/v3 ACL inspection/export/import](docs/REPLACEMENT.md#nfsv3-acl-inspection) |
| `label`, `setlabel`, `xattrs`, `getxattr`, `setxattr`, `removexattr` | Bounded metadata operations; authorization remains server policy |
| `rm`, `rmdir`, `mv`, `mkdir`, `chmod` | Explicit namespace/metadata mutations; no recursive deletion or automatic mutation replay |

## Self-check and project artifacts

```powershell
go mod download
python tests/selfcheck.py
python tests/selfcheck.py --linux-container
```

`tests/selfcheck.py` runs native Go vet/race, Python evidence-decoder regressions,
a CGO-free build and local release-process scenarios. Adding `--linux-container` runs Linux Go
checks/build/release scenarios in temporary Docker containers. Neither enables
opt-in external service fixtures. Results are under `bin/verification/`.

See [verification](docs/DEVELOPMENT.md#local-self-check) for check scope and
[artifact cleanup](docs/DEVELOPMENT.md#historical-evidence) for retained evidence and runtime directories.
The race checks require CGO enabled and a supported C compiler on the test host;
the distributed client itself remains CGO-free. Keep build-only environment
overrides scoped to the build, as in the recipes above.
Hardware RDMA and a new external stand are outside the completion scope.
