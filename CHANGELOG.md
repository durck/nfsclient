# Changelog

User-visible changes are grouped by version and type.

## [Unreleased]

### Changed

- Expand the real Windows README demo to cover help, file hints, previews,
  transfers, links, permissions and cleanup, with a slower, compact introduction;
  document direct release downloads.
- Record demos from a neutral local directory, reject private profile details,
  omit absolute local paths, and wait for visible character echoes to prevent
  burst-like command entry. Keep reading pauses below two seconds.

### Fixed

- Preserve current `nfsclient` binaries during local artifact archival; exclude
  local builds, verification output and environment files from Docker contexts.

## [0.2.0] - 2026-10-08

### Changed

- Shorten owner/group names ending in `@localhost` or `@localdomain` in file
  listings; preserve other domains and the exact identities in `stat` JSON.
- Unified terminal colors across listings, prompts, transfers and session status.
  Familiar system files/directories use pale gray exact-name hints; configuration
  and credential hints have separate colors. Current-year modification dates
  remain orange for every entry, including unavailable links. Link status labels
  are colored independently; metadata remains readable and color-free output
  retains the same layout and status text.

### Added

- Corporate and cloud file hints using known listing paths, including AD/Samba,
  GPP, database/service profiles, Jenkins, mail/backups, cloud credentials and
  Terraform state. `legend PATH` explains the matched rule with remote completion.
  Stacked backup/archive suffixes retain hints; example/template names are toned down.
- Shell `ln`, `ln -s`, `readlink`, `chown` and `chgrp`, with pinned identities,
  explicit symlink rules, ownership readback and matching help/completion.
- Bounded `mounts` diagnostics and opaque `handle` hex/JSON inspection;
  connection reports include requested host, connected peers and identity.
- Discovery reports distinguish completed empty listings from unenumerated or
  partial paths, with additive `listed_entries`/`listing_complete` JSON evidence.
- Explicit single-target and per-target Kerberos SPNs in `scan`, plus ccache
  selection, shared credential validation and early mapping checks.
- `scan --dns-domain` discovers RFC 6641 NFSv4 domain roots, including their
  advertised ports and namespace paths. Invocation-scoped DNS also covers
  connection probes and NFS connections; domain-only invocation is supported.
- `--paths-file` in `scan` and shell `exports`, with bounded, validated UTF-8
  path lists, shell-local path resolution, help and filename completion.
- NFSv4 `chmod` warns that changing mode bits can change existing ACL entries.

### Fixed

- Recognize an expected broken pipe in opt-in iSCSI fault-injection fixtures,
  avoiding intermittent CI failures when clients reject corrupted digests.
  Unexpected disconnects, timeouts and protocol errors still fail the tests.
- Protected scans now receive the required service principal. Password-only
  authentication passes shared validation; conflicting credentials and ignored
  passwords under AUTH_SYS/SSPI are rejected.
- Port-qualified scan SPNs cannot approve an unknown rpcbind-discovered port;
  use host-only mappings or an explicit NFS port for legacy negotiation.
- Preserve SRV ports and reject unavailable/invalid endpoints; restrict domain
  roots to NFSv4, respect DNS deadlines and expose endpoints in scan reports.
- Make the lease-renewal crash test use an observable recoverable RPC boundary,
  with a separate interrupted-renewal case verifying recovery quarantine.

## [0.1.0] - 2026-10-07

Initial public release for Windows x64 and Linux x64.

### Added

- Concise startup and shell help, complete topic/command references and
  context-aware Tab completion for options, values and quoted paths. Startup
  shell-completion scripts include enum and file/directory flag suggestions.
- RFC-informed inspection: shared ACCESS evidence and `access`, explicit known
  paths/provenance in `exports` and `scan`, connection `info`, per-path
  `capabilities`, opt-in offline metadata, NFSv4 `locktest`, and bounded read-only
  named-attribute listing/export. Inspection preserves the current identity.
- Bounded NFSv4 namespace discovery in `exports` and `scan`, with current-identity
  access checks, filesystem boundaries, partial results, JSON output and traversal
  limits. NFSv2/v3 discovery checks advertised MOUNT exports; scan accepts explicit
  MOUNT ports.
- Current server hostname and connected IP in the interactive prompt, with
  bounded reverse DNS lookup for IP targets and refresh after reconnect.
- Typographic nfsclient banner for the GitHub README.
- Interactive Windows/Linux NFS client with direct RPC, NFSv2/v3/v4 profiles,
  safe file transfers, previews, completion and optional command history.
- Explicit Kerberos authentication, integrity and privacy, protected automatic
  version selection, bounded credential profiles, pure-Go FAST/PKINIT and an
  opt-in Windows SSPI provider.
- RPC-over-TLS with verified peer identities and no plaintext fallback.
- NFSv2/v3 ACL export/import and ordered NFSv4 ACL management, bounded metadata
  operations, advisory locks and range transfers.
- Explicit transfer resume, durable lock recovery, approved migration/referrals
  and receipt-verified NFSv4.2 offload recovery.
- Bounded pNFS FILE/Flex, block and OSD profiles, authenticated iSCSI with CHAP
  and CRC32C policies, 4 KiB logical sectors and guarded read recovery.
- Streaming block-write recovery across process crashes, authenticated OSD-1
  capabilities and secured finite writes to existing dense RAID0 objects.
- Protected callback-context renewal and immutable Kerberos configuration
  snapshots with bounded include resolution.
- Windows/Linux CI, standalone binary artifacts with checksums and dependency
  notices, contributor guidance and private vulnerability-reporting guidance.
- MIT license for project code and a recorded local NFSv4.1 transfer demo.
- Multi-host NFS scan subcommand (`nfsclient scan`) with CIDR/range/file target
  parsing, concurrent probing (configurable `--concurrency`), advertised MOUNT client
  rules and observed access results, root-squash checks, and
  root-handle escape checks for NFSv2/v3 (knfsd handle heuristic) and NFSv4 (PUTROOTFH
  pseudo-root probe).  Output in human-readable table or JSON.
- PKCS12/PFX certificate format for PKINIT: `--pkinit-pfx` and `--pkinit-pfx-password`
  extract the leaf certificate and private key into session-scoped temporary PEM files.
- Password-based Kerberos initial authentication via `--password`; `--domain` qualifies
  a bare `--principal` with an explicit realm, matching Windows domain conventions.
  Both flags are available on the main command and on `scan`.

### Fixed

- Installation instructions link to versioned release archives, checksums,
  development CI artifacts and source builds.
- `ls` and `stat` correctly treat option-looking literal paths after `--`.
- Preserve NFSv4 SETATTR error payloads/status during chmod, reject incomplete
  success acknowledgements, and explain possible partial metadata changes.
- Retain ACCESS supported masks and NFSv4 execute-authorized read semantics in
  inspection instead of treating unsupported checks as permission denials.
- Reject malformed protocol envelopes and keytab inputs without exposing key data.
- Preserve uncertain lock/offload state and require confirmed cleanup before
  reporting recovery completion; quarantine NLM state after crash notification.
- Enforce selected authentication algorithms, exact TLS identities, device
  identities and transfer geometry throughout renewal and recovery.
- Correct XFS root-candidate identifiers, Windows reserved-port collision
  handling and bidirectional iSCSI sequencing.

### Changed

- Tree-transfer flags accept either side of positional paths; `--` ends option
  parsing before literal filenames.
- Report permission denial without inferring an IP restriction, and stop treating
  ordinary NFSv4 pseudo-root navigation as a root-escape vulnerability.
- Replace the captioned batch demo with a native Windows interactive terminal
  recording, including real prompts, colors, navigation and Tab completion.
- Consolidate public documentation by operation and state native interoperability
  limits explicitly in the compatibility guide.
- Remove unused internal helpers and standardize error messages; retain local
  test artifacts outside the published source tree.

See [compatibility](docs/COMPATIBILITY.md) for the supported bounds of each profile.
