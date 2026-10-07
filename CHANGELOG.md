# Changelog

User-visible changes are grouped by type. No version or release date is assigned
until a tagged release is published.

## [Unreleased]

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
  parsing, concurrent probing (configurable `--concurrency`), automatic IP-restriction
  detection (NFS status 13 on MOUNT), no_root_squash detection via UID 0 spoofing, and
  root-handle escape checks for NFSv2/v3 (knfsd handle heuristic) and NFSv4 (PUTROOTFH
  pseudo-root probe).  Output in human-readable table or JSON.
- PKCS12/PFX certificate format for PKINIT: `--pkinit-pfx` and `--pkinit-pfx-password`
  extract the leaf certificate and private key into session-scoped temporary PEM files.
- Password-based Kerberos initial authentication via `--password`; `--domain` qualifies
  a bare `--principal` with an explicit realm, matching Windows domain conventions.
  Both flags are available on the main command and on `scan`.

### Fixed

- Installation instructions point to available CI artifacts and source builds
  instead of describing downloads from unpublished releases.
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
