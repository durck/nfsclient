# Client functionality implementation plan

Rebuilt 2026-10-05 from the current client source. This replaces the historical
completion ledger. It contains **13 client tasks**, ordered in four stages.
**13 accepted, 0 open in the original plan.** The separate RFC-informed iteration
below tracks the newly approved scope. Acceptance records below refer to the current implementation;
completed behavior is described in the linked operation guides.

The first four tasks extend incomplete existing workflows. The remaining nine
add specific missing capabilities to existing subsystems; they are new, bounded
scope in this plan, not claims that all were promised or broken previously.
Each task identifies the current restriction, the implementation and observable
completion criteria. Missing native-server evidence is not a development task.
Current support remains defined by [compatibility](COMPATIBILITY.md).

## Stage 1: Finish existing user workflows

### F01 — Kerberos-aware automatic NFS version selection

- [x] **Implemented.** Explicit Kerberos `auto`
  negotiates TCP 4.2/4.1/4.0/3/2 or UDP 3/2 using non-mutating version probes.
  The omitted API version retains its v3 default; successful selection is pinned.
- Implement explicit `auto` negotiation across 4.2/4.1/4.0/3/2 for TCP and 3/2
  for UDP, preserving the chosen principal, SPN, security and TLS policy.
  Keep advanced pNFS/offload explicit-version requirements.
- Done when a v4-only protected server connects with `auto`, version mismatch
  permits the next candidate, and credential/trust/authorization failures stop
  negotiation. Failed probes release their state; no NFS mutation is replayed.

### F02 — Complete legacy ACL commands

- [x] **Implemented.** Versioned v2/v3 CLI ACL
  export/import uses an explicit in-place editing API with exact readback.
  The staging-only replacement API retains its original ownership contract.
- Add version-aware ACL export/import for v2/v3, reusing existing wire code.
  Define an explicit in-place editing contract before exposing SETACL on an
  existing target; keep the current staging API contract until then.
- Done when file access ACLs and directory default ACLs round-trip through the
  CLI, explicit empty defaults clear policy, and exact readback verifies the
  selected target/identity. Symlink, ownership, malformed policy and unsupported
  extension cases refuse; a lost SETACL reply reports an uncertain change and
  does not retry or claim rollback. Recursive ACL cloning stays excluded.

### F03 — Streaming block recovery beyond 16 MiB

- [x] **Implemented.** Private source spooling,
  streaming verification and fixed-size v2 checkpoints remove the 16 MiB gate.
  Windows/Linux packaged CLI recovery passed two process crashes on a transfer
  above 20 MiB; cancellation, changed-source/device and unrelated-byte checks pass.
- Replace whole-input buffering and whole-file size gating with bounded chunk
  verification and durable range progress. Version the journal and preserve
  the existing source, volume, layout, lock and uncertain-write checks.
- Done when a large destination accepts a small recoverable patch, a transfer
  larger than 16 MiB resumes after multiple process crashes with bounded memory,
  and changed source/volume/layout evidence refuses without modifying unrelated
  bytes. Old journals remain readable or receive a precise migration refusal.

## Stage 2: Complete credential and session integration

### F04 — Renew protected callback sessions

- [x] **Implemented.** Protected callbacks rotate
  contexts through BACKCHANNEL_CTL on the existing session, retaining bounded
  authenticated old-context windows. Active callbacks and cancellation pass;
  uncertain or durably pinned requests refuse without replay.
- Add a controlled renewal lifecycle for pNFS/offload callbacks: stop new work,
  drain tracked requests, rotate/rebind where supported, and retain validated
  callback sequencing and identity. Establish a replacement session only at a
  proven safe boundary; do not silently transfer outstanding state.
- Done when new protected work can continue after renewal without a manual CLI
  reconnect, with coverage for active callbacks, cancellation and context
  exhaustion. Pending unknown mutations and state the server cannot preserve
  still refuse. This does not implement missing server callback support.

### F05 — Windows SSPI credential mechanism

- [x] **Implemented.** Explicit Windows SSPI uses
  current-logon Kerberos handles for ordinary RPCSEC_GSS without exporting keys.
  Native-call, provider/RPC and refusal tests pass; the opt-in real-domain
  positive RPC test remains unexecuted without a domain ticket/server.
- Add an explicitly selected SSPI provider using the current logon session,
  with context establishment and RPCSEC_GSS signing/sealing through OS handles.
  Integrate provider selection, lifetime and cleanup into the existing client.
- Done when the selected Windows identity performs ordinary NFS RPCs without
  exporting its key, with krb5/i/p integrity, replay and expiration checks.
  TLS channel binding and callback support must be implemented or explicitly
  rejected before network mutation; never silently fall back to LSA/keytab.
  Linux must retain its existing providers and reject SSPI selection clearly.

### F06 — Explicit persistent Linux KEYRING caches

- [x] **Implemented.** Explicit
  `KEYRING:persistent:UID:CACHE` reads the current UID's named persistent cache.
  Windows/Linux tests cover snapshot refusals and encrypted authentication/refresh;
  these tests do not claim native persistent-kernel interoperability.
- Add explicit persistent-cache selection for the current UID, retaining
  bounded snapshots, ownership validation and principal continuity.
- Done when a named persistent cache can authenticate and refresh, while a
  foreign UID, changed membership/principal, expired TGT or absent cache refuses.
  Ambient/default selection and cross-user cache discovery are not required.

### F07 — File-based Kerberos configuration includes

- [x] **Implemented.** A bounded file loader
  resolves includes into one pinned configuration/trust-path snapshot and
  refuses changed dependencies during renewal, reconnect and recovery.
- Introduce one bounded configuration loader shared by authentication and
  trust-path validation, with deterministic include ordering, cycle detection
  and a stable snapshot used throughout authentication and renewal.
- Done when a split configuration behaves like its flattened equivalent;
  conflicts, unreadable inputs, cycles, size/depth excess and changed policy
  fail explicitly. Dynamic executable `module` loading remains excluded.

### F08 — Combined required FAST and certificate PKINIT

- [x] **Implemented.** Both certificate AS rounds
  run inside mandatory FAST with authenticated freshness and reply verification.
  Native MIT KDC exchanges and public Initiator GSS integrity/privacy pass on
  Windows/Linux, including negative controls; no helper or method fallback.
- Add an explicit certificate-authentication profile inside mandatory FAST,
  reusing the pure-Go implementations and the selected armor/trust policy.
- Done when the combined exchange succeeds on Windows/Linux and rejects missing
  armor, invalid certificate/trust/freshness and unarmored replies without a
  method downgrade. Existing standalone FAST and PKINIT remain functional.

## Stage 3: Complete the bounded iSCSI storage client

### F09 — iSCSI authentication and negotiated digests

- [x] **Implemented.** Explicit per-target CHAP,
  mutual CHAP and CRC32C policies cover block/object transport. Independent
  peers verify authenticated I/O, strict negotiation, numerical/hex grammar,
  reflection/downgrade refusal and corrupted-PDU connection termination.
- Add explicit CHAP, mutual CHAP and CRC32C header/data digest policy, including
  bounded multi-step login and secret handling outside URLs/logs/journals.
- Done when authenticated reads/writes work, wrong or reflected credentials
  fail before SCSI writes, and corrupt headers/data terminate the connection.
  Required authentication/digests cannot downgrade. CHAP is authentication;
  CRC32C is error detection. Neither provides encryption or substitutes for
  cryptographic transport protection.

### F10 — Native 4 KiB logical sectors

- [x] **Implemented.** iSCSI discovers 512/4096-byte
  logical sectors and carries geometry through bounded I/O, pNFS write alignment
  and recovery fingerprints. Changed NAA/sector size refuses across fresh client
  incarnations; the unchanged-device positive control succeeds.
- Carry the discovered logical-sector size through capacity, SCSI commands,
  pNFS block alignment, buffering and recovery evidence; support 512 and 4096.
- Done when 512-byte and 4Kn targets transfer exact data, capacity arithmetic
  rejects overflow, and incompatible layout/sector alignment fails before a
  write. Recovery rejects a changed sector size or device identity.

### F11 — Approved iSCSI read reconnection and alternate portals

- [x] **Implemented.** Explicit read recovery uses
  bounded fresh sessions on the original or approved alternate portals, rechecking
  security, NAA/geometry, signatures and layout/lease state. Windows/Linux wire
  and packaged CLI tests pass; writable/uncertain operations never receive replay.
- Add explicit alternate portal mappings and bounded fresh-session recovery
  for reads, with target/LUN/device identity and layout/lease revalidation.
  Restart failed SCSI reads only while their enclosing consistency checks hold.
- Done when a lost read transport resumes through an approved equivalent portal;
  wrong device, changed geometry, expired lease and unapproved redirects refuse.
  Unknown writes stay quarantined. Full task reinstatement, general multipath
  scheduling and blind write replay are not part of this task.

## Stage 4: Complete the selected pNFS object profile

### F12 — Secured OSD capabilities

- [x] **Implemented.** OSD-1 ALLDATA capabilities
  use authenticated slot-zero discovery, scoped finite-lived keys, protected
  commands/data/replies and immutable device security selection. Independent
  peers and protected NFS/API/CLI checks cover refusal and publication boundaries.
- Add a specified OSD-1 authenticated-capability profile end to end: layout
  decoding, capability/key lifetime, authorized command construction and reply
  validation. Keep credentials confined to operation memory.
- Done when an independently implemented peer accepts correctly authorized
  operations and rejects altered, expired, wrong-object or insufficient-rights
  capabilities. Selecting secured mode must never fall back to NOSEC.
  OSD-2 and parity/group/mirror layouts remain outside this bounded profile.

### F13 — OSD writes for existing objects

- [x] **Implemented.** Explicit finite object writes
  require a whole-file lock and secured complete dense RAID0 grants. Every
  confirmed prefix completes WRITE, FLUSH and MDS LAYOUTCOMMIT; failure tests
  verify quarantine, no replay and preserved unrelated bytes.
- After F12, implement finite range writes to existing files with approved,
  complete dense RAID0 OSD-1 component layouts. Include write authorization,
  layout/lock lifetime, component bounds, data durability and MDS completion.
- Done when aligned and stripe-crossing ranges publish exact bytes; short/error
  replies, recalls, expired capabilities and lost completion cannot report full
  success. Confirmed progress survives the supported failure boundaries;
  uncertain writes are never blindly repeated. Creation, growth, parity and
  mirrored object writes are separate future scope, not implied by this item.

## Execution and completion rules

Implement F01-F03 first, then F04-F08, F09-F11 and F12-F13. Independent items may
be developed in parallel; F13 depends on F12, and shared credential/storage
changes must be integrated before their dependants are accepted.

For each task: reproduce the existing limitation, implement the specified user
flow, verify success and meaningful refusal/failure paths, update the owning
guide and compatibility row, then mark the checkbox complete. A named restriction
or guard removed without a working replacement does not complete a task.

Use deterministic protocol/process peers and existing local software fixtures;
no hardware or new external stand is required. Native interoperability evidence
is recorded separately and honestly. At integrated checkpoints run the
[Windows/Linux self-checks](DEVELOPMENT.md#local-self-check), including packaged
CLI scenarios affected by the change. Tests are acceptance conditions within
feature tasks, not a separate endless validation backlog. 

This finite plan is complete when all 13 client tasks meet their stated criteria.
It does not promise every option in every NFS, Kerberos, iSCSI or OSD standard.
Adding an unrelated protocol profile requires a visible scope change rather than
silently extending the completion target.

## Outside the client development backlog

- Native-only evidence gaps: terminal applications, Windows LSA/FAT/exFAT,
  AD forests/PAC, occupied reserved ports, and server-specific optional NFS
  operations. Current limitations remain in the relevant operation guides and
  [compatibility](COMPATIBILITY.md); they do not count as missing client code.
- Server implementation work: Ganesha's missing protected callback support,
  server-side COPY/WRITE_SAME/ADB/READ_PLUS/advice/label support, and NSM cleanup
  completion signals. An unavailable server feature is not fixed by removing
  the client's refusal.
- Unrecoverable evidence: no guaranteed unknown-write replay after loss of the
  required session/journal, reconstruction of missing child credentials, or safe
  post-SM_NOTIFY lock reacquisition based only on an empty acknowledgement.
- Explicit exclusions: hardware RDMA, a new external stand, and recursive source
  owner/ACL cloning. Existing bounded software iWARP remains supported.
- Unselected expansion: full OSD layout families, smart-card/PKCS11 integration,
  all encryption types, automatic domain discovery, iSCSI TLS/general task
  reinstatement, and new transport families. These are not automatically defects
  in the selected client profiles and are not hidden completion conditions.

Verification scope is documented in [development](DEVELOPMENT.md).

## RFC-informed inspection iteration (2026-10-07)

The completed F01-F13 scope remains unchanged. The user approved the following
bounded additions after reviewing primary NFS RFCs. Hardware and a new external
stand remain excluded; WebNFS and new pNFS extensions are deferred. DNS domain-root
discovery was subsequently implemented and is documented in README.

Design decision: share typed access/capability observations in `internal/nfs`,
resolve paths with pinned identities in `internal/session`, and present commands
in `internal/cli`. Keeping independent wire checks in each command was rejected:
it already produced different interpretations of the ACCESS supported mask.
No persistent capability cache or generic plugin framework is introduced.
Advertised support, client implementation, protocol eligibility and observed
authorization remain distinct; diagnostic commands do not test mutations.

- [x] R01: Preserve ACCESS requested/supported/allowed masks; expose `access`;
  unsupported checks must not become permission denials. Pin inspection identity.
- [x] R02: Check explicit `exports --path` paths independently of READDIR depth;
  merge provenance and expose security/referral/partial boundaries without fallback.
- [x] R03: Expose `info` and per-path `capabilities`; optional operations without
  affirmative evidence remain unknown. Do not infer AD mapping from owner strings.
- [x] R04: Add explicit `ls --offline` and `stat --offline` metadata inspection;
  missing support remains unknown and inspection never opens file contents.
  `gettree --skip-offline` lists known offline skips before opening content;
  unknown status retains normal download behavior.
- [x] R05: Extend `locktest` with NFSv4 LOCKT and expose bounded named-attribute
  listing/export; no remote attribute creation or lock acquisition during inspection.
- [x] R06: Verify lost-reply/GSS/partial-operation behavior, fix confirmed defects,
  complete independent review and integrated Windows/Linux checks.

Completion requires observable success and refusal tests for each item, topical
documentation updates and the integrated checks from DEVELOPMENT.md. Optional
server features are tested with protocol peers; this does not claim native NAS
interoperability for the new extensions.

All six items are accepted. Independent review findings were corrected, including
unsupported ACCESS handling, execute-authorized read observations, unavailable
root handles, stale discovery hints and SETATTR error payloads. Windows/Linux
self-checks (vet, race, builds and packaged release scenarios), focused final
regressions and staticcheck v0.7.0 passed. New optional extensions retain the
software-peer evidence limitation described above.

## Everyday client improvements (2026-10-07)

Approved after comparing nfsshell with the existing client. This iteration
finishes everyday workflows rather than adding another protocol family.

- [x] U01: Repair protected scan with explicit single-endpoint/per-target SPNs,
  shared credential validation and cache/password selection. Reject ambiguous,
  conflicting, missing and unused mappings before NFS probes; never infer SPNs.
- [x] U02: Expose `ln`, `ln -s` and `readlink` using existing protocol operations.
  Exact destinations, no replacement, pinned identities and explicit symlink
  semantics; report uncertain mutations without blind replay.
- [x] U03: Add `chown` / `chgrp`, numeric v2/v3 and string v4 ownership, exact
  same-handle readback, refusal/partial-change/lost-reply handling.
- [x] U04: Explain discovery provenance, permission uncertainty and traversal
  limits. Add backward-compatible READDIR count/completion evidence so unknown
  or partial contents cannot be mistaken for a confirmed empty directory.
- [x] U05: Add bounded historical MOUNT records, opaque handle hex/JSON diagnostic
  export and requested/observed connection context. Preserve existing separation
  of server advertisements, client support and access observations.
- [x] U06: Integrate command help and context-sensitive completion, update the
  existing user guides, and independently cross-review all implementation areas.

Windows/Linux self-checks passed: vet, race, CGO-free builds and packaged CLI
scenarios; Windows Python checks also passed. Staticcheck and reachable-code
vulnerability checks passed. A disposable MIT KDC/Ganesha verified 24 protected
scan successes (v3/v4.0/v4.1/v4.2, keytab/cache/password, both SPN forms) and wrong
SPN/password refusal. The Windows binary completed link/ownership workflows
against Ganesha on v3/v4.1. Wire peers cover malformed replies and uncertain
mutations; native NAS/hardware claims remain limited by COMPATIBILITY.md.

`mknod` and arbitrary filehandle import remain explicitly deferred. Diagnostic
handle output is not a recovery or import format. No new external stand is needed.
