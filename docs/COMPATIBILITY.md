# Current protocol and filesystem compatibility

This table describes implemented profiles, not universal server certification.
Windows and Linux are equal targets for the Go core. Ordinary operation needs
one CGO-free executable, including optional FAST/PKINIT. An explicitly selected
native MIT helper remains a Linux compatibility option. Hardware RDMA and an external stand are
excluded from completion scope.

[Development](DEVELOPMENT.md#local-self-check) describes current check scope;
[artifact handling](DEVELOPMENT.md#historical-evidence) covers local evidence.
This table and the operation guides define current support.

| Feature | Implemented profile | Material limit / contract |
| --- | --- | --- |
| NFSv2 | Bounded ordinary metadata, downloads, safe staged uploads, ACL inspection/export/import, explicit ACL replacement and namespace operations; TCP/UDP | Less than 2 GiB transfers; replacement requires NFSACLv2; [ordinary fixture](../tests/README.md#fixture-catalog), [replacement](../tests/README.md#fixture-catalog) |
| NFSv3 | Ordinary file/namespace operations, ACL inspection/export/import and explicit bounded replacement; TCP/UDP | NFSACL extension required for policy-preserving replacement; ordinary overwrite refuses; [NFSACL](REPLACEMENT.md#nfsv3-acl-inspection) |
| NFSv4.0/4.1/4.2 | Direct COMPOUND, ordinary OPEN/read/write/close, negotiated session budgets and leases | Fixed state/identity checks; exact original-slot recovery requires an explicit policy |
| Selection/discovery | AUTH_SYS/Kerberos explicit auto TCP 4.2 -> 4.1 -> 4.0 -> 3 -> 2; UDP 3 -> 2; explicit service ports and rpcbind/MOUNT | Only version mismatches allow fallback; pNFS/advanced paths require explicit versions |
| Resource inspection | Bounded `exports` namespace/MOUNT discovery plus explicit `--path`, provenance, security/referral boundaries and `access` observations | Fixed current identity; hidden paths require supplied names; no claim to enumerate server configuration |
| Listing evidence | `listed_entries` / `listing_complete` for attempted NFSv4 discovery READDIR | Empty requires zero entries and confirmed EOF; ACCESS permission alone is not listing evidence |
| Explicit links / ownership | `ln` / `ln -s` on v3/v4, `readlink`, v2/v3 numeric and v4 string `chown` / `chgrp` with readback | Fixed identity, no destination replacement for links; final symlinks rejected for hardlink sources/ownership; uncertain mutations are not automatically replayed |
| Legacy mount / handle diagnostics | `mounts` bounds MOUNT DUMP to 4096 records / 5 seconds; `handle` emits opaque hex and connection context | MOUNT records are not active-client evidence; unavailable on v4 without contacting mountd; handle output is not an import/recovery format |
| Protected scan | Explicit one-endpoint `--spn` or per-target `--target-spn`; keytab, ccache or password | No guessed service identity or authentication downgrade; validated with a disposable MIT KDC/Ganesha over v3/v4.0/v4.1/v4.2 TCP using krb5p |
| Capability/connection inspection | `info`, per-path `capabilities`, explicit `ls --offline` / `stat --offline` | Advertisement differs from successful operation; unknown remains unknown; optional metadata never opens content |
| Named-attribute inspection | NFSv4 OPENATTR(false), bounded listing and export to a new local file | Up to 64 entries / 64 KiB per exported value; separate from RFC 8276 xattrs; [attributes](REPLACEMENT.md#extended-and-named-attributes) |
| AUTH_SYS | UID/GID and bounded groups, explicit/fixed or v3 observed-owner selection | Server permissions/root squash remain authoritative; observed namespace root is not host `/` |
| Kerberos/GSS | v2/v3/v4 TCP and v2/v3 UDP `krb5`, `krb5i`, `krb5p`; pinned identities/SPNs, bounded routes and context renewal | No automatic security downgrade; [protected UDP](TRANSPORT.md#protected-nfsv3-udp), [TLS/GSS](TRANSPORT.md#tls-bound-gss) |
| Keytab / FILE | Explicit credential sources, valid home TGT import, AES session profiles; parse diagnostics redact keys | FILE formats 3/4, fixed principal; live connections renew eligible TGTs in memory, subject to KDC renewal lifetime; OS caches remain externally managed |
| KCM | Explicit Linux named cache/trusted socket and bounded repeated snapshots; native SSSD 2.9.4/MIT 1.20.1/Ganesha 4.3 verified | Other daemon/version combinations remain unverified; [KCM](AUTHENTICATION.md#linux-kcm) |
| KEYRING | Explicit Linux session/process/user collection and subsidiary, or current-UID persistent cache selection | No foreign-UID/thread/default selection; [KEYRING](AUTHENTICATION.md#linux-keyring) |
| LSA | Windows current-logon cache-only exportable AES home TGT | Key-export policy can refuse; positive native domain import not established; [LSA](AUTHENTICATION.md#windows-lsa) |
| SSPI | Explicit Windows current-logon Kerberos handles; ordinary krb5/i/p RPCs without key export | TLS, callbacks and GSS v3 refuse; positive native domain RPC remains unverified; [SSPI](AUTHENTICATION.md#windows-sspi) |
| AS aliases / enterprise UPN | Protected same-realm pinned canonical alias and explicit approved-realm UPN routing | No general forest/directory routing; [canonical AS](AUTHENTICATION.md#pinned-as-aliases), [UPN](AUTHENTICATION.md#enterprise-upn-routing) |
| FAST / PKINIT | Pure-Go Windows/Linux mandatory FAST, certificate AS, or combined FAST + PKINIT; explicit Linux helper remains optional | AES17/18; PKINIT requires freshness; no smart cards/PKCS11; [FAST](AUTHENTICATION.md#linux-required-fast), [PKINIT](AUTHENTICATION.md#linux-pkinit) |
| RPC-over-TLS | Mandatory AUTH_TLS, TLS 1.3/sunrpc, exact peer identity; serverAuth or rpcTLSServer purpose across a validated chain; optional client cert | No plaintext fallback or DTLS; insecure mode is explicit; [TLS contract](TRANSPORT.md#rpc-over-tls) |
| Software RPC/RDMA | MPA2 untagged inline iWARP, AUTH_SYS, one foreground RPC | About 4068-byte RPC budget; no chunks, GSS/TLS, pNFS/callbacks or hardware path; [RDMA](TRANSPORT.md#software-iwarp) |
| File locks / ranges | Whole-file and multiple nonoverlapping byte ranges, exact unlock, guarded range I/O | Advisory locks do not isolate unrelated server clients; [locks](LOCKS.md#locks-ranges-and-ownership) |
| NLM | v1/v4 TEST, retained confirmed owners, callbacks, explicit reclaim, exact-owner automatic cleanup; optional one-attempt crash notification | Notification keeps new locks quarantined: void NSM acknowledgement cannot prove delayed cleanup completion. No unknown acquisition replay/lock continuity; [recovery](LOCKS.md#confirmed-owner-cleanup), [notification](LOCKS.md#client-crash-notification) |
| Restart reclaim | Explicit original-owner OPEN/LOCK reclaim during server grace | Lease/state validation required; [reclaim](STATE_RECOVERY.md#server-restart-reclaim), [NLM reclaim](LOCKS.md#nlm-restart-reclaim) |
| Referrals / state migration | Approved protected read mappings; explicit OPEN/LOCK existing-session transfer and source-unavailable replica validation | Complete stable state/session required; [referrals](STATE_RECOVERY.md#approved-namespace-referrals), [migration](STATE_RECOVERY.md#open-and-lock-migration) |
| Automatic stateful failover | One armed protected endpoint, original session/state and exact request | No new owner/session or fallback after evidence loss; [policy](STATE_RECOVERY.md#automatic-stateful-failover) |
| Retained-lock process recovery | Durable acquisition/release lifecycle, exact cached requests, protected original-session continuation | Live lease and original slot/cache evidence required; absent/expired state quarantines; [recovery](STATE_RECOVERY.md#retained-lock-process-recovery) |
| pNFS FILE / Flex | Approved DS/mirror reads, finite writes, callbacks and bounded recovery/refresh | Explicit topology/security bounds; [FILE](PNFS_FILES.md#file-downloads), [Flex](PNFS_FILES.md#flex-files), [writes](PNFS_FILES.md#file-writes-and-uploads) |
| pNFS BLOCK | Approved images or iSCSI, range/COW writes, new uploads and explicit growth | Finite whole-block profile and lock requirements; [block](PNFS_BLOCK.md), [uploads](PNFS_BLOCK.md#new-files-and-growth), [recovery](PNFS_BLOCK.md#process-crash-recovery) |
| iSCSI | Bounded direct-access 512/4096-byte sectors and OSD transport; CHAP/mutual CHAP, CRC32C and approved block-read reconnection | No storage TLS, write replay, general multipath or reinstatement; [storage](PNFS_BLOCK.md#iscsi-storage) |
| pNFS object | OSD-1 dense RAID0 reads (NOSEC or ALLDATA) and secured finite existing-object writes with WRITE/FLUSH/MDS commit | No creation/growth, OSD-2, SSV, parity/groups/mirrors or crash journal; native OSD unverified; [object](PNFS_OBJECT.md) |
| Offload / v4.2 extensions | COPY/CLONE, async/inter-server controls, WRITE_SAME/ADB, READ_PLUS, SEEK/space/advice and bounded GSSv3 | Exact optional-operation/server/security bounds; [v4.2](OFFLOAD.md#nfsv42-operations), [offload recovery](OFFLOAD.md#crash-journal-and-acknowledgement) |
| Offload crash recovery | Original-session exact COPY/CLONE/WRITE_SAME recovery and quiescent asynchronous streamed verification; separate bounded receipt reconciliation | Lost sessions/child privileges and unresolved grants remain quarantined; original state disposal can remain unverified; [session recovery](OFFLOAD.md#original-session-recovery), [receipt reconciliation](OFFLOAD.md#receipt-confirmed-reconciliation) |
| Replacement metadata | Bounded v4 ACL/DACL/SACL/inheritance, owner/group, mode bits, label, xattrs/named policies with readback | Requires complete observable/authorized policy, not unlimited cloning or concurrent-writer CAS; [attributes](REPLACEMENT.md#extended-and-named-attributes) |
| Recursive transfer | Explicit tree merge, symbolic/hard links, ordinary mode and mtime preservation | No whole-tree atomicity or universal owner/ACL cloning; Windows symlink privileges can be required |
| Local publication | Sibling temp, sync and no-replace publication for new destinations; staged explicit replacements | Filesystem name/size limits, directory power-loss durability and cross-process isolation are not promised |

Remote filesystem formats are server responsibilities for ordinary opaque-handle
operations. This does not certify all export policies, NAS implementations or
backing filesystems. Recorded MIT/Samba/Microsoft AD, kernel/Ganesha/UNFS3 and
FreeBSD results apply only to their documented profiles. Fresh software checks
do not create new native NAS/cluster/forest interoperability evidence.

## Inspection commands

```text
info
capabilities /data
access /data/report.txt --json
ls --offline /data
stat --offline /data/archive.bin
mounts --json
handle /data/report.txt --json
```

The new link/ownership command flow was also exercised with the Windows binary
against disposable Ganesha over NFSv3 and NFSv4.1 with krb5p. Broader wire refusal,
partial-change and lost-reply cases use protocol peers in Windows/Linux checks;
these results do not certify every server filesystem or name-mapping policy.

`info` returns JSON for the connected peer, configured/best-effort display name,
transport, NFS version, AUTH_SYS fields or Kerberos principal, and actual TLS
status. EXCHANGE_ID implementation strings are server claims, not a verified
vendor fingerprint. TLS verification and RPC user authentication are distinct;
owner strings cannot establish the server's internal AD/UID mapping.

`capabilities [PATH] [--json]` returns JSON (default path `.`), distinguishing
client implementation, negotiated-protocol eligibility and per-object server
advertisement. ACL/xattr/layout/offline attributes provide metadata evidence;
COPY, CLONE and other optional operations stay unknown without such evidence.
It performs no mutation or content probes and keeps no persistent capability
cache. Advertisement is neither a successful operation nor an authorization grant.

`access PATH [--json]` preserves requested, supported and allowed ACCESS masks.
Results distinguish allowed, denied, unsupported and unknown. NFSv2 has no ACCESS.
Directory READ/LOOKUP are labelled list/traverse. NFSv4 regular-file EXECUTE can
authorize reading even when the raw READ check is denied; the report explains
this without reading content. Inspection pins and restores the current identity.
An observation is not a guarantee for a subsequent operation.

`ls --offline [PATH]` and `stat --offline PATH` request RFC 9754 metadata only
when advertised. Missing/omitted/unsupported status stays `unknown`, never
`online`; ordinary ls/stat add no optional-attribute RPCs. Explicit cat/get still
read content and may initiate server-side archive recall. The new inspection
profiles have deterministic software-peer coverage; native optional-extension
interoperability is not claimed.

Native Windows/Linux NFSv3 checks additionally cover ext4, XFS and Btrfs with
permissive and subtree-restricted exports. Bounded root candidates succeed on
the freshly formatted ext4/XFS profiles and refuse the generation-7 Btrfs
subvolume and all restricted exports. Ordinary transfers pass across all six
exports. Linux publication onto freshly formatted FAT32/exFAT passes new-file,
collision and explicit-replacement checks; this does not establish native
Windows FAT32/exFAT behavior. See the [fixture catalog](../tests/README.md).

The [client implementation plan](PLAN.md) records the completed original scope
and the separately approved RFC-informed inspection iteration. Native interoperability gaps remain evidence
limitations in this table and the operation guides; they are not unfinished
client features. Completed historical ledgers are retained as development evidence.
