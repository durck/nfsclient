# pNFS FILE and Flex layouts

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [FILE downloads](#file-downloads)
- [FILE writes and uploads](#file-writes-and-uploads)
- [Flex Files](#flex-files)
- [DS identities and callbacks](#ds-identities-and-callbacks)
- [Protected path recovery](#protected-path-recovery)
- [Protected write recovery](#protected-write-recovery)
- [Protected mirror recovery](#protected-mirror-recovery)
- [Device refresh](#device-refresh)
- [FILE session trunking](#file-session-trunking)

<a id="file-downloads"></a>
## FILE downloads

For explicit `--layout flex` reads and writes, see the
[Flex Files contract](PNFS_FILES.md#flex-files).

For new uploads and finite writes with explicit growth, see
[`putrangepnfs` and its durability contract](PNFS_FILES.md#file-writes-and-uploads). The download
contract below applies to FILE reads.

`--pnfs` explicitly enables NFSv4.1/4.2 file-layout reads over TCP with
AUTH_SYS or [explicit Kerberos DS identities and protected callbacks](PNFS_FILES.md#ds-identities-and-callbacks).
`getpnfs` gets the layout from the metadata server (MDS), reads from the
approved data servers (DS), syncs the local bytes and strictly verifies source
metadata while the layout is held, then returns the layout, closes its temporary
OPEN and publishes the local file without replacement after a final check.
Ordinary `get`, uploads and metadata operations still use the MDS.

```text
nfs-viewer 192.0.2.10 --nfs-version 4.1 --pnfs --export /data
getpnfs report.bin local.bin 192.0.2.11:2049=192.0.2.11:2049
getpnfs striped.bin local-striped.bin --parallel 3 192.0.2.11:2049=192.0.2.11:2049 192.0.2.12:2049=192.0.2.12:2049 192.0.2.13:2049=192.0.2.13:2049
```

Mappings are literal IP:port pairs. Every DS address used must have an explicit
mapping from its advertised endpoint to an approved endpoint. The target can
differ to accommodate NAT. Only advertised addresses with explicit mappings
are considered for connection fallback. IPv6 endpoints use brackets. At most
64 mappings are accepted; duplicate canonical addresses and invalid ports fail.

When a server advertises several addresses in one multipath group, the client
tries approved targets in advertised order until a TCP connection succeeds.
Duplicate targets are collapsed; each failed target is attempted only once per
transfer, including across layout segments. Each attempt uses the configured
connection timeout and respects caller cancellation. All groups must have an
approved target before any DS connection is opened.

By default, fallback stops once authentication begins: failed AUTH_TLS/TLS, Kerberos, EXCHANGE_ID, CREATE_SESSION
or READ ends the transfer without trying another address. A live DS session is
reused by target endpoint, with one outstanding READ per session. Failed paths
are reconsidered only in a new transfer. This bounded initial connection
selection follows the address alternatives described in
[RFC 8881 section 13.5](https://www.rfc-editor.org/rfc/rfc8881.html#section-13.5);
it does not provide session trunking, device refresh or in-flight recovery.

Explicit `--read-failover` adds one transport-loss READ recovery per verified
DS identity for `krb5i`/`krb5p`. It uses confirmed client-ID trunking to an
approved address in the same group; [see the separate contract](PNFS_FILES.md#protected-path-recovery).

`--tls --pnfs` also requires TLS 1.3 with `sunrpc` ALPN on every DS connection,
before AUTH_SYS or NFS initialization. The CA, client certificate and explicit
verification policy are shared with the MDS profile. DS certificate identity
defaults to the approved target IP, never the MDS `--tls-server-name`. For NAT
or certificates with DNS identities, append `@TLS_NAME` to the target, for
example `192.0.2.11:2049=192.0.2.21:2049@ds.example.test`. This name is used
only for certificate verification/SNI; it does not trigger DNS resolution.
API callers use `PNFSOptions.TLSNames`, keyed by approved target endpoints.
Unknown/duplicate canonical targets, empty names and names without TLS fail
before OPEN or layout acquisition. Failed negotiation or verification never
falls back to plaintext or another address. TLS does not replace AUTH_SYS.

`--parallel 1..8` sets the maximum concurrent READ requests to distinct approved
DS endpoints. The default is sequential. API callers set `PNFSOptions.Parallelism`
(zero means one). The client assembles contiguous batches and stops a batch at
the first repeated endpoint, keeping one outstanding request per DS session.
One DS, or consecutive chunks on the same DS, remains sequential. Initialization
is serialized and this bounded batching does not promise a throughput increase.

Each request is capped at 1 MiB and the batch at eight requests, so buffered
file payload is at most 8 MiB, in addition to RPC frames and bookkeeping.
Responses may arrive out of order; writes and progress callbacks occur in file
order after every worker in the batch has finished. By default, any worker failure cancels
outstanding sibling RPCs and joins all workers before returning layouts or
closing sessions. A failed batch contributes no output bytes. Layout/state
checks run before/after each read and again before each local write. The caller
must still serialize foreground API use on a client; parallelism is internal.
With read failover enabled, eligible transport failures allow healthy siblings
to finish before serial recovery; fatal failures still cancel the batch.

<a id="file-downloads-state-and-failure-handling"></a>
### State and failure handling

The MDS and DS use the same client owner/verifier. DS READ uses the MDS OPEN
or retained LOCK stateid with its sequence field set to zero, as required by
[RFC 8881 sections 13.1 and 13.9.1](https://www.rfc-editor.org/rfc/rfc8881.html#section-13.9.1).
Temporary DS sessions are destroyed without destroying a potentially shared
MDS client ID. Whole-file read/write locks remain held after downloads;
partial locks refuse whole-file reads before data transfer.

CREATE_SESSION sequences survive temporary DS sessions and are shared with
co-located MDS identities. The key includes client incarnation, protocol minor,
server scope/major ID and client ID, not the network endpoint or server minor ID.
Creation is serialized and response sequence numbers must match. Unknown or
unsuccessful results refuse a new creation for a confirmed identity; there is
no automatic replay. The bounded identity table refuses a 257th identity rather
than evicting state needed for a later confirmed exchange.

Strict source verification includes ctime and runs after all bytes are synced,
before LAYOUTRETURN can update server bookkeeping. After successful cleanup,
the client rechecks size, change, mtime, type and identity, retaining presence
checks. This second check permits ctime-only changes because FreeBSD updates an
MDS xattr during return. A ctime change during reading still refuses publication.
The result is detectable-change protection through the completed-read boundary,
not a snapshot guarantee or preservation of metadata changed during cleanup.
Raw API users can select `ReadPNFSToProgressVerified` to run their verifier at
this boundary; a failed verifier or failed cleanup still fails the transfer.

A serialized TCP backchannel handles CB_NULL, CB_SEQUENCE and CB_LAYOUTRECALL,
including duplicate callback detection and referring-call delays. A recall,
lost metadata channel, elapsed confirmed lease, server revocation or changed
device indication stops further DS reads. The client renews its MDS lease in
the background. Layouts are retained only during one foreground transfer.

The backchannel negotiates its own 64 KiB request/response/cache ceilings,
eight operations and one slot, independently of foreground transfer sizes.
The accepted size limits are enforced before committing callback state. Invalid
callbacks do not consume a sequence or acknowledge a recall. A response that
fits the channel but exceeds its smaller cache can succeed when `cachethis`
is false; retries receive the retained CB_SEQUENCE result and an uncached-reply
error on the next supported operation, without repeating the recall. Protocol
size refusals do not consume the callback sequence.

No failed DS read is replayed or replaced with an MDS READ. Errors, cancellation,
source changes, invalid replies and failed LAYOUTRETURN prevent publication.
Temporary local files are removed. Uncertain metadata state requires explicit
reconnect; a DS-only failure can leave the MDS session usable after successful
layout cleanup. Existing local destinations remain unchanged.

<a id="file-downloads-supported-bounds"></a>
### Supported bounds

The client acquires complete file coverage before connecting to any DS, using
at most 64 granted segments across at most 64 LAYOUTGET requests. Each request
asks for the remaining range with a one-byte minimum (zero for an empty file).
Replies must extend coverage and have file layout type 1 and one READ or RW mode
within each reply. Each LAYOUTGET result is bounded to 32 KiB. Zero lengths,
gaps, overlaps, reordered segments, finite range overflow, a pattern beginning
after its segment, and an EOF sentinel before the last segment are refused.
An invalid grant makes the metadata connection unusable; it is never read.
If a newer grant expands backwards, it replaces overlapping old coverage while
preserving the earlier prefix and its stripe pattern. Layout stateids must keep
their identity and advance, including wraparound that skips zero. A recall
received while acquiring more coverage is retained, including its newer stateid;
the client stops acquisition and returns the layout. Status/limit failures return
known grants; unknown results quarantine the metadata connection without replay.

Segments can use different device IDs, handles and striping patterns. READs
are split at both stripe and segment boundaries; dense offsets remain relative
to each segment's pattern start, which can precede the segment itself. All
segment devices and endpoint permissions are checked before the first DS
connection. A shared endpoint reuses its temporary session across segments,
with at most one outstanding READ per endpoint. The layout shares one stateid
and one whole-file LAYOUTRETURN; a recall stops the entire transfer.

Device descriptions permit at most 64 stripes, 64 server groups and eight
addresses per group, with a 32 KiB body bound per segment. The client selects
the first reachable explicitly approved address in each group, only before
protocol exchange. At most 64 distinct approved endpoints are available across the
transfer. Coverage is fetched anew per transfer; it is not cached across reads.
Successful short DS reads, including empty replies and EOF, are zero-filled
within the requested stripe and the MDS logical file size, as required by
[RFC 8881 section 13.10](https://www.rfc-editor.org/rfc/rfc8881.html#section-13.10).
The next request is still issued normally: an EOF is not cached across other
components, handles or stripes. Transport/protocol failures and NFS status errors
never produce zero-filled success. Reads use at most
1 MiB per request. Output files contain explicit zero bytes, not local sparse
allocation guarantees.

Multi-segment protocol tests cover NFSv4.1/4.2, sparse/dense layouts, pattern
and handle changes, a segment ending inside a stripe, parallelism 1/3/8, holes,
late unapproved devices, denied reads, cancellation, recalls and short local
writes. The request oracle is independent of the production offset mapping.
Stock-server multi-segment issuance remains unverified; native FreeBSD
coverage uses its single-segment FILE layout. FILE downloads do not provide
layout caching/reclaim or RDMA. Flex layouts, writes and protected DS identities
have their own sections below; [block storage](PNFS_BLOCK.md) and
[OSD layouts](PNFS_OBJECT.md) have their own guides.
Source guards observe metadata changes; they do not create snapshots.
Whole-file advisory locks still require cooperating writers.

<a id="file-writes-and-uploads"></a>
## FILE writes and uploads

The [iSCSI block storage profile](PNFS_BLOCK.md#iscsi-storage) also supports range
writes, COW, guarded new-file uploads and explicit growth on approved remote LUs.

`putrangepnfs LOCAL REMOTE OFFSET [--extend] [--parallel 1..8] ADVERTISED_IP:PORT=APPROVED_IP:PORT[@TLS_NAME] [...]`
writes a nonempty local regular file into an existing remote byte range. Select
`--pnfs`, NFSv4.1 or v4.2, and acquire a whole-file write lock with `lock REMOTE
write` first. Identity and export must remain fixed. The destination must be a
regular file of known size. Extension requires explicit `--extend` (API:
`PNFSOptions.Extend`); the default refuses writes beyond EOF. Neither mode truncates.

The Session API is `PutPNFSRange`; the Client API is
`WritePNFSRangeFromProgress`. Both retain the original lock and never acquire a
replacement, replay a failed write, fall back to MDS WRITE, or roll back bytes.
The Session checks the local file identity/size/mtime and the final remote
pathname/handle/size. On error, acknowledged or uncertain changes may remain.

The client requests RW layouts and validates complete coverage and every
approved device before DS I/O. It supports sparse and dense FILE stripes,
multiple segments, incremental acquisition and the existing explicit initial
connection alternatives. The default is sequential. `--parallel 1..8` enables
bounded concurrent writes to distinct approved DS endpoints, with one stripe
fragment per endpoint in each contiguous batch and at most 8 MiB of payload.
A repeated endpoint ends the batch; wide stripes can therefore limit overlap. Mandatory DS TLS uses the same
target-specific policy as `getpnfs` when TLS is selected for the connection.

Each WRITE uses the original lock stateid with the DS sequence field zero.
Positive short acknowledgements advance only over acknowledged bytes. Invalid
counts, stability values, truncated/lost replies and changed write verifiers
stop the operation. The client requests UNSTABLE and accepts all three valid
stability levels. It sends COMMIT to the MDS or DS as directed by
`NFL4_UFLG_COMMIT_THRU_MDS`, comparing the returned verifier. Every acknowledged
prefix is followed by LAYOUTCOMMIT to synchronize MDS metadata before progress
is reported. LAYOUTCOMMIT uses logical file offsets; DS COMMIT uses stripe
offsets. The returned size, if present, must equal the larger of the original size and
the end of the acknowledged prefix. Extension beyond EOF leaves a zero-filled gap.

A recall prevents further WRITEs. The known acknowledged prefix is flushed
while the original lock and lease remain valid, then the layout is returned.
Unknown mutation or durability outcomes quarantine MDS state instead of
returning a layout with unconfirmed writes. Reconnect/recovery is an explicit
separate operation. This profile does not implement
automatic mutation recovery, flexible/block/object layouts,
RDMA DS transport or native Kerberos DS authorization certification.
[The Kerberos profile](PNFS_FILES.md#ds-identities-and-callbacks) adds explicit DS SPNs and protected
callbacks with MIT-ticket/scripted-protocol validation.

`putpnfs LOCAL REMOTE [--parallel 1..8] DS=TARGET [...]` creates a new file and uploads through
approved FILE-layout servers. The Session API is `PutPNFS`. It validates the
source and connection profile before guarded CREATE, refuses existing names,
and obtains a temporary whole-file write lock for nonempty files. Confirmed
state is unlocked on success or known failure; uncertain acquisitions/writes
remain in the lock inventory for explicit recovery. Empty files require no
DS WRITE. This is not atomic publication: readers may see partial data during
the upload, and failure leaves the partial or uncertain destination in place.
The client checks source identity/size/mtime and final destination identity/size.

Protocol reference: [RFC 8881](https://www.rfc-editor.org/rfc/rfc8881.html),
sections 12.5.4, 13.7, 13.9.1, 18.38 and 18.42.
Protocol and native results must be recorded separately in the project status;
a successful synthetic fixture does not certify a stock server implementation.

<a id="file-writes-and-uploads-parallel-write-failure-and-progress-contract"></a>
### Parallel write failure and progress contract

Workers only use their own DS session. Source reads, connection setup, MDS
COMMIT/LAYOUTCOMMIT and progress callbacks remain serialized. Positive short
acknowledgements advance within that worker's buffered fragment; a changed
verifier, invalid reply or failed operation cancels the batch and joins every
worker. Known DS prefixes are committed by their worker. MDS COMMIT bookkeeping
is bounded to one complete fragment per worker, even for one-byte acknowledgements.

Only a completely acknowledged and committed batch receives LAYOUTCOMMIT and
advances progress. Successful later stripes do not count as a contiguous prefix
when another worker fails. Any failed batch that issued a WRITE quarantines the
MDS state unless explicit same-session write recovery resolves every uncertain
fragment before publication; it never issues a replacement mutation in a new session.
A recall after every fragment completed permits metadata flushing, then stops
new work; a recall interrupting a partial batch leaves it quarantined. The last
confirmed batch remains visible in the returned count. This can leave later
changed bytes beyond that count, as with other uncertain writes.

<a id="file-writes-and-uploads-later-block-image-range-write-profile"></a>
### Block image range writes

[Block range writes/COW](PNFS_BLOCK.md#range-writes-and-cow) require explicit image-write
approval and an existing whole-file write lock. They initialize server blocks,
synchronize images and use the type-3 commit list. This separate profile has no
DS WRITE fallback or mutation replay. Later [new-file uploads and explicit
growth](PNFS_BLOCK.md#new-files-and-growth) reuse guarded creation and block initialization.

<a id="flex-files"></a>
## Flex Files

`getpnfs REMOTE LOCAL --layout flex ADVERTISED_IP:PORT=APPROVED_IP:PORT`
explicitly selects layout type 4 (RFC 8435). The connection still requires
`--pnfs --nfs-version 4.1` or `4.2`. Omitted `--layout` retains FILE layouts.
The public API selects this profile with `PNFSOptions{Layout: "flex"}`.

<a id="flex-files-supported-profile"></a>
### Supported profile

- AUTH_SYS over TCP for loose/tight devices, or explicit `krb5`, `krb5i` and
  `krb5p` for tight devices. Mandatory RPC-over-TLS can be combined with either
  profile; each DS certificate is independently verified. Explicit
  `--read-failover` supports the bounded krb5i/krb5p tight-device profile below.
- Loose NFSv3 devices use the layout's canonical numeric synthetic UID/GID,
  without supplementary groups or an implicit MOUNT operation.
- Tight NFSv4.1/4.2 devices use the original MDS identity, including groups,
  the layout's global DS stateid and the advertised protocol version. They
  ignore synthetic identity strings as required by RFC 8435 section 5.1.
  DS sessions retain the MDS client incarnation and CREATE_SESSION sequence
  history. The DS minor version may differ from the MDS minor version.
- Up to eight mirrors, 64 total stripe components, eight protocol handles and
  eight TCP/TCP6 paths per device. Mirrors must have equal stripe widths;
  the highest total advertised efficiency wins, with stable ties. Only that
  mirror is read. Every selected component of every granted segment is
  validated and approved before any DS connection.
- Sparse stripe mapping preserves the logical offset, including across
  segment boundaries. Requests respect stripe, segment, file, device and
  client limits. Short non-EOF replies continue at the next byte; EOF fills
  the remainder with zeros only below the MDS size. Zero progress without EOF
  fails. `--parallel 1..8` retains one worker per distinct endpoint and ordered
  publication after the complete batch succeeds.
- Recalls match the active layout type. Cancellation, retained MDS locks,
  source verification, temporary-file cleanup and publication follow the
  existing pNFS download contract. Failed DS reads are reported through the
  Flex Files LAYOUTRETURN error array; optional usage statistics are empty.
  No failure falls back to MDS READ or replays a request on another mirror.
  Opt-in protected path recovery is described below.

Opt-in [device refresh](PNFS_FILES.md#device-refresh) supports protected tight-device
reads. Loose NFSv4 devices, NFSv4.0 devices, session trunking and general HA
remain outside this profile. Block/object
layouts and hardware RDMA remain separate.

<a id="flex-files-writes"></a>
### Writes

`putpnfs LOCAL REMOTE --layout flex DS=TARGET` creates a new file with the
existing guarded-upload lifecycle. `putrangepnfs LOCAL REMOTE OFFSET --layout
flex DS=TARGET` modifies an existing file under a retained whole-file write
lock. `--extend` is still required for range growth. Neither command replaces
an existing file through a new-file upload or silently falls back to MDS WRITE.

All required mirrors are approved before data-server I/O. Every mirror gets
the same stripe fragment unless WRITE_ONE_MIRROR explicitly delegates mirror
updates to one selected server. Up to `--parallel 1..8` different mirror
endpoints run together; shared endpoints are serialized. This bounds mirror
concurrency, not parallel writes to successive stripes. An issued wave is
joined before reporting failures or issuing MDS operations.

Each WRITE requests FILE_SYNC. Both UNSTABLE and DATA_SYNC replies require
DS COMMIT before MDS LAYOUTCOMMIT, with exact verifier matching. Short
acknowledgements advance only over accepted bytes. Progress advances only
after all required replicas and metadata are durable. NO_LAYOUTCOMMIT skips
the metadata operation exactly when requested by the layout. The destination
size is rechecked after completion; a write-only RW layout remains usable for
writes even when NO_READ_IO prevents downloads.

An incomplete fragment reports all potentially divergent replicas through
Flex LAYOUTRETURN before uncertain MDS state is quarantined. This report does
not claim recovery or durability. There is no replay, mirror replacement,
implicit new lock or rollback. A failed upload can leave a named partial file;
confirmed prefixes and temporary-lock cleanup retain the normal upload contract.

<a id="flex-files-kerberos"></a>
### Kerberos

Tight NFSv4.1/4.2 devices preserve the authenticated MDS principal and GSS
service. Every approved DS target requires `--ds-spn TARGET=nfs/HOST`, using
the same options as [protected FILE layouts](PNFS_FILES.md#ds-identities-and-callbacks). The DS creates
its own authenticated context before EXCHANGE_ID and uses the layout's global
stateid. TLS upgrades precede GSS and bind each context to its own exporter.
There is no downgrade after failed authentication or protocol negotiation.

RFC 8435 section 15 does not define RPCSEC_GSS for loose coupling. A protected
transfer therefore refuses a loose device during complete device preflight,
before contacting any DS, including earlier compatible components. Writes
check every required mirror; WRITE_ONE_MIRROR checks the delegated mirror.
Authentication-only krb5 has the usual payload-integrity limitation; use
krb5i/krb5p when data integrity/confidentiality is required.

`TestFlexMITRead`, `TestFlexMITWrite` and `TestFlexMITBackchannel` cover 216
read, 288 write and 12 protected callback cases per OS with real MIT tickets,
all three GSS services, both MDS minors, optional TLS, two mirrors and one/three
stripes. Refusal cases independently count accepted DS connections; no loose
profile may connect. Six additional pool tests reject identity/service/SPN
changes before dialing. Write failures cover lost replies, downgraded COMMIT,
recall and cancellation without mutation replay. Read failures include corrupt
replies, denied access and joined cancellation of parallel requests.

<a id="flex-files-protected-read-path-recovery"></a>
### Protected READ path recovery

`getpnfs REMOTE LOCAL --layout flex --read-failover ...` permits one transport
recovery per confirmed DS identity, at most eight per transfer, using krb5i or
krb5p. It uses only already approved alternate addresses of the same component
and requires the same Kerberos SPN, user, protection, server owner/scope, client
ID and advertised DS minor before creating a replacement session. The MDS
minor can differ. Unknown creation sequences, authentication errors, NFS errors,
malformed replies, cancellation and recalls cannot trigger replay.

The complete parallel batch is joined before serial recovery. A partial short
component reply is discarded and the original component window is read again;
publication waits for the entire batch. Recovered DS errors are still sent in
LAYOUTRETURN. The existing global DS stateid and selected mirror are retained.
There is no mirror switch, device refresh or write replay. See [the recovery
contract and verification matrix](PNFS_FILES.md#protected-path-recovery).

<a id="ds-identities-and-callbacks"></a>
## DS identities and callbacks

Both FILE and tight [Flex Files](PNFS_FILES.md#flex-files-kerberos) layouts support this
profile. Loose Flex devices are refused before DS connections.

Select explicit NFSv4.1 or v4.2, TCP, `--pnfs` and `--sec krb5`,
`krb5i` or `krb5p`, with the ordinary explicit Kerberos configuration,
principal, keytab/FILE cache and MDS service principal. `getpnfs`, `putpnfs`
and `putrangepnfs` accept a repeatable `--ds-spn TARGET=nfs/HOST`:

```text
getpnfs report.bin local.bin --ds-spn 192.0.2.21:2049=nfs/ds.example.test 192.0.2.11:2049=192.0.2.21:2049
```

Each approved target needs an explicit SPN, including initially unused
alternatives. API callers use `PNFSOptions.SPNs`, keyed by canonical target
IP:port. The target is the dial address after mapping; the SPN identifies the
Kerberos service and does not trigger a DNS lookup. Empty, malformed, duplicate
canonical or unapproved mappings fail before OPEN/layout acquisition or new-file
creation. Supplying DS SPNs under AUTH_SYS is an error.

Every DS authenticates using the selected MDS principal, protection level and
effective credential paths. Each DS has its own GSS context and NFS session.
Initial TCP connection failure may select another approved target; Kerberos,
NFS initialization or subsequent I/O failure never switches targets or security.
The existing durability, lock, source verification, partial-result and uncertain
mutation contracts remain applicable.

The MDS session offers only RPCSEC_GSS callbacks, using its shared Kerberos
context with separate fore/back RPC sequence windows and distinct context
handles. Even authentication-only `krb5` requires integrity-protected callbacks;
`krb5p` requires encrypted callbacks. Header and body authentication, service,
context handle, lifetime and replay checks precede callback state changes.
Shared cryptographic operations are serialized. Replies are protected with the
same callback service and sequence; negotiated request/reply/cache limits
include security framing.

At context renewal or sequence exhaustion, the client serializes foreground
work, establishes a fresh context under the same identity/security policy and
confirms BACKCHANNEL_CTL on the existing session before continuing. Layouts,
locks and callback sequence state stay on that session. Old authenticated
handles retain their replay windows until expiry; at most eight live contexts
are retained. Active callbacks can arrive during renewal. Cancellation, rejected
or uncertain control replies quarantine the connection without replay.

Durable recovery recorders, saved exact requests, uncertain work and pinned
inter-server COPY state refuse rotation before new work is sent. This does not
transfer such state to a replacement session. DS contexts can renew before a
new request under the existing identity-preserving rules. Connection close joins
the callback reader before releasing retained GSS contexts.

TLS plus Kerberos uses a separate exporter binding on every MDS/DS connection;
see [the combined profile and independent MIT GSS checks](TRANSPORT.md#tls-bound-gss).
AUTH_SYS with mandatory TLS remains available. RDMA,
recovery across expired contexts and native server
authorization interoperability remain separate work.

The retained native Ganesha 4.3/LizardFS image has GSS enabled but its RPCSEC_GSS
callback implementation is incomplete. Windows/Linux checks of NFSv4.1/4.2 with
krb5i/p confirm ordinary protected MDS metadata access, then explicit pNFS
connection refusal because the server declines the backchannel. Server logs
independently confirm all eight refusals. The isolated
[fixture](../tests/README.md#fixture-catalog) records this boundary; it proves no
protected DS transfer or recovery and does not weaken callback authentication.

<a id="protected-path-recovery"></a>
## Protected path recovery

`getpnfs ... --read-failover ...` opts into one transport-loss recovery per
authenticated DS identity during a FILE or tight Flex Files download. The default remains
fail-fast after an interrupted READ. The API option is `PNFSOptions.ReadFailover`.
It requires `--sec krb5i` or `krb5p`; writes reject the option before mutation.

The alternative must be in the same already validated GETDEVICEINFO multipath
group, with an explicit approved endpoint mapping and the same selected user,
Kerberos service principal and GSS protection. TLS, when selected, remains
mandatory with its per-target certificate identity and exporter binding.

The client retains the original EXCHANGE_ID owner, scope, client ID, protocol
minor and client incarnation. Before CREATE_SESSION on an alternative it
requires a confirmed, identical tuple and a known successful CREATE_SESSION
sequence. A changed server minor ID is allowed for client-ID trunking. This
does not bind a new connection to the lost session: a new session is created,
and no uncertain session slot or session-creation request is reused.

Only transport errors marked at the stream I/O boundary are eligible. Complete
malformed RPC/XDR, failed authentication, expired contexts, NFS errors, caller
cancellation/deadlines, lost MDS state and recalls stop the transfer. A failure
during alternate authentication or session creation stops without trying a
third protocol endpoint. Initial TCP dial refusals may skip to another approved
address, using the existing bounded multipath rules.

For parallel reads, the client joins all original workers before recovery.
Recoverable transport loss does not cancel healthy sibling reads; other failures
do. Recovery READs run serially with the same handle, stateid, offset and count.
FILE uses its retained OPEN/LOCK state; Flex keeps the layout global DS stateid.
A short Flex prefix from an incomplete component request is discarded before
retrying the original request window; published bytes are never duplicated. The failed endpoint is retained as unavailable, the new session is
reused for subsequent stripes, and a second loss for that identity stops.
Bytes and progress for a batch are emitted only after the entire batch succeeds.
Previously emitted batches remain partial data if a later batch fails. Normal
source verification and local publication checks still apply; this is not a
snapshot or a general HA/restart recovery mechanism.

Flex recovery is additionally limited to eight attempts per download. Every
original transport failure is retained as a READ/NFS4ERR_NXIO report in the
Flex LAYOUTRETURN, even after successful recovery (RFC 8435 section 7). Up to
eight further errors from a final parallel batch also fit the bounded report.
The alternative must belong to the same component's advertised multipath list;
the selected mirror, stripe mapping, protocol minor, global stateid and device
ID remain unchanged. Recovery never switches to a different mirror. Loose
Flex devices, AUTH_SYS and authentication-only krb5 are refused before I/O.

Mirror switching is a separate opt-in [Flex policy](PNFS_FILES.md#protected-mirror-recovery).
It cannot be combined with this same-DS path recovery option.

<a id="protected-mirror-recovery"></a>
## Protected mirror recovery

`getpnfs REMOTE LOCAL --layout flex --mirror-failover ...` permits one change
of mirror per granted layout segment after READ transport loss. The API option
is `PNFSOptions.MirrorFailover`. It requires krb5i or krb5p, explicit endpoint
mappings and an explicit SPN for every approved DS. It cannot be combined with
`--read-failover`, which preserves the identity of one DS while changing its
network path. Both options are forbidden for writes.

Before contacting any DS, the client validates every component of every mirror
in all granted segments. Each must provide an approved tight NFSv4.1/4.2
profile. TLS, when enabled, remains mandatory with per-target certificate
identity and exporter binding. Loose devices and missing approvals stop before
DS connections, including when they belong to an initially unselected mirror.

After a marked transport error, the client joins all original workers and
selects the remaining mirror with the greatest summed efficiency; ties retain
advertised order. Each failed original stripe maps to the corresponding stripe
of that mirror. The replacement uses its own device, filehandle, global DS
stateid, protocol minor and approved service principal. Its authenticated user
and GSS protection must match the MDS. A different confirmed server identity is
valid here because the MDS layout explicitly grants access to that replica.

The entire failed request window is reread, discarding an incomplete short
prefix. Replacement requests respect the new DS read-size limit. Completed
siblings are retained, and subsequent batches use the chosen replacement mirror.
Bytes and progress advance only after every request in the current batch has
succeeded. Ordinary MDS source verification, layout return, OPEN/lock cleanup
and guarded local publication still apply.

There is one mirror switch per segment and at most eight recovered requests per
download. Failure of the replacement, including its authentication or session
creation, stops the transfer. No third mirror is tried. A second failure on the
replacement also stops. All original DS failures remain in the Flex error return,
even after successful recovery. The report also has room for a final failed
parallel batch.

NFS access errors, malformed RPC/XDR, authentication failures, recalls, lost MDS
state and cancellation do not authorize switching. No MDS data fallback, device
refresh, new layout acquisition, lock reclaim or write replay is introduced.
This is a read policy under a retained layout, not general HA or replica repair.

Protocol basis: RFC 8435 sections 7 and 8 require error reporting, identical
over-the-wire mirror contents and client selection of the read mirror. The MDS
owns replica repair and must recall affected layouts during recovery.

<a id="device-refresh"></a>
## Device refresh

`--refresh-devices` on `getpnfs`, `putrangepnfs` or `putpnfs` selects protected
FILE or tight Flex mapping recovery. The API option is
`PNFSOptions.RefreshDevices`. It requires krb5i/krb5p and cannot combine with
session trunking, read path failover or mirror failover. It can accompany
`--write-failover`. All possible targets, SPNs and
TLS certificate identities must be supplied before the transfer.

The client requests CHANGE and DELETE notifications in GETDEVICEINFO and
requires the server to accept both. A server declining this optional feature
causes a clean refusal and layout return. CB_NOTIFY_DEVICEID is processed on
the existing protected backchannel with its slot replay/cache rules. At most
64 records per operation are decoded; unknown device IDs or layout types do
not grow retained state. The notification layout type must match the active
FILE or Flex grant. Malformed callbacks do not commit any device changes.

Non-immediate CHANGE notices can be applied at the next read-batch boundary.
Every segment referencing that device receives the new address mapping before
further DS selection. Initial segments retain their individual mapping
generation so a notice between two initial queries cannot hide a stale segment.
A notice racing GETDEVICEINFO causes another query. Eight refresh queries are
allowed per transfer; persistent churn stops instead of looping indefinitely.

Updates preserve stripe indices/count, server-group count, layout stateid,
filehandles and file offsets. Every server group still needs an explicit
approved destination. Updated addresses may select a different authenticated
DS, as authorized by the MDS mapping, using that target's preselected SPN and
TLS identity with the original user/service. This does not claim session
trunking or continuity of the old DS identity. Removed paths are no longer
selected; retained connections are closed during normal transfer cleanup.

Immediate CHANGE fences the old mapping until current requests have joined and
the mapping has been refreshed. A stale read batch is discarded and its window
read again using the accepted mapping. DELETE revokes affected layouts: the
client returns them and requests a fresh grant using the original OPEN/LOCK.
Deleted device IDs remain tombstoned for the client incarnation; a grant reusing
one is refused. Layout recall, MDS state loss and unauthorized topology still
stop the transfer. Reads are published only after a complete accepted window.

Writes refresh or reacquire layouts only before the first mutation or after a
fully durable, published batch. A notification during an issued mutation with
unproved completion quarantines that batch; acquiring a fresh layout cannot
establish its outcome. The original lock remains required, and every Flex mirror
must be durable before progress or LAYOUTCOMMIT. No operation falls back to an
MDS READ or WRITE.

<a id="device-refresh-tight-flex-files"></a>
### Tight Flex Files

Add `--layout flex` to refresh addresses of the selected mirror's components.
Mirror selection, stripe geometry and global stateids remain fixed. Only tight
NFSv4 devices with krb5i/krb5p are eligible; synthetic AUTH_SYS identities and
loose NFSv3 are not used for refresh. Reads leave unselected mirrors unopened;
writes refresh all required mirror components, including notices for a mirror
that has not yet received the current batch.

A single GETDEVICEINFO response is decoded separately against the handle
array of every selected component referencing the changed device. All must
retain their original major/minor version, selected handle and read/write
limits. The client commits all replacement addresses and mapping generations
together after validation. A callback racing that query keeps refresh pending;
all queries share the same eight-query transfer limit. Stateids and per-segment
handles are never copied from one component to another.

<a id="device-refresh-protocol-basis"></a>
### Protocol basis

[RFC 8881 sections 12.2.10, 18.40 and 20.12](https://www.rfc-editor.org/rfc/rfc8881.html#section-20.12)
define device mapping lifetime, notification negotiation and the distinction
between immediate and non-immediate changes. A notification racing an address
query can make its result stale; obtaining a new mapping is required before
using that result as current.
Flex protocol/handle associations follow [RFC 8435 sections 4.1 and
5.3](https://www.rfc-editor.org/rfc/rfc8435.html#section-5.3).

## Protected write recovery

`putrangepnfs` and `putpnfs` accept `--write-failover` for FILE and tight Flex
layouts, with krb5i/krb5p and explicit approved alternate endpoints. The API
option is `PNFSOptions.WriteFailover`. It does not combine with read/mirror
failover or session trunking.

After a transport failure, the client authenticates an approved alternate with
the same principal, service and SPN, verifies the server owner/scope/incarnation
and client ID, then binds the original session. It retransmits the exact cached
WRITE or COMMIT compound with the original slot and sequence. No new session,
lock or replacement write is created. One recovery attempt is allowed per DS
session. Missing cached replies, changed identities, malformed responses,
expired state or a second transport failure leave the outcome uncertain.

Sequential and parallel writes share this rule. Flex still writes every required
mirror; recovery never skips a replica. Count, progress and metadata publication
advance only after all corresponding data and COMMIT results are verified.
Independent peers with real MIT-issued tickets exercise dropped WRITE/COMMIT
responses, exact reply-cache reuse and one mutation execution on Windows/Linux,
with TCP/TLS and krb5i/krb5p. These are protected protocol tests, not certification
of native server failover or hardware storage recovery.

<a id="file-session-trunking"></a>
## FILE session trunking

`getpnfs REMOTE LOCAL --session-trunking ...` opts into shared sessions across
approved paths in each FILE data-server group. The API option is
`PNFSOptions.SessionTrunking`. It requires krb5i/krb5p, optionally over TLS,
and is separate from path failover, mirror failover and device refresh. Flex
layouts and writes are refused. The default path policy is unchanged.

Every selected path must have the same explicit DS SPN, user principal and
GSS service. The first connection creates a session; each additional connection
authenticates independently, confirms the original client ID, server owner,
server scope and server minor ID, then binds its fore-channel to that session.
BIND_CONN_TO_SESSION must return the original session, fore-channel direction
and no RDMA binding. A failed or lost binding never falls back to session
creation. All selected paths are bound before the group starts reading.

The group rotates read windows across its connections. One shared mutex and
slot sequence serialize requests across aliases; this is not a multi-slot
throughput optimization. Other independent DS groups can still run concurrently.
An uncertain reply poisons the common slot and stops all aliases without replay.
Each connection retains its own GSS context and TLS exporter binding. Cleanup
attempts session destruction once through its owner and closes each connection;
a lost owner transport can prevent confirmation of server-side destruction.

The profile uses SP4_NONE; it does not provide SP4_MACH_CRED or SSV state
protection. Protocol rules are in [RFC 8881 sections 2.10.5 and
18.34](https://www.rfc-editor.org/rfc/rfc8881.html#section-18.34).
