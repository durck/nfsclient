# NFSv4.2 operations and offload recovery

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [NFSv4.2 operations](#nfsv42-operations)
- [Protected inter-server COPY](#protected-inter-server-copy)
- [Crash journal and acknowledgement](#crash-journal-and-acknowledgement)
- [Original-session recovery](#original-session-recovery)
- [Receipt-confirmed reconciliation](#receipt-confirmed-reconciliation)

<a id="nfsv42-operations"></a>
## NFSv4.2 operations

The base v4.2 connection uses ordinary READ/WRITE. The following optional
[RFC 7862](https://www.rfc-editor.org/rfc/rfc7862.html) operations are now explicit
commands; they require the actual negotiated minor version to be 4.2.

Optional `--offload-journal ABSOLUTE_FILE` preserves COPY/CLONE/WRITE_SAME crash
evidence and quarantines an unknown issued result. The additional
`--offload-session-recovery` option records the original session/request for
[exact recovery](#original-session-recovery). See the
[recovery contract and offline commands](OFFLOAD.md#crash-journal-and-acknowledgement).

| Command | Behavior |
| --- | --- |
| `seek PATH OFFSET data\|hole` | Return JSON `{offset,eof}` for the next server-reported boundary |
| `allocate PATH OFFSET LENGTH` | Reserve storage; extend logical size when necessary, reading as zeros in the extension |
| `deallocate PATH OFFSET LENGTH` | Discard bytes in that range, making subsequent reads return zeros; do not shrink size |
| `getplus REMOTE LOCAL` | Download with READ_PLUS, decoding DATA and HOLE segments; publish only after source verification |
| `advise PATH OFFSET LENGTH HINT[,HINT...]` | Send I/O hints using a retained whole-file lock; zero length means through EOF |
| `copyrange SRC DST SRC_OFFSET DST_OFFSET LENGTH` | Request one synchronous, consecutive server COPY into an existing destination |
| `clonerange SRC DST SRC_OFFSET DST_OFFSET LENGTH` | Request one server CLONE into an existing destination |
| `copyasync SRC DST SRC_OFFSET DST_OFFSET LENGTH WAIT` | Permit asynchronous intra-server COPY and wait for callback completion (`--offload`) |
| `copyfrom SOURCE_IP:PORT EXPORT SRC DST SRC_OFFSET DST_OFFSET LENGTH WAIT DEST_IP:PORT [SOURCE_IP:PORT ...]` | Authorize and wait for COPY from a separately selected source server/export |
| `writesame PATH OFFSET REPEAT_COUNT HEX_PATTERN WAIT` | Repeat a 1..4096-byte block using WRITE_SAME (`--offload`) |
| `writeadb PATH OFFSET BLOCK_SIZE BLOCK_COUNT WAIT [--number OFFSET FIRST] [--pattern OFFSET HEX]` | Initialize application data blocks, with optional numbering and a placed pattern (`--offload`) |
| `label PATH` | Read the opaque security label as format/policy/hex JSON |
| `setlabel PATH FORMAT POLICY HEX` | Set one opaque security label and verify readback on the same file handle |
| `xattrs PATH` | Enumerate user xattr keys as sorted JSON |
| `getxattr PATH KEY` | Read one user xattr as key/hex JSON |
| `setxattr PATH KEY create\|replace\|either HEX` | Create or replace one user xattr and verify readback |
| `removexattr PATH KEY` | Remove one user xattr and verify absence |

For the space commands, offsets/lengths are decimal uint64 values. Length must be positive and the end
must not overflow. Final symbolic links and nonregular files are refused.
The client opens the resolved file and checks the returned handle. Existing
whole-file locks are honored; mutations require a write lock if one is held.
Partial, uncertain or differently owned held locks refuse these operations.
No server operation is emulated. Ordinary failures do not retry a mutation
with a new session or sequence. A lost or
malformed acknowledgement is reported as an unverified outcome. A successful
operation followed by failed state cleanup is reported separately.

SEEK reports the filesystem's logical data/hole interpretation, not physical
allocation. Reserved unwritten blocks may be reported as holes or data after
reading populates the page cache. Preserve `NFS4ERR_NXIO` (status 6): Linux 6.8
returns it when there is no later DATA as well as beyond EOF; the client does
not invent a successful result. Servers can return NOTSUPP independently for
each optional operation.

<a id="nfsv42-operations-bounded-asynchronous-offload"></a>
### Bounded asynchronous offload

Connect with `--nfs-version 4.2 --offload` over TCP with AUTH_SYS or explicit
`--sec krb5`, `krb5i` or `krb5p`. The client
negotiates a callback channel on the existing connection; no separate listener
or automatic security downgrade is used. `--pnfs` remains a separate opt-in.
TLS may protect AUTH_SYS connections; recorded native AUTH_SYS coverage uses
plain TCP. Kerberos uses authenticated shared-context callbacks.
TLS/GSS uses [connection-specific channel binding](TRANSPORT.md#tls-bound-gss). Hardware/RDMA
offload profiles remain unimplemented.

`copyasync` uses one consecutive intra-server COPY, allowing either synchronous
completion or a server-generated offload stateid. `writesame` uses one
WRITE_SAME with FILE_SYNC requested. Its block is exactly the decoded hex
pattern; the repeat count is positive, the complete range must fit uint64,
and ADB block numbering is disabled. Both commands modify existing regular
files, honor whole-file locks and refuse partial/read-only/uncertain locks.
They do not replace metadata, roll back, or emulate unsupported server features.

WAIT is a positive duration up to 24 hours, for example `30s`. While waiting,
the client accepts CB_OFFLOAD only for the bound destination handle/stateid.
Early callbacks receive DELAY until the initial reply binds that stateid.
OFFLOAD_STATUS reports progress, but successful completion still requires the
callback's byte count, stability and verifier. Short completion is an error;
unstable bytes require COMMIT with an unchanged verifier. Repeated callbacks
follow the negotiated sequence/cache policy, including a zero-sized cache.
A retired offload stateid does not itself invalidate unrelated file locks.

Deadline/cancellation sends at most one bounded OFFLOAD_CANCEL. A confirmed
cancel stops work but can leave changed bytes. Unknown initial replies, lost
state or unconfirmed cancellation stop without mutation replay and can leave
server work running. Foreground Session/Client calls must remain serialized.
The client keeps OPEN/LOCK state until completion or bounded cleanup; this
profile alone does not recover an offload across a client crash or reconnect.
Use the explicit [original-session recovery](#original-session-recovery) option
to retain the additional evidence before an operation starts.

<a id="nfsv42-operations-protected-intra-server-offload"></a>
#### Protected intra-server offload

The `offload-gss` profile protects COPY/WRITE_SAME, status/cancel operations and
CB_OFFLOAD using the selected Kerberos identity. Callback integrity is mandatory
even under `krb5`; `krb5p` requires encrypted callbacks. It uses the same shared
context and independent RPC replay window as
[pNFS callback protection](PNFS_FILES.md#ds-identities-and-callbacks). Authentication and job binding
precede completion publication. Eligible sessions renew callback contexts through
confirmed BACKCHANNEL_CTL on the existing session. Pinned COPY child state,
durable recorders or uncertain requests refuse rotation and close without replay;
server work may remain uncertain if cancellation cannot be confirmed.
Ordinary reconnect does not recover that job; original-session recovery must
have been enabled before issue.

The opt-in MIT lifecycle fixture is listed in the
[fixture catalog](../tests/README.md#fixture-catalog). Protected inter-server COPY requires the separate
[RPCSEC_GSSv3 privilege profile](OFFLOAD.md#protected-inter-server-copy).

<a id="nfsv42-operations-explicit-inter-server-copy"></a>
### Explicit inter-server COPY

`copyfrom` requires an existing regular destination, `--nfs-version 4.2
--offload`, and TCP. The default AUTH_SYS profile requires no TLS. The explicit
protected profile uses `--sec krb5p --rpcsec-gss-version 3`, `--source-spn` and
`--copy-user`; see [protected inter-server COPY](OFFLOAD.md#protected-inter-server-copy).
The AUTH_SYS profile connects to the selected source endpoint/export using
the current UID, GID and supplementary groups,
with the existing timeout/reserved-port policy. No identity probing or export
discovery occurs. Both source and destination must permit inter-server COPY.
The AUTH_SYS profile does not negotiate secure server-to-server delegation.

```text
copyfrom 192.0.2.10:2049 /data source.bin destination.bin 0 0 1048576 30s 192.0.2.20:2049
```

`DEST_IP:PORT` identifies the destination as seen by the source. The optional
final addresses approve the source locations the destination may receive;
without them only `SOURCE_IP:PORT` is approved. All are literal IP endpoints.
Client-facing NAT endpoints and server-facing addresses can differ, but the
source list returned by COPY_NOTIFY is forwarded exactly, never rewritten,
filtered or resolved through DNS. An unapproved location refuses COPY and
revokes the source grant. Names/URLs and non-TCP locations are unsupported.
The list and caller approvals are each bounded to 64 entries.

The client retains source/destination OPEN or covering whole-file LOCK state,
requests one COPY_NOTIFY, checks its finite lease before COPY, then performs
one consecutive COPY. Zero lease duration means no time limit; the caller's
WAIT still bounds the operation. Synchronous completion and CB_OFFLOAD use the
same count/stability/COMMIT checks as `copyasync`. Every confirmed grant gets
one bounded OFFLOAD_CANCEL on the source after completion or error. Revocation
uses a separate cleanup deadline, including after caller cancellation.
An unconfirmed revocation quarantines the source connection. An unknown grant
or COPY result is reported as unverified and never replayed.

The Session API rechecks source metadata after success; this detects observed
changes but cannot promise a snapshot. Short copies, errors and failed cleanup
can leave destination bytes changed. There is no rollback or WRITE emulation.
Serialized API callers can use `Client.CopyRangeFrom` with two existing clients
and `CopyFromOptions`; `Session.CopyFrom` opens the selected source connection.

<a id="nfsv42-operations-application-data-blocks"></a>
### Application data blocks

`writeadb` generalizes `writesame` using the same single WRITE_SAME request and
completion/cleanup lifecycle. It initializes an existing regular file range
from blocks of 1..1,048,576 bytes, with a positive count and no uint64 range
overflow. With neither option it requests zero-filled blocks. A pattern is
1..4096 bytes at the specified relative block offset; it must fit completely.
`--number` supplies a relative offset and a uint32 initial number. Numbering
must not wrap across the requested block count. This bounded profile reserves
eight bytes for the number field, following the example in RFC 7862 section
8.2, and rejects pattern overlap with that region. The initial number is
encoded as the protocol's count4. Successful native numbering interpretation
has not been verified against a supporting server.

```text
writeadb image.bin 0 4096 100 30s --number 0 0 --pattern 8 feedface
writeadb image.bin 0 4096 100 30s
```

Absent optional fields use the RFC UINT64_MAX relative-offset sentinel.
The API exposes `ApplicationDataBlock`, `ValidateApplicationDataBlock` and
`WriteApplicationDataBlocks`; nil `FirstNumber` and empty `Pattern` omit those
fields, whose unused offsets must be zero. `writesame` retains its original
full-block pattern semantics. Neither command emulates unsupported operations
with WRITE or promises rollback after partial completion.

<a id="protected-inter-server-copy"></a>
## Protected inter-server COPY

Connect the destination with explicit NFSv4.2/TCP, `--offload --sec krb5p
--rpcsec-gss-version 3` and the usual explicit Kerberos credentials. The source
uses the same user principal and privacy service with its own selected NFS SPN.
Unsupported versions or failed privileges never fall back to AUTH_SYS, GSSv1
or client-side READ/WRITE copying.

```text
copyfrom 192.0.2.10:2049 /data source.bin destination.bin 0 0 1048576 30s 192.0.2.20:2049 --source-spn nfs/source.example.test --copy-user alice@example.test
```

`--copy-user` is the exact NFSv4 `user@domain` name to which both servers map
the authenticated principal. Servers must authorize that mapping; the client
does not infer it from a UID or Kerberos principal. All source endpoints are
literal, explicitly approved IP:port addresses. The COPY_NOTIFY list is
forwarded unchanged.

With destination TLS, both client connections require TLS. Supply an explicit
`--source-tls-name` for the source certificate identity. The source inherits
trust anchors and client-certificate policy, and each GSS context uses its
own connection's TLS exporter. Client TLS does not independently configure
the servers' data-transfer transport; servers must implement secure delegation.

<a id="protected-inter-server-copy-lifetime-and-cleanup"></a>
### Lifetime and cleanup

Both privacy parents are pinned before OPEN or privilege creation. Each must
last beyond the WAIT deadline plus an 18-second cleanup reserve without renewal.
Otherwise COPY is refused before authorization; reconnect for fresh contexts.

Each copy generates a fresh 32-byte secret. Privacy-protected RPCSEC_GSS_CREATE
on the source requests exactly `copy_from_auth`, binding that secret, destination
and mapped user. COPY_NOTIFY uses the returned child. After validating the grant
and lease, a destination CREATE requests exactly `copy_to_auth`, binding the same
secret, exact source list and user. COPY, STATUS and destination CANCEL use this
child; source cancellation uses the source child.

Children share the parent's cryptographic mechanism with independent RPC
sequences. A child is selected for one serialized RPC. Lease traffic, OPEN/CLOSE
and COMMIT retain the parent. The v3 reply MIC binds XID, procedure and complete
credential, separating parent/child replies even at equal sequence numbers.
Protected callbacks retain their replay window and use v3 reply verifiers.

The client requires an exact privilege echo and refuses assertion mapping.
A malformed reply with a known child gets one bounded DESTROY. Unknown, empty
or parent-alias handles close the parent and report unverified revocation.
Unknown CREATE, COPY, CANCEL or DESTROY results never cause replay.

Every confirmed child gets bounded DESTROY; every confirmed source grant gets
bounded OFFLOAD_CANCEL. Cleanup failures reach the caller, and closed connections
invalidate retained NFS state. Cleanup does not restore partially changed bytes.
Session-level source metadata verification remains in place.

Servers own `copy_confirm_auth`, its server-to-server GSS context, READ
authorization and cleanup. The client does not impersonate a server or replace
missing delegation with cleartext transfer. See [RFC 7861](https://www.rfc-editor.org/rfc/rfc7861.html)
and [RFC 7862 section 4.9.1.1](https://www.rfc-editor.org/rfc/rfc7862.html#section-4.9.1.1).

<a id="crash-journal-and-acknowledgement"></a>
## Crash journal and acknowledgement

Opt-in [receipt-confirmed automatic reconciliation](OFFLOAD.md#receipt-confirmed-reconciliation)
now verifies bounded synchronous whole-file COPY/CLONE after a process crash.
The baseline quarantine and operator acknowledgement described below still
apply when neither a durable completion receipt nor the additional original-session
recovery evidence can resolve an unknown operation.

`--offload-journal ABSOLUTE_FILE` enables an append-only local journal for
NFSv4.2 COPY, CLONE and WRITE_SAME/ADB, including inter-server COPY. It requires
`--offload`, a private existing local directory and fixed CLI identity:
`--auto-uid=false --auto-escape=false`. Use the same journal on every restart.
Without this explicit option the existing operation behavior remains available.

```powershell
.\nfs-viewer-windows-amd64.exe server.example --nfs-version 4.2 --offload `
  --auto-uid=false --auto-escape=false --offload-journal C:\NfsState\copy.journal
```

The journal binds the connected target, NFS version, effective security and
principal/AUTH_SYS identity, RPCSEC_GSS version/SPN and TLS policy. Each operation
records its source/destination file handles, offsets, length, source profile,
readable endpoint/identity descriptions and a random operation ID. It retains
callback IDs as diagnostic evidence. It does not store COPY shared secrets,
GSS keys, tickets, keytabs or TLS private keys. The additional session-recovery
option stores exact request arguments, which can include WRITE_SAME patterns. Preserve the
original command/export/path information to help map handles to files.

<a id="crash-journal-and-acknowledgement-durable-boundaries"></a>
### Durable boundaries

An exclusive OS file lock prevents concurrent users of the same journal.
Length/checksum framing, strictly increasing record numbers and checked intent
transitions reject truncated, corrupt, reordered or incompatible records.
Each append is synced and checks the open file's identity and expected size.
The journal is bounded to 4 MiB; a full or externally changed file refuses a
new request. It is not silently repaired, truncated, compacted or deleted.

1. `prepared` is synced before OPEN preparation. No COPY/CLONE/WRITE_SAME,
   COPY_NOTIFY or GSS COPY privilege may be sent under this phase.
2. `issued` is synced before the first data operation or inter-server
   authorization. It conservatively means a request *may* have been sent.
3. Known asynchronous callback IDs are synced before the wait continues.
   Failure to save one triggers the existing bounded cancellation attempt.
4. `completed` is synced only after the NFS operation, durability checks and
   resource cleanup all succeed. Additional Session source-stability checks
   can still fail; this record is not independent content certification.

A fresh process can retire a pending `prepared` operation as `not-issued` and
start a new explicitly requested operation. It never continues an old byte
range. Any failure after `issued`, including a refusal, cancellation, partial
result or cleanup failure, remains `unverified` and blocks another tracked
operation. Inter-server source connection creation is also blocked by an issued
pending record. The journal does not gate unrelated ordinary READ/WRITE or
namespace commands; it is not a general transaction/recovery subsystem.

<a id="crash-journal-and-acknowledgement-inspect-and-acknowledge"></a>
### Inspect and acknowledge

The following commands run offline, with no NFS connection:

```text
nfs-viewer offload-state inspect ABSOLUTE_FILE
nfs-viewer offload-state ack ABSOLUTE_FILE OPERATION_ID --server-quiesced --destination-verified
```

Inspect validates the entire journal and prints the latest record as JSON.
An active owner prevents inspection/acknowledgement until it releases the lock.
For an issued pending record, first establish externally that the old server
work cannot modify the destination, then independently verify or repair that
destination. Use its exact operation ID and both confirmation flags to record
that decision. Acknowledgement preserves `acknowledged-unknown` and the original
intent/error. It does not send CANCEL, stop server work, restore bytes, certify
COPY success or reuse a saved stateid. A wrong/stale ID is refused.

After a clean terminal record, archive a full journal and select a new file if
needed. Never replace/delete pending or corrupt evidence to bypass quarantine.
Local filesystem access controls must protect the journal and its directory.
This profile covers process crashes with the same retained local storage;
power-loss, adversarial rollback, deleted storage and general HA are not claimed.

[RFC 7862 section 4.8](https://www.rfc-editor.org/rfc/rfc7862.html#section-4.8)
invalidates copy-offload stateids when the client/server restarts. Therefore
saved IDs alone cannot authorize restart-time STATUS/CANCEL or continuation.
The opt-in continuation below first proves that the original protocol incarnation
and session survived; it does not create a new incarnation around an old ID. The
client also rejects an asynchronous stateid whose sequence is zero, as required
by that section. Live-client cancellation and protected context destruction
continue to use the existing bounded cleanup paths.

<a id="original-session-recovery"></a>
## Original-session recovery

Enable `--offload --offload-journal ABSOLUTE_FILE --offload-session-recovery`
before starting an operation. Use explicit NFSv4.2 TCP, a fixed identity and
protected transport (verified TLS or krb5i/krb5p), with the same explicit server,
principal/SPN and trust files on recovery. The journal stores exact cache-enabled
compounds and original session/slot evidence before issue, then validated results
before advancing. Callback completion is synced before acknowledgement.

```text
nfs-viewer offload-state inspect ABSOLUTE_FILE
nfs-viewer SERVER --nfs-version 4.2 --tls --tls-ca ca.pem --tls-server-name SERVER --auto-uid=false --auto-escape=false --recover-offload ABSOLUTE_FILE --offload-operation OPERATION_ID
```

Recovery selects the saved intent. Omit export, batch/interactive commands and
lock-recovery options. The standalone command prints its result as JSON. New
session-recovery operations inventory their owned OPEN state before acquisition;
the independent source and content-verification connections retain separate
session/request ledgers. Verification-owned LOCK, LOCKU, FREE_STATEID and CLOSE
are recorded as separate phases. Caller-owned retained locks are explicitly
borrowed and are never released by offload recovery.

Recovery reports `completed` with `Recovery.StateCleanup="confirmed"` only
after the data result, source authorization and every operation-owned resource
have checked completion evidence. A prepared operation can finish as `not-issued`
after releasing its resources, without issuing COPY. A second process crash
resumes the recorded cleanup phase on its original session. Old records without
an ownership inventory retain `completed-data-state-unverified` and
`Recovery.StateCleanup="unverified"`; missing state evidence cannot be replaced
with a guessed release. A normal live operation likewise requires checked cleanup.

A validated server refusal or short/failed result remains a failed data operation.
Recovery records that result and releases resources whose ownership and safe
release are proven; successful cleanup does not convert the operation to success.
The verifier keeps its original session while a durable completion receipt is
pending, including after a receipt-write failure. Unrelated lease traffic cannot
advance an OPEN or CLOSE checkpoint.

For an unresolved compound, a fresh authenticated transport must bind the original
live session and exact server/client incarnation before sending the same request
with its original slot/sequence. An executed request returns its cached reply;
a request never received can execute once. No fresh COPY, CLONE or WRITE_SAME
with a new session/sequence substitutes for unavailable evidence. Lost sessions,
expired leases, missing cached results or changed authentication remain quarantined.
Synchronous COPY/CLONE and WRITE_SAME/ADB support this exact-request continuation,
including required COMMIT/verifier checks.

For asynchronous work, durable callback completion can resolve the result.
Otherwise the still-live original incarnation can use the confirmed offload ID
with journaled OFFLOAD_STATUS. A successful final STATUS establishes quiescence;
it does not prove durability. Expected range SHA256, destination identity/size
and parent/name were saved before issue. A fresh protected connection then checks
the original namespace binding, takes a whole-file read lock, performs COMMIT,
streams the exact range through SHA256 and checks stable attributes and cleanup.
There is no 16 MiB range cap in this streaming verification path. Once original
operation-owned resources are durably released, a quiescence record permits
fresh verification after the original lease expires. Legacy records lacking an
inventory can also take this path but retain unverified cleanup. Unresolved
original or source resource cleanup still requires its surviving session;
lease expiry alone never proves quiescence.

Inter-server recovery also needs confirmed source-grant revocation or its actual
server-granted expiration. The local WAIT timeout does not shorten that grant. Persisted expiration
requires a trusted wall clock across restarts; moving that clock forward can
invalidate this evidence, so require confirmed revocation or external quiescence
when clock continuity is uncertain. An infinite or unknown grant remains unresolved. A pending secure GSSv3 COPY
request cannot be retried after losing its original child privilege; that secret
is not persisted or replaced with a broader identity.

Session recovery uses a fixed two-bank checkpoint file created before its first
operation. Each bank stores the latest validated transition. The inactive bank
is invalidated and synced, its new body is synced, then its commit marker is
synced before publication. The old committed bank remains intact throughout.
Each record is bounded to 64 KiB. This is process-crash protection; host
power loss and initial directory-entry durability are outside its contract.
Interrupted inactive writes can fall back to it; malformed commit markers or
committed checksums quarantine the file. The original inode stays exclusively
locked. Repeated STATUS polls cannot grow this file without bound.

This checkpoint retains current recovery evidence rather than a chronological
log. Existing append-only journals keep their original format; resolve their
pending intent before selecting a new checkpoint file. Failed or killed recovery
preserves pending evidence; a later attempt repeats only the recorded phase.
Missing content expectation, changed bytes/name/identity, malformed STATUS,
failed COMMIT or cleanup prevents verified completion. Advisory locks and digest
observations do not exclude writers bypassing locks or provide atomic publication.
Deleted evidence, hostile rollback and server-incarnation replacement cannot be
repaired by guessing. Keep unresolved operations quarantined for the explicit
offline acknowledgement workflow above.

<a id="receipt-confirmed-reconciliation"></a>
## Receipt-confirmed reconciliation

The client can automatically compare a crashed synchronous COPY/CLONE against
pre-recorded expected bytes and retire its pending journal. This is an explicit
verification command on a fresh connection, not an automatic retry of a mutation.

<a id="receipt-confirmed-reconciliation-supported-profile"></a>
### Supported profile

Recording requires `--offload --offload-journal ABSOLUTE_FILE --offload-reconcile`,
explicit NFSv4.2 over TCP, fixed credentials and a protected connection:
AUTH_SYS with verified TLS, or RPCSEC_GSS integrity/privacy. TLS requires an
explicit certificate name. Ordinary intra-server `copyrange` and `clonerange`
are supported for entire equal-size regular source/destination files from byte
zero, positive length up to 16 MiB, without retained locks or pNFS. Complete
file identity, change and modification/metadata timestamps must be available.
Async COPY, inter-server COPY and WRITE_SAME/ADB remain available in their
existing profiles with this recording option disabled.

The existing private append-only 4 MiB journal uses exclusive OS process
locking, strict framed/checksummed records and synced appends. The option adds
the expected source SHA256, full-file size, destination FSID/FileID and a
fixed recovery profile including trust-file hashes. It does not store file
payloads or private credentials. Source bytes are streamed through a bounded
digest; complete metadata must match before/after hashing. Intent is durable
before source OPEN, and `issued` is durable before COPY/CLONE.

After the entire synchronous operation succeeds, including COPY's existing
stable-write/verifier checks, the client synchronizes a completion receipt
**before** OPEN cleanup and the final journal retirement. This receipt is the
necessary evidence that the old operation has finished. A crash during that
cleanup leaves a receipt-confirmed pending record which a fresh process can
reconcile. A clean successful operation still retires as `completed`.

<a id="receipt-confirmed-reconciliation-run-verification-after-a-crash"></a>
### Run verification after a crash

Inspect the journal offline to obtain the exact operation ID:

```text
nfs-viewer offload-state inspect ABSOLUTE_FILE
```

Reconnect with the same explicit NFSv4.2 host/port, security, identity, export
and trust settings, **without** `--offload` or its recording flags. Run:

```text
offload-reconcile ABSOLUTE_FILE OPERATION_ID DESTINATION
```

The command resolves the destination without following symlinks or referrals,
checks the exact saved file handle and FSID/FileID/size, and requires the saved
profile and a valid completion receipt. It acquires a fresh whole-file advisory
read lock, performs COMMIT and streams the entire destination through SHA256.
The complete digest must match the expectation saved before the original
operation. Before/after file attributes, connection identity and credentials
must remain stable. Fresh state cleanup must finish before the synced terminal
record `reconciled-verified` is written. Original intent/error evidence remains.

No COPY, CLONE, WRITE, OFFLOAD_STATUS, OFFLOAD_CANCEL, COPY_NOTIFY or saved
offload stateid is used by reconciliation. The command neither repairs bytes
nor acquires write access. A failed or killed verifier leaves the pending
receipt intact; another fresh verifier may try the observation again.

<a id="receipt-confirmed-reconciliation-limits-and-quarantine"></a>
### Limits and quarantine

Without original-session recovery evidence, a crash **before** the completion
receipt is synced remains quarantined even
if the file currently contains the expected bytes. Neither a fresh lock, a
lease timeout, a new session, a changed server incarnation nor a later SEQUENCE
proves that an unknown old operation has stopped. A lost reply can therefore
require external quiescence/destination verification and the existing exact-ID
operator acknowledgement described in [crash evidence](OFFLOAD.md#crash-journal-and-acknowledgement).
Asynchronous or inter-server operations without this receipt have that same
boundary. Their unknown mutations are never replayed.

The read lock is advisory. File metadata and SHA256 are observations, not
compare-and-swap publication or exclusion of bypassing writers/ABA changes.
Verification does not preserve old locks and does not make COPY atomic.
It certifies the observed complete bytes after a known completion receipt,
not which actor produced those bytes. Existing local journal storage must be
retained and access-controlled. Power loss, adversarial journal rewriting or
rollback, deleted evidence, endpoint remapping and general distributed recovery
are outside this profile. Native NAS/cluster/domain interoperability is
unverified; hardware work is N/A at the user's request.

The protocol basis is [RFC 7862 COPY](https://www.rfc-editor.org/rfc/rfc7862.html#section-15.2)
and [synchronous CLONE](https://www.rfc-editor.org/rfc/rfc7862.html#section-15.13).
[Offload stateids expire across restart](https://www.rfc-editor.org/rfc/rfc7862.html#section-4.8).
[RFC 8881 session sequencing](https://www.rfc-editor.org/rfc/rfc8881.html#section-2.10.6.2)
requires waiting for the old reply before using the next sequence; a new
SEQUENCE is not a recovery barrier.
