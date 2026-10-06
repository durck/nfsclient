# NFS state, migration and recovery

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [Server-restart reclaim](#server-restart-reclaim)
- [OPEN and LOCK migration](#open-and-lock-migration)
- [Automatic stateful failover](#automatic-stateful-failover)
- [Retained-lock process recovery](#retained-lock-process-recovery)
- [Approved namespace referrals](#approved-namespace-referrals)
- [Protected MDS read failover](#protected-mds-read-failover)

<a id="server-restart-reclaim"></a>
## Server-restart reclaim

For explicit legacy NFSv2/v3 recovery, see the separate
[NLM server-enforced-grace profile](LOCKS.md#nlm-restart-reclaim).

`reconnect --reclaim-locks` makes one explicit attempt to recover previously
confirmed NFSv4 OPEN and LOCK state after a server restart. It preserves lock
IDs, access type and exact ranges, including the EOF sentinel. It is separate
from `reconnect --discard-locks`, which deliberately abandons old state.

Recovery preserves the in-memory client owner/verifier and each open/lock
owner, establishes a fresh transport/session, and requires a changed server
client ID. It sends OPEN with CLAIM_PREVIOUS and LOCK with reclaim=true.
NFSv4.1/4.2 send RECLAIM_COMPLETE only after every lock has been acknowledged.
Any delegation returned during reclaim is immediately returned. The original
export identity, working directory and every locked pathname/file handle are
validated before the new shell session is published. SEQUENCE revocation or
LEASE_MOVED notifications at initialization, reclaim operations, RECLAIM_COMPLETE,
lease confirmation or the final pathname lookup refuse success and retain the
old uncertain inventory. RESTART_RECLAIM_NEEDED is tolerated only during the
active grace reclaim; after completion it invalidates recovered state.

Only confirmed acquisitions are eligible. An uncertain LOCK or LOCKU, changed
identity, known revocation/expiration/invalid state, missing namespace binding,
or elapsed last confirmed lease prevents recovery. The entire attempt is
bounded by that prior lease deadline. Lease confirmation tracking is conservative:
successful LOCK and background renewal update it; arbitrary file activity
does not extend the recovery window. No on-disk client crash recovery is claimed.

There is one attempt per old client incarnation. Once it starts, old protected
I/O is disabled. A partial reclaim, expired grace window, RECLAIM_BAD/CONFLICT,
changed file handle or lost reply does not fall back to a new non-reclaim lock.
It also does not replay interrupted READ, WRITE, RENAME or other file operations.
Failure leaves the old inventory uncertain for inspection and explicit discard;
the server may retain partially recovered state until its lease expires.

The command requires the server's recovery/grace support and timely invocation.
It is not an automatic reconnect policy, recovery from arbitrary long network
partitions, a promise against future lock revocation, or protection from
uncooperative writers that ignore advisory locks.

Recorded Windows/Linux kernel-restart profiles cover AUTH_SYS and Microsoft AD
`krb5p` across all three minors, including independent contention and unlock
checks. Protected recovery creates a fresh authenticated GSS context.
TLS, NAS failover and multiple rapid server reboots require additional native
validation; hardware transports are outside the accepted scope.

References: [NFSv4 recovery](https://www.rfc-editor.org/rfc/rfc7530.html),
[NFSv4.1 reclaim and sessions](https://www.rfc-editor.org/rfc/rfc8881.html).

<a id="server-restart-reclaim-automatic-protected-download"></a>
### Automatic protected download

`reget --reclaim-locks REMOTE [LOCAL]` and `Session.GetResumeReclaim` add a
separate opt-in read recovery policy. Obtain a confirmed whole-file lock on
the original source pathname first. The operation holds the local resume
exclusion through both attempts and permits exactly one server-restart reclaim
after a recoverable read failure. It cannot be combined with `--retries`.

All retained locks, their IDs, ranges, file handles, paths and credentials must
remain unchanged. The recovery uses the same bounded reclaim implementation
described above. An unchanged server client ID, failed/uncertain reclaim,
expired lease or known revocation stops the operation without a replacement
lock. There is no retry of a failed reclaim and no automatic file mutation.

After recovery, the source path, filesystem/file identity and metadata must
still match the first attempt. The entire retained prefix is reread and
compared before accepting new bytes. Local errors and mismatching source or
prefix never trigger reclaim. Session/identity changes or unlock/relock from a
progress callback stop publication, including changes at EOF. The foreground
API remains single-threaded; this guard does not make concurrent Session use
supported. Failed recovery retains verified partial bytes and uncertain lock
inventory for inspection.

This policy does not recover after client process crashes, discover failover
servers, or replay uploads and other mutations. Its native security/transport
coverage is retained with the reclaim-resume recipes in the
[fixture archive](DEVELOPMENT.md#historical-evidence).

<a id="open-and-lock-migration"></a>
## OPEN and LOCK migration

`migrate SERVER=HOST:PORT,SPN,TLS_NAME` transfers the selected export and all
confirmed retained locks to one explicitly approved NFSv4.1/4.2 TCP endpoint.
Use fixed credentials and namespace (`--auto-uid=false --auto-escape=false`).
At least one retained lock is required. The current export must return a fully
decoded MOVED response. Its fs_locations root must exactly equal that export;
the advertised SERVER must exactly match the approval. Trust anchors, principal,
GSS service, credentials and protocol remain fixed. Bare AUTH_SYS, unprotected
krb5, insecure TLS and callback/pNFS profiles are refused.

```text
lock report.bin write
migrate destination.example=192.0.2.20:2049,,destination.example
locks
get report.bin local.bin
unlock 1
```

<a id="open-and-lock-migration-state-and-namespace-contract"></a>
### State and namespace contract

The target must confirm the same client owner/verifier, client ID and nonempty
server scope. A different server owner is allowed within that scope. The client
binds the already transferred session using BIND_CONN_TO_SESSION, retaining its
slot sequence. It tests both OPEN and LOCK stateids of every retained lock using
TEST_STATEID. Each result must confirm validity, with exact count and XDR framing.
No new session, ordinary replacement LOCK, reclaim OPEN or data request is issued
as fallback. Unknown CREATE_SESSION sequencing is never guessed.

The target pseudo-root is obtained afresh. The remapped export must retain its
handle, filesystem ID and file ID. Every recorded regular-file pathname must
resolve without symlinks to the original locked handle. The original CWD is
resolved under the new export. Lock IDs, owners, OPEN/LOCK stateids, credentials,
access mode, finite ranges and through-EOF ranges are retained. The complete
inventory and final lease renewal are checked before publishing the new Session.

At most 64 locks are supported. The last confirmed lease must still be live;
its deadline bounds the complete transition. LEASE_MOVED alone suspends data and
state operations at the source while permitting namespace discovery. It can
authorize this explicit validation workflow. Revocation, malformed responses,
uncertain acquisition/unlock, unknown slots or any lost state refuse migration.

Once the transition starts, the old transport is disabled. Failed validation
retains the original Session and uncertain lock inventory for explicit discard;
it never unlocks or destroys potentially transferred state. Success transfers
ownership once, replacing the interactive server/export/CWD together. Closing
the retired connection cannot release the transferred locks/session. No command
or unknown mutation is replayed. Subsequent user commands can read, write and
unlock using the validated retained state.

This profile requires complete state/session transfer and stable handle/ID
classes. Partial state merge, lost-session replacement, alternate location
retries, NFSv4.0 migration and client-process recovery are outside this command.
`migrate --source-unavailable SERVER=HOST:PORT,SPN,TLS_NAME` selects the
separate approved-replica workflow when the source cannot provide MOVED. It
requires the same server owner/scope/minor and client incarnation, a known
slot, live lease, confirmed locks and exact namespace validation. It cannot
resolve an interrupted request that was not armed for cached recovery.

<a id="automatic-stateful-failover"></a>
## Automatic stateful failover

`migrate --arm-failover SERVER=HOST:PORT,SPN,TLS_NAME` approves one automatic
transport transition for the current healthy NFSv4.1/4.2 session. Use a fixed
selected export and credentials, protected TCP, and a distinct target address.
Kerberos must retain the original SPN; TLS uses the explicitly approved name.
`migrate --status` reports the target and whether the approval is armed or consumed.

Subsequent compounds request cached replies. After a qualifying transport loss,
the approved target must confirm the same server/client incarnation and bind
the original session. The exact request, slot and sequence are retried there:
a request already executed returns its cached result; a request never received
can execute once. The client retains original handles, OPEN/LOCK stateids and
namespace. No replacement session, owner or ordinary acquisition is created.
Authentication, protocol, state revocation and cache-loss failures stop the flow.

One approval permits one attempt, including a failed attempt. After success,
explicitly arm a further target if needed; an uncertain session cannot be rearmed.
This policy applies to ordinary compounds, including reads and mutations. It
requires a server cluster that actually shares the original session/state; equal
file contents or an operator's endpoint approval alone do not establish continuity.
Callbacks, pNFS/offload and endpoint-bound durable journals cannot be combined
with this policy. Process recovery uses the separate journal contract below.

The APIs are `Session.ArmStatefulFailover`, `Client.EnableStatefulFailover` and
`Client.StatefulFailoverStatus`. Protected independent peers test both minors,
applied/never-started writes, cached reads, denial and invalid-session controls.
Native cluster interoperability remains unverified.

<a id="retained-lock-process-recovery"></a>
## Retained-lock process recovery

`lock-save ABSOLUTE_JOURNAL` attaches a new durable journal to the selected
namespace. Saving an empty inventory arms journaling before subsequent lock
acquisitions; saving existing confirmed locks retires the journal once the inventory becomes empty.
Both modes permit additional pathname-bound acquisitions while active. Restart with `--recover-locks FILE`,
the same explicit protected NFSv4.1/4.2 TCP profile and fixed credentials.
Omit `--export` on recovery: the journal selects its saved export/CWD.

```text
lock-save /private/state/locks.journal
lock report.bin write
get report.bin local.bin
```

```text
nfs-viewer server.example --nfs-version 4.2 --tls --tls-ca ca.pem --tls-server-name server.example --auto-uid=false --auto-escape=false --recover-locks /private/state/locks.journal --command "get report.bin recovered.bin" --command "unlock 1"
nfs-viewer lock-state inspect /private/state/locks.journal
```

Windows uses an absolute path such as `C:\NfsState\locks.journal`. Create a
private directory protected by local filesystem access controls first. The
journal contains protocol stateids/owners, namespace handles and identities;
it can contain the exact pending WRITE payload. It contains no ticket, GSS key
or private key. Protect the journal as private application data. Inspection is offline,
redacted to serial, armed/pending/retired state, pending phase, lock count,
confirmation time and recovered operation/status/count.

<a id="retained-lock-process-recovery-durable-boundaries"></a>
### Durable boundaries

The journal records client owner/verifier, client ID, server owner/scope/minor,
session/slot sequence, confirmed lease, exact connected peer, fixed security,
principal/AUTH_SYS groups and trust-file hashes. It preserves all OPEN/LOCK
stateids, owners, ranges, access modes, owner sequences and namespace paths.
Authenticated TLS requires an explicit certificate name. Kerberos requires
krb5i/krb5p. Callbacks, offload, pNFS, insecure TLS and NFSv4.0 are refused.

An active journal permits subsequent pathname-bound lock acquisitions.
Reclaim/migration and untracked metadata mutations are refused while journaling.
Ordinary metadata navigation, retained-lock reads/writes and unlock remain available.
Acquisition persists the planned owner/path/handle before OPEN, then records OPEN
and LOCK separately. Release records LOCKU, FREE_STATEID and CLOSE separately.
An armed journal stays active after the last unlock; a journal saved with existing
locks retires after their final release. A local pre-issue
refusal preserves confirmed inventory/slot/journal state so allowed operations
remain usable. A journal identity/size/storage error or unknown RPC result instead
quarantines the client. Graceful close releases
known locks through the journal. A new journal cannot overwrite an existing
file; a retired journal cannot recover or silently start another incarnation.

An exclusive OS file lock prevents another process from recovering live state.
Length/SHA256 framing, strict JSON/bounds, increasing serial and preserved
incarnation/inventory reject truncated, incompatible or reordered records.
Every append checks the open file's identity and expected size. Maximums are
64 locks, 4 MiB per record and 16 MiB per journal; capacity/storage failure
refuses requests and retains quarantine. Preserve corrupt/pending evidence.

<a id="retained-lock-process-recovery-restart-contract"></a>
### Restart contract

The old protocol incarnation is continued with the same owner and verifier.
This does not create a restarted protocol owner or ordinarily reacquire locks.
A still-live confirmed lease and complete original session evidence are required.
The saved deadline bounds the whole attempt. Every recoverable operation records
its exact cache-enabled compound before issue and syncs validated phase/result
state before the next phase. A pending operation can therefore request its original cached
reply after a crash; a second crash retains the same durable phase evidence.

Fresh protected transport/GSS uses EXCHANGE_ID, BIND_CONN_TO_SESSION and
TEST_STATEID. The exact server owner/scope/minor, peer, client ID, identity,
session sequence and every OPEN/LOCK must still match. Namespace checks verify
the export handle/IDs, saved working-directory path, and each regular-file
path/handle without symlinks. The final renewal and advanced slot are synced
before recovered state becomes visible. No CREATE_SESSION sequence is guessed,
no new OPEN/LOCK fallback is acquired. Pending OPEN/LOCK, WRITE/COMMIT and
LOCKU/FREE_STATEID/CLOSE phases use the same session, slot, sequence and exact
request. A previously executed request returns its cached result; one never
received by the server can execute once in that original slot. An uncached or
lost session is not replaced with a new mutation. A recovered final release in
a non-armed journal reports that locks are already released; normal reconnect
starts a new incarnation. An armed journal remains available with no locks.

An unjournaled or incompatible pending RPC, expired lease, changed
time/profile/server, missing state, unavailable cached result or failed validation
stops recovery. Failed candidates do not destroy borrowed
sessions or locks. This is process-crash recovery with retained local storage
and server state. Power loss, hostile rollback, deleted storage, server restart,
partial state recovery and restoration of a crash before the journal was armed
are outside this profile. Native NAS/domain interoperability remains unverified;
hardware is N/A.

<a id="approved-namespace-referrals"></a>
## Approved namespace referrals

`reget --referral SERVER=HOST:PORT,SPN,TLS_NAME REMOTE [LOCAL]` follows
`NFS4ERR_MOVED` through `fs_locations` on ordinary NFSv4.0/4.1/4.2 over TCP.
Repeat `--referral` for up to eight approvals. SERVER is the exact advertised
server string; HOST:PORT and its protected identities are operator selections.

```text
reget --referral replica.example=192.0.2.10:2049,nfs/replica.example, reports/file.bin file.bin
reget --referral replica.example=192.0.2.10:2049,,replica.example reports/file.bin file.bin
```

The first example uses krb5i/krb5p; the second uses authenticated TLS with
AUTH_SYS. With both Kerberos and TLS, specify both identities. Existing trust
anchors, credentials, principal, GSS service and negotiated protocol remain
fixed. Bare AUTH_SYS, krb5 without integrity/privacy, insecure TLS, pNFS/offload
callbacks and held locks are refused. Current/base credentials must match.
The selected export and identity must be fixed (`--auto-uid=false`,
`--auto-escape=false`). Other reget recovery modes cannot be combined.

<a id="approved-namespace-referrals-namespace-and-recovery-boundaries"></a>
### Namespace and recovery boundaries

The client first resolves the requested path under the selected export. On
MOVED, it requests only fs_locations, using LOOKUP/GETATTR without GETFH when
an absent filesystem cannot return a filehandle. The advertised fs_root must
be a component-wise prefix of both the encountered namespace and requested
physical pathname. A location root replaces that prefix and preserves the
remaining suffix. No raw advertised hostname becomes dial authority: only an
exact approved SERVER mapping can be selected. Empty/current-address selectors
and unapproved locations are unsupported.

Responses are bounded to 64 path components, 255 bytes per component, eight
locations, eight server strings per location and a 64 KiB attribute value.
Invalid UTF-8, dot components, embedded separators, missing/unsolicited
attributes and trailing XDR are refused. Paths are limited to 16 KiB and this
bounded profile refuses symlinks and explicit `.`/`..` navigation. Other shell
namespace commands retain their existing behavior.

Each transition creates fresh transport, GSS context, client owner, session and
read OPEN state. No old handle, stateid, LOCK or uncertain RPC slot is carried
to the new server. A private working Session holds the remapped namespace;
the interactive Session's server/export/CWD remain unchanged. No referral cache
outlives this command. There are at most eight transitions and repeated
endpoint/path pairs stop as cycles. A failed selected connection stops the flow;
it does not try an unapproved alternate or downgrade security.

If migration occurs after the source was observed, filesystem/file identity,
metadata and the complete retained prefix must match before accepting new data.
This supported migration profile requires stable IDs and metadata across the
transition; deployments changing those classes are refused. Progress and notice
callbacks cannot change original credentials or namespace and still publish.
The local resume exclusion remains held across transitions. Final metadata/name
checks, file synchronization and atomic no-replace publication retain the
ordinary reget contract.

Only a fully decoded MOVED result authorizes switching. An accompanying cleanup,
authentication, revocation or transport error stops recovery. The common decoder
now rejects trailing bytes on NFSv4 error replies; malformed MOVED cannot be
used as referral authority. An uncertain upload or other mutation is never
replayed. Lock continuity is available through the separate explicit [state migration command](STATE_RECOVERY.md#open-and-lock-migration).

<a id="protected-mds-read-failover"></a>
## Protected MDS read failover

`reget --failover HOST:PORT,SPN,TLS_NAME REMOTE [LOCAL]` permits a fresh
ordinary NFSv4 connection to an explicitly approved endpoint after a recoverable
download failure. Repeat `--failover` for an ordered list of 1..8 endpoints.
Empty identity fields remain present; commas are separators, not part of a name.

```text
reget --failover backup.example:2049,nfs/backup.example, report.bin report.bin
reget --failover backup.example:2049,nfs/backup.example,backup.example report.bin report.bin
reget --failover backup.example:2049,,backup.example report.bin report.bin
```

The first example selects Kerberos without TLS, the second combines Kerberos
with TLS, and the third uses AUTH_SYS over authenticated TLS. Enable the matching
security/TLS profile when connecting the original client. Every Kerberos target
needs an explicit `nfs/hostname` SPN, and every TLS target needs an explicit
certificate name. Trust anchors, client certificates, keytab/cache, principal,
security flavor and negotiated NFS version remain fixed. There is no downgrade,
implicit SPN selection, insecure TLS or plaintext fallback. Bare AUTH_SYS and
authentication-only `krb5` are refused. The existing `--retries` and
`--reclaim-locks` modes cannot be combined with this mode.

<a id="protected-mds-read-failover-recovery-and-publication"></a>
### Recovery and publication

This profile covers ordinary NFSv4.0/4.1/4.2 over TCP, with a fixed identity and
selected export (`--auto-uid=false --auto-escape=false`). It excludes pNFS/offload
callback profiles and all held locks. The entire target list is validated before
the first transfer; duplicate normalized addresses are refused. The local resume
exclusion remains held across every connection attempt.

Each target is tried at most once. The budget never resets after progress;
connection failures consume entries. Only recoverable network/server read
failures qualify, and the original file identity must already have been observed.
Local failures, prefix/source mismatch, authentication failure, changed session,
namespace, current/base credentials or lock inventory stop recovery. A notice or
progress callback cannot bypass those checks, including at EOF.
The CLI reports each selected alternate and the failure that caused the switch.

Every successful switch creates fresh transport, Kerberos context, NFS client
owner/session and OPEN state. It does not transfer old stateids, file handles,
lock owners or an uncertain session slot. Export filesystem/file identity,
working directory and resolved source pathname must remain consistent. The
source filesystem/file ID, metadata and entire retained prefix are checked before
accepting a suffix. The source's final metadata/name are checked before atomic
local publication. Complete prefix comparison rereads bytes from offset zero;
it saves retained progress, not prefix network traffic.

Operator approval must designate paths/replicas with stable file and filesystem
identities and an appropriate consistency policy. Equal IDs/metadata do not
certify a cluster's replication or an immutable file snapshot. This profile
does not discover referrals or `fs_locations`, prove server trunking, resume
mutations, migrate OPEN/LOCK state, maintain lock continuity, or implement general
cluster HA. Ordinary NFS metadata/Open/Close/durability operations still apply;
no upload or failed mutation is replayed. See [RFC 8881 section 11](https://www.rfc-editor.org/rfc/rfc8881.html#section-11)
for the wider multi-server namespace protocol.

The API is `Session.GetResumeFailover` with `[]nfs.ReadReplica`.
`Client.ConnectReadReplica` only creates a fresh connection; its caller must
validate namespace/content before using it and owns its lifetime. Foreground
Session/Client APIs remain serial.
