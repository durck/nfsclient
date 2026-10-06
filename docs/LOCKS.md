# Advisory locks and legacy NLM

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [Locks, ranges and ownership](#locks-ranges-and-ownership)
- [NLM restart reclaim](#nlm-restart-reclaim)
- [Confirmed-owner cleanup](#confirmed-owner-cleanup)
- [Client-crash notification](#client-crash-notification)

<a id="locks-ranges-and-ownership"></a>
## Locks, ranges and ownership

Explicit legacy server-restart recovery is described in the
[NLM reclaim contract](LOCKS.md#nlm-restart-reclaim). It requires `--nlm-reclaim` and a server
that rejects reclaim outside grace; general client-crash recovery stays separate.

<a id="locks-ranges-and-ownership-nfsv2v3-conflict-inspection"></a>
### NFSv2/v3 conflict inspection

`locktest PATH read|write [OFFSET LENGTH|eof]` uses NLM TEST (program 100021,
version 1 for NFSv2 and version 4 for NFSv3). It reports either one conflicting
holder's type/range/SVID or no conflict at that instant. It does not acquire a
lock, prove access rights, reserve a range, or authorize a subsequent write.
A competing client can acquire a lock immediately after the observation.
Errors, server grace, unavailable service and invalid replies are never reported
as an unlocked file. A conflict is a successful observation, not a CLI error.

The profile is AUTH_SYS over the selected TCP/UDP transport. Kerberos and TLS
profiles refuse this operation without opening an unprotected side channel.
The current identity is fixed during path resolution and inspection; the final
component must be a regular file, and its handle is checked again afterward.
This check detects observed namespace replacement; it does not isolate paths.

`--nlm-port PORT` selects a port on the actual connected NFS peer. The default
zero discovers that peer's matching NLM service through `--portmap-port`.
Neither discovery nor TEST re-resolves the original NFS hostname. Connections
are temporary; inspection does not add anything to `locks`. UDP retransmits
only the read-only TEST operation, with the same RPC packet and cookie.

Ranges use decimal offsets and positive lengths, or `eof` (the default range
is zero through EOF). NLM represents EOF with length zero on the wire; the
CLI still rejects an explicit zero length. NFSv2 ranges are limited to 32-bit
unsigned offsets/lengths; NFSv3 ranges must fit signed 64-bit file offsets.
Out-of-range input, cookie mismatches, truncated/oversized holder fields,
nonconflicting holders and trailing reply data are rejected. Remote opaque
owner bytes are not printed; SVID is a server-supplied process identifier.

Stock FreeBSD 14.4 native POSIX locks are checked on both client OSes, both
NFS versions and both transports, before and after the holder exits. See
[fixture and evidence](../tests/README.md#fixture-catalog).

TEST alone cannot provide the retained-lock contract. Protocol sources:
[FreeBSD NLM definitions](https://raw.githubusercontent.com/freebsd/freebsd-src/a456f852d14544460204036ea55f45a9c7e04972/include/rpcsvc/nlm_prot.x)
and [NSM definitions](https://raw.githubusercontent.com/freebsd/freebsd-src/a456f852d14544460204036ea55f45a9c7e04972/include/rpcsvc/sm_inter.x).

<a id="locks-ranges-and-ownership-nfsv2v3-retained-locks-explicit-monitored-profile"></a>
### NFSv2/v3 retained locks: explicit monitored profile

`lock`, `locks`, and `unlock` also support NFSv2/v3 AUTH_SYS with explicit
`--nlm-client-ip CLIENT_IPV4 --nlm-state-dir ABSOLUTE_DIRECTORY`, a selected
export and `--auto-uid=false --auto-escape=false`. Use a dedicated stable client
IPv4 address and persistent state directory. The address must belong exclusively
to this client profile, including across machines behind NAT; sharing it with a
system NLM client is unsupported. One process owns TCP and UDP port 111 on that
address. Existing listeners are never replaced. Linux requires permission to
bind the low port. An optional `--nlm-listen-ip` supplies a local bind address
for explicit forwarding; both protocols must preserve public port 111.

NFS data uses the selected TCP/UDP transport, while retained NLM control and
outbound NSM checks use retained TCP connections on the pinned server.
Probe connections are reused to avoid ephemeral-port exhaustion during transfers;
a lost connection invalidates the state without transparent reconnect. The server must expose NLM and
NSM through its portmapper. The embedded listener provides NSM NULL/STAT/
NOTIFY, read-only port lookup and explicitly enabled NLM GRANTED/GRANTED_MSG callbacks;
it is not a general system rpcbind/statd/lockd.
Inbound requests are admitted only from the pinned server IP. No security
downgrade is allowed from Kerberos, TLS, or NFSv4.

Each acquisition has a separate opaque owner and process identity, with at most
64 nonoverlapping ranges. NLM LOCK is nonblocking by default; `--wait` polls only
confirmed DENIED responses. `--wait-native` selects the callback profile below.
Ordinary mutations are never automatically retransmitted after an unknown result.
An uncertain acquisition retains an ID. Unlock uses the original credentials.
Whole-file reads/writes require a whole-file lock when that file is locked;
partial ranges refuse whole-file transfers, and read locks refuse writes.
`reput` requires a confirmed whole-file write lock and verifies the complete
remote prefix before appending. Explicit `getrange` and `putrange` also support
NFSv2/v3 under one confirmed covering lock. Explicit bounded legacy reclaim is
available under the [NLM reclaim contract](LOCKS.md#nlm-restart-reclaim).
See [upload resume](TRANSFERS.md#reconnect-and-transfer-recovery-verified-prefix-upload-resume).

<a id="locks-ranges-and-ownership-native-nlm-callback-waiting"></a>
#### Native NLM callback waiting

`lock --wait-native 10s PATH read|write [OFFSET LENGTH|eof]` sends one blocking
LOCK and waits for synchronous GRANTED (procedure 5) or asynchronous GRANTED_MSG
(10), replying in place or with GRANTED_RES (15), respectively.
It requires the explicit monitored legacy profile above and
a callback route that preserves the pinned server source IP. There is no
fallback to polling. NFSv4 CB_NOTIFY_LOCK, automatic
reclaim and failover are outside this profile. The duration is positive and at
most 24 hours; cancellation cleanup can extend the wait by bounded RPC timeouts.

The callback must match the original caller, file handle, opaque owner, process
ID, access and range. Its cookie is echoed independently of the initial LOCK
cookie: servers can generate a new one. GRANTED_RES is sent on a separate TCP
connection and does not expect an RPC reply. A successful write is not described
as an acknowledged server response; the matching GRANTED notification supplies
the grant. Duplicate callbacks while held are accepted without another LOCK.
The foreground API confirms NSM/control continuity and syncs the journal before
returning the retained ID. Foreground Client calls must remain serialized.

For synchronous GRANTED, the RPC reply echoes the callback cookie and contains
the NLM status. A matching positive grant becomes available to the foreground
only after the complete TCP/UDP reply has been written. The grant mutex stays
held through that write so cancellation cannot send cleanup while a positive
reply is in flight. Short/failed writes invalidate the monitor and quarantine
the acquisition. A successful transport write does not prove the server has
processed the reply; the foreground continuity checks remain mandatory.

After an acknowledged BLOCKED response, deadline/cancellation disables grant
acceptance and sends one CANCEL. Both CANCEL granted and denied require an
exact-owner UNLOCK, followed by confirmed state checks, before local state is
cleared. This resolves a grant racing cancellation. Unknown LOCK, grant-send,
CANCEL or UNLOCK outcomes quarantine the state and never replay the mutation.
An unconfirmed queued acquisition stays unrecoverable through `nlmrecover`
after a crash. The session also rechecks the pathname after acquisition and
releases the new lock if that check fails.

<a id="locks-ranges-and-ownership-legacy-range-transfers"></a>
#### Legacy range transfers

Use `getrange REMOTE LOCAL OFFSET LENGTH` for a nonempty bounded download and
`putrange LOCAL REMOTE OFFSET` for an in-place update using the entire nonempty
local file. Both require the fixed export/identity and NSM configuration above.
A read or write lock covers reads; only a write lock covers writes. Adjacent
locks are not combined to authorize a transfer. NFSv2 data ranges must end at
or below 2 GiB minus one byte; NFSv3 ranges fit a signed 64-bit file size.

Each READ, WRITE and COMMIT is checked against the requested range and the
original acquisition, with synchronous NSM/control probes before and after
the RPC. Unlocking/reacquiring inside a callback cannot resume that transfer.
Ordinary whole-file methods still refuse partial locks. Writes use stable
acknowledgements and exact COMMIT ranges; uncertain mutations never replay.
Downloads publish a new local file only after byte-count/source/lock checks.

Writes are in place and may extend the file when the covering lock allows it.
Cancellation, local source changes or errors can leave acknowledged or uncertain
bytes in the range; there is no rollback. Other writers must cooperate with
advisory locks. Whole-file metadata changes outside the locked range can make
download verification refuse publication. Coarse legacy timestamps are not a
snapshot or fencing mechanism.

The client synchronously checks the server NSM epoch and retained NLM connection
before and after guarded NFS RPCs, and once per second while idle with locks.
A changed epoch, failed control probe, malformed mutation reply, or uncertain
NFS transport result makes the state permanently uncertain and closes the data
connection. This is advisory coordination, not fencing: a server may already
have executed an in-flight write, and unrelated clients can ignore locks.

The append-only journal (at most 8 MiB) is exclusively locked, checksummed and
synced before LOCK and after confirmation. It records each handle, range, owner,
protocol and original credentials. Persistent monotonically increasing process
identities prevent a delayed cleanup from addressing a later acquisition.
New acquisitions reserve journal capacity for confirmation and eventual releases.
Clean sessions can reuse it. Unclean state refuses ordinary acquisition. Never
delete or reset the journal to bypass this refusal. Journal compaction and
power-loss durability certification remain outside this profile.

On a fresh connection using the same server, NFS version, client address and
state directory, `nlmrecover` explicitly releases durably confirmed pre-crash
locks. It uses their saved credentials, even if the connection's current UID
differs. Each acknowledged UNLOCK is saved before proceeding. A failed cleanup
retains unresolved entries; a later explicit attempt may repeat only these exact
UNLOCKs. No new LOCK, file write, or reclaim is sent by recovery. After success,
the user may explicitly acquire fresh locks and verify data before continuing.
Existing `reconnect --discard-locks` alone does not perform this cleanup.

Optional `--nlm-auto-recover` performs confirmed-owner cleanup before the first
new lock, with complete current-identity preflight and failure quarantine.
See [the automatic cleanup contract](LOCKS.md#confirmed-owner-cleanup).

```text
nlmrecover
lock reports/current.bin write
cat reports/current.bin
unlock 1
```

An unconfirmed LOCK may still execute remotely, so it remains quarantined even
under `nlmrecover`. Corrupt journals, changed peer identities, and dirty journals
from the older `nlm2` format also refuse recovery because exact confirmed owners
cannot be established. Clean old journals migrate automatically. There is no
force-reset option. Bounded [client-crash notification](LOCKS.md#client-crash-notification)
and [server-restart reclaim](LOCKS.md#nlm-restart-reclaim) are implemented as explicit separate
profiles. Unknown acquisition outcomes remain quarantined.

This deliberately avoids automatic SM_NOTIFY followed by immediate reacquisition:
FreeBSD acknowledges NOTIFY before asynchronous local lock cleanup, which could
otherwise remove newly acquired locks. See the pinned server's
[notification implementation](https://raw.githubusercontent.com/freebsd/freebsd-src/a456f852d14544460204036ea55f45a9c7e04972/usr.sbin/rpc.statd/procs.c).

Windows/Linux FreeBSD matrices verify acquisition, conflicting TEST, shared reads,
independent adjacent ranges, protected I/O, unlock and clean CLI restart. Actual
statd and lockd restarts verify uncertainty/refusal, and forced standalone client
termination verifies retained server locks, quarantine, exact-owner recovery and
subsequent fresh protected I/O. Both OSes also recover after actual statd/lockd
restarts. Local TCP/UDP wire tests exercise notification dispatch. Separate
Windows and FreeBSD clients receive actual server-originated UDP NOTIFY with
polling disabled. The FreeBSD run took about 71 seconds while statd retried an
earlier unreachable peer. Linux container inbound forwarding remains unverified.
See [archived reproduction recipes](DEVELOPMENT.md#historical-evidence).

<a id="locks-ranges-and-ownership-nfsv4-retained-locks"></a>
### NFSv4 retained locks

Confirmed locks can now be recovered after a timely server restart with
`reconnect --reclaim-locks`. It uses protocol reclaim and verifies the original
namespace; it never substitutes a new lock or replays interrupted file I/O.
See the [bounded reclaim contract](STATE_RECOVERY.md#server-restart-reclaim). Historical statements
below about absent reclaim are superseded only for that explicit scope.

`lock [--wait DURATION] PATH read|write [OFFSET LENGTH|eof]`, `locks`, and `unlock ID` support NFSv4.0, 4.1 and 4.2
over TCP, with AUTH_SYS or the configured Kerberos/TLS profile. Acquisition is
nonblocking by default: a conflict returns `NFS4ERR_DENIED`. Explicit `--wait`
enables bounded polling of clean conflicts, described below. NFSv2/v3 use the
separate explicitly configured NLM profile above.

```text
lock reports/current.bin read
locks
get reports/current.bin current.bin
unlock 1
```

Use the actual ID printed by `lock`. IDs are local to the connection. At most
64 locks may be retained. Multiple nonoverlapping ranges on one file have
independent IDs, OPENs and lock owners; all must use the same identity. Local
overlaps are refused even for read locks. Without range arguments, the lock
covers offset zero through future EOF. Native blocking callbacks, upgrades and
downgrades are not exposed. Only regular files can be locked through the shell.
Write locks open the file for both reading and writing, requiring both rights.

<a id="locks-ranges-and-ownership-byte-ranges"></a>
### Byte ranges

```text
lock archive.bin write 1048576 4096
locks
unlock 1
lock archive.bin read 8589934592 eof
unlock 2
```

Offsets are zero-based bytes. A finite positive length locks
`[OFFSET, OFFSET + LENGTH)`: adjacent ranges do not overlap. `eof` extends from
the offset through future file growth, including bytes not yet allocated.
Numbers are decimal unsigned 64-bit values. Zero lengths, negative values,
invalid numbers and finite-range addition overflow are rejected before network
I/O. The numeric length 18446744073709551615 is the protocol EOF sentinel and
is displayed as `eof`. Servers may impose smaller limits and return an error;
the client never clamps, splits or automatically retries a range request.

`locks` reports offset and length, including for uncertain state. `unlock ID`
releases the exact originally requested range. `Client.LockRange` and
`Session.LockRange` expose the same contract; the existing `Lock` methods retain
their whole-file default.

Current `cat`, `get`, `reget` and library `ReadTo`/`WriteFrom` transfer entire
files. They refuse a partial-range lock on that file before transferring any
data. This remains true even when the current file size fits within a finite
range: another writer could extend it afterward. Acquire a whole-file lock for
whole-file transfers. Failed downloads publish no final file.

For transfers confined to a retained range:

```text
auto-uid off
lock archive.bin write 1048576 4096
getrange archive.bin block.bin 1048576 4096
putrange modified-block.bin archive.bin 1048576
unlock 1
```

Use the printed lock ID. `getrange REMOTE LOCAL OFFSET LENGTH` reads exactly
the selected bytes and publishes to a new local filename after strict source
verification. Early EOF, cancellation, changed metadata, lost lock state and
local collisions prevent publication. Metadata verification covers the whole
source, so another writer changing a different range may also cause refusal.

`putrange LOCAL REMOTE OFFSET` writes the nonempty local file in place, requiring
one write lock covering every byte. It may extend the file but never truncates
it or writes outside that interval. Confirmed stable bytes are counted; failure
may leave partial or uncertain writes. There is no rollback or automatic retry.
Both commands require a fixed identity/export and one covering confirmed lock;
adjacent held ranges are not combined. The transfer end must fit signed 64-bit
file sizes. Ordinary whole-file I/O continues to refuse partial locks.

Recorded native range-I/O and protected lock-ownership results apply to
their individual fixture profiles. They do not establish every
range-I/O/TLS/reclaim combination.

<a id="locks-ranges-and-ownership-ownership-and-transfers"></a>
### Ownership and transfers

Each lock retains its own OPEN and lock owner. Reads and library `WriteFrom`
calls for the same handle under a whole-file lock use the lock stateid; finishing a transfer leaves the
lock held. Writing under a read lock or using a changed AUTH_SYS identity is
refused. `unlock` uses the saved acquisition identity. Shell `uid`, `use` and
ordinary `reconnect` refuse to discard outstanding locks.

Locks are advisory and protect an inode, not a pathname or a snapshot. Other
applications must cooperate; server enforcement for unrelated I/O can differ.
Another client can rename or replace a path. A later path resolution may then
select another inode. This client refuses its own replacement of a currently
locked destination, because staging plus rename would switch the inode.
`put`/`replace` do not become in-place locked writers. The library's existing
`WriteFrom` writes from offset zero without truncation and is not an atomic
replacement API.

<a id="locks-ranges-and-ownership-release-and-lost-state"></a>
### Release and lost state

`unlock ID` sends one LOCKU. It releases the retained OPEN and lock-owner state
after an acknowledged unlock. A subsequent cleanup failure is reported as such;
the acknowledged lock is already removed from the local list. Client exit tries
bounded best-effort release; it cannot promise server cleanup after a failure.

Transport failure, lease-renewal failure, invalid server state, or SEQUENCE
revocation/restart notifications mark retained locks uncertain. A malformed or
unconfirmed LOCK/LOCKU also remains visible as uncertain. Further protected I/O
and unlock replay are refused. `held` means acquisition was acknowledged, not
that future revocation is impossible. Detection occurs on a reply, transport
failure or lease check, not instantly when the remote server changes state.
An invalid COMPOUND reply closes the RPC connection so a possibly uncertain
session sequence cannot be reused by another command. A changed write verifier
also invalidates the connection instead of attempting CLOSE with pre-restart state.

```text
locks
reconnect --discard-locks
lock reports/current.bin read
```

Explicit discard closes the old client, attempts bounded cleanup where state is
still known, abandons local lock state and reconnects with the saved profile.
Server locks can remain until lease expiry. A failed reconnect leaves the old
connection closed; retry `reconnect` after addressing the error. Reconnection
never restores a lock or the protected interval. Re-read and revalidate data
after obtaining a new lock. Bounded [explicit restart reclaim](STATE_RECOVERY.md#server-restart-reclaim),
[protected resume with reclaim](STATE_RECOVERY.md#server-restart-reclaim-automatic-protected-download)
and [retained-lock process recovery](STATE_RECOVERY.md#retained-lock-process-recovery) are separate
implemented policies; arbitrary unknown state is not automatically recovered.

<a id="locks-ranges-and-ownership-bounded-conflict-waiting"></a>
### Bounded conflict waiting

`lock --wait 10s PATH read|write [OFFSET LENGTH|eof]` polls acknowledged
NFS4ERR_DENIED conflicts with a 100 ms to 1 s backoff. The duration must be
positive and at most 24 hours. Every retry requires successful temporary
OPEN/owner cleanup. Any transport error, malformed reply, other status or
cleanup failure stops the operation without replay. This is client polling,
not native blocking LOCK/CB_NOTIFY_LOCK or automatic state reclaim.

The resolved file handle is pinned across attempts and checked after acquisition.
A replaced pathname is refused; a newly acquired lock is released if the final
name check fails. If release cannot be confirmed, the retained lock ID is
reported for explicit inspection. The wait deadline covers attempts/backoff;
bounded protocol cleanup may add time before returning. Existing immediate
`lock` behavior is unchanged.

<a id="nlm-restart-reclaim"></a>
## NLM restart reclaim

Select `--nlm-reclaim` together with the existing explicit NFSv2/v3 AUTH_SYS
monitored NLM profile (`--nlm-client-ip`, `--nlm-state-dir`, fixed identity and
export). Then `reconnect --reclaim-locks` restores previously confirmed locks.
`reget --reclaim-locks` can use the same recovery once after a failed protected
download, retaining source metadata, namespace, lock and full-prefix checks.

This option asserts that the server rejects reclaim outside its recovery grace
period. It is not a capability discovered from a successful reply. Linux lockd
enforces this restriction; FreeBSD 14.4 accepts reclaim outside grace and must
not be selected for this continuity profile. See the primary implementations:
[Linux lockd](https://github.com/torvalds/linux/blob/v6.1/fs/lockd/svclock.c) and
[FreeBSD NLM](https://github.com/freebsd/freebsd-src/blob/releng/14.4/sys/nlm/nlm_prot_impl.c).
Coordinated lockd/statd restart and preserved server NSM state are required.

Recovery pins the original peer IP and requires exactly one NSM epoch advance
of two. Unchanged, regressed, skipped or exhausted epochs are refused. Every
original lock must have a confirmed acquisition and no uncertain mutation.
Current credentials must match all retained owners. The original journal,
client NSM epoch, process IDs, opaque owners, handles, lock IDs, modes and ranges
must match. Recovery opens fresh connections but never sends an ordinary
replacement LOCK and never replays interrupted writes.

There is one attempt per server incarnation. Before each reclaim LOCK, the
journal records an unconfirmed request and syncs it. A lost/malformed reply or
unexpected queued result keeps that owner quarantined across process restarts.
Confirmed denials retain historical owners for explicit exact-owner
`nlmrecover` cleanup. Partial success does not publish a usable client; the old
inventory stays uncertain. A successful Session reclaim revalidates original
export identity and pathname/handle bindings before replacing the session.

This is live-client recovery after a server restart. It does not recover a
crashed client, emit broad crash notifications, discover replacement servers,
provide HA failover or establish protection against noncooperating writers.
No post-crash replay of a saved LOCK is permitted. Standalone `nlmrecover`
continues to release exact recorded owners and never acquires locks.

Incoming callbacks through fixture NAT are not certified.

<a id="confirmed-owner-cleanup"></a>
## Confirmed-owner cleanup

`--nlm-auto-recover` enables cleanup of a previous crashed client's durably
confirmed NLM acquisitions before the first new legacy lock. The default still
quarantines dirty state. This is cleanup followed by the requested new lock;
it does not establish uninterrupted lock ownership or resume file operations.

Use explicit NFSv2/v3, AUTH_SYS, the original dedicated client IPv4 address,
the original absolute `--nlm-state-dir`, and the same UID/GID and ordered
supplementary groups as **every** saved acquisition. The CLI requires
`--auto-uid=false --auto-escape=false`. API users select `Config.NLMAutoRecover`.
The first lock initialization performs cleanup; connecting, listing, or reading
without a retained lock does not trigger it.

Before any mutation, journal validation checks the pinned peer, client address,
checksum, epoch, saved identities and confirmed acquisition outcomes. All saved
protocol versions and credentials must match. The callback listener and journal
must be exclusively owned. Mixed identities require explicit `nlmrecover`,
which retains its existing saved-credential behavior. Optional
`--nlm-auto-notify` adds [durable crash notification](LOCKS.md#client-crash-notification) after
confirmed cleanup, but retains quarantine because NSM cannot acknowledge completion
of delayed server cleanup. Use automatic confirmed-owner recovery alone when
fresh lock acquisition must continue.

Each cleanup sends UNLOCK for the exact saved handle, owner, process identity
and byte range. NSM checks bracket the operation; its cookie/status must match.
Each completed removal is synced before proceeding. Only after the entire
inventory is clean may the requested new lock obtain a fresh owner and a
persistently increasing process identity. No old LOCK, file I/O or SM_NOTIFY
is replayed, and no TEST result substitutes for ownership.

Cancellation, malformed replies, denied/grace results, connection loss or server
epoch changes stop cleanup and invalidate this connection. Another lock on that
connection cannot retry cleanup. Reopening with this option, or using explicit
`nlmrecover` on a fresh connection, can retry the remaining exact UNLOCKs.
Already durably removed owners are absent from subsequent recovery. A lost
UNLOCK reply leaves that owner recorded. Unknown LOCK outcomes and corrupt or
legacy dirty journals remain quarantined; never delete the journal to bypass
this refusal.

This option can coexist with `--nlm-reclaim`: explicit live-client reclaim uses
its original recovery path and does not invoke automatic cleanup. See
[server-restart reclaim](LOCKS.md#nlm-restart-reclaim).

<a id="client-crash-notification"></a>
## Client-crash notification

`--nlm-auto-notify --nlm-auto-recover` enables a bounded client-process crash
notification after exact confirmed-owner cleanup. It does not authorize a new
retained lock afterward: NSM provides no cleanup-completion barrier. The dedicated IPv4 client
address, pinned server, exclusive persistent journal, NFSv2/v3 AUTH_SYS and fixed
identity requirements of [automatic confirmed-owner cleanup](LOCKS.md#confirmed-owner-cleanup)
remain mandatory. CLI requires `--auto-uid=false --auto-escape=false`. NFS and
NSM transport source addresses must equal the dedicated client address; NAT or
a forwarding address that differs is refused. API uses `Config.NLMAutoNotify`.

On a dirty confirmed-owner journal, notification intent and the next odd NSM
epoch are synced before any cleanup UNLOCK. Exact saved owners/ranges are then
released and each removal synced. After all cleanup succeeds, the new epoch is
synced, published to the embedded local NSM listener, and sent as SM_NOTIFY
(program 100024, version 1, procedure 6) to the retained pinned NSM connection.
Its name is exactly the dedicated caller address originally used for NLM locks.
A strictly empty acknowledgement can be saved as receipt evidence, but the
pending notification epoch remains quarantined. The pre-send epoch is durable,
so a restart after that boundary never sends the notification again.
Clean startup without pending notification sends no simulated reboot.

SM_NOTIFY has a void result. Receipt cannot prove that a server recognized the
caller or released its locks. Exact acknowledged UNLOCK cleanup is therefore
required separately. Even after those UNLOCKs, delayed host-wide notification
handling could erase a subsequently acquired lock. Neither unchanged SM_STAT
nor TEST proves that this delayed work is finished. New acquisitions therefore
return `ErrNSMNotificationUnverified` and retain the journal. Notification does
not replace cleanup, and interrupted LOCK/payload requests are never replayed. The
protocol and this limitation follow the primary
[nfs-utils NSM definition](https://github.com/linux-nfs/nfs-utils/blob/master/support/nsm/sm_inter.x)
and [sm-notify contract](https://github.com/linux-nfs/nfs-utils/blob/master/utils/statd/sm-notify.man).

A notification attempt poisons the connection and preserves the pending epoch,
including an empty acknowledged response. A fresh startup may finish pre-send
owner cleanup, but never repeats a possibly delivered notification or admits a
fresh lock while its completion is unverified. Completed UNLOCKs are not
repeated. Historical journals that cleared an attempted notification as though
its receipt proved cleanup are refused. Ordinary clean journals with no such
notification history retain normal behavior. Other startup/reclaim/acquisition
paths cannot bypass a pending notification. Unknown LOCK outcomes, corrupt/legacy dirty
journals, differing identities/protocols, exhausted epochs, journal errors and
server restarts refuse recovery before a new acquisition.

This address must belong exclusively to this client's lock service and journal;
notification has host-level semantics. It does not provide general HA, lock
continuity, multiprocess/shared-host support, power-loss certification or
notification of an unknown acquisition. Safe automatic reacquisition after
SM_NOTIFY is not implemented for the generic protocol; no fixed sleep or journal
reset is a substitute for server-side completion evidence. Native notification
delivery remains unverified. Exact-owner `--nlm-auto-recover` without notification
remains the usable automatic cleanup path.
