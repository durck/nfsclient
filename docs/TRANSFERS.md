# Transfers, publication and resume

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [Reconnect and transfer recovery](#reconnect-and-transfer-recovery)
- [Local publication](#local-publication)

<a id="reconnect-and-transfer-recovery"></a>
## Reconnect and transfer recovery

<a id="reconnect-and-transfer-recovery-explicit-reconnect-and-verified-partial-downloads"></a>
### Explicit reconnect and verified partial downloads

For approved protected NFSv4 alternate endpoints, use
[`reget --failover`](STATE_RECOVERY.md#protected-mds-read-failover). This separate read-only policy keeps
credentials fixed, recreates state and checks source identity and all retained
bytes; it does not transfer locks or replay mutations. The ordinary bounded
`--retries` path now also refuses publication if progress callbacks change the
current/base credentials, working directory or session, including at EOF.

```text
reconnect
reget remote.iso local.iso
```

`reconnect` creates fresh transport, Kerberos and NFSv4 client/session state,
pins the negotiated NFS version/security/transport and authenticated identity,
remounts the selected export, checks its filesystem/file identity and resolves
the working directory by name. It commits the new session only if all steps
succeed. It never repeats a failed command or reuses old state IDs/file handles.
A discovered root must first be reset with `root reset`. Expired FILE tickets
still require external renewal. Export identity changes require a new explicit
session. Wait for a restarted server's grace period before reconnecting.

Outstanding NFSv4 locks block ordinary `reconnect`. Release them with `unlock`
or explicitly use `reconnect --discard-locks`, which closes the old connection
before attempting fresh state and does not restore any locks. See
[lock ownership, uncertain outcomes and recovery](LOCKS.md#locks-ranges-and-ownership).

`reget` refuses an existing final destination. Interrupted data is kept in
`LOCAL.nfs-part`; each attempt reads and compares every retained prefix byte
against the current remote stream, then publishes through the normal checked
no-replace download path. A mismatch preserves the old partial and returns an
error. This supports progress across process/connection restarts but rereads the
prefix over the network. It is not offset-only resume, upload resume or a remote
snapshot. Metadata checks retain the usual timestamp-resolution limitations.

`LOCAL.nfs-part.lock` excludes simultaneous resume attempts. After a crash,
remove a stale lock only after verifying that no transfer uses that destination.
Use a trusted local destination directory. Temporary and partial files are not
a substitute for coordinating with other writers.

<a id="reconnect-and-transfer-recovery-verified-prefix-upload-resume"></a>
### Verified-prefix upload resume

```text
lock partial.iso write
reput local.iso partial.iso
unlock 1
```

Use the actual printed lock ID. `reput` supports NFSv2/v3/v4.0/v4.1/v4.2 and an existing
regular remote file. It requires a fixed identity, selected export and confirmed
whole-file write lock. It reads and compares every remote prefix byte with the
open local source, checks local identity/size/mtime and remote identity/size/
change (v4) or mtime/ctime (v2/v3), then appends from the verified EOF. A final
size/identity/change-or-timestamp preflight is
made immediately before writing. No truncation, automatic replay, implicit lock
discard or offset-only trust is used. Stable WRITE/COMMIT verifier rules apply.
An already complete matching destination is verified without appending bytes.

On interruption, the visible remote partial remains. An uncertain last WRITE
may have reached the server. For NFSv4, explicitly reconnect with lock discard when needed,
wait for an old server lock to expire, obtain a new write lock and repeat `reput`;
the next attempt verifies the actual remote prefix. Local source changes or
prefix mismatches refuse continuation. Advisory locks do not exclude arbitrary
uncooperative writers, and this is not atomic publication or rollback.
NFSv2/v3 require the explicit AUTH_SYS [retained NLM profile](LOCKS.md#locks-ranges-and-ownership),
including a dedicated callback address and persistent journal. After uncertain
state, close the connection, use `nlmrecover` on a fresh matching profile to
release confirmed saved owners, then explicitly acquire a new lock and rerun
`reput`. Unknown acquisitions remain quarantined. Never delete a journal to
force continuation. Ordinary cancellation between confirmed chunks permits an
explicit unlock/reconnect/relock. No automatic upload retries or reclaim.

NFSv2 source size must be at most 2 GiB minus one byte, checked before writing.
NFSv2 uses synchronous WRITE acknowledgement; NFSv3 confirms FILE_SYNC or a
matching COMMIT verifier. Malformed acknowledgements, failed COMMIT and changed
verifiers invalidate retained NLM state and stop writes. Prefix validation is
not an atomic snapshot: uncooperative changes that preserve observable metadata
can evade timestamp checks.

Separate Microsoft AD runs `interop-20260924-15` (Linux client) and
`interop-20260924-win06` (Windows client) pass NFSv4.1/krb5p upload resume across
an actual knfsd restart: a 458,752-byte source has a 65,536-byte remote prefix;
the server restarts after the append reaches 98,304 bytes. The failed operation
stops, uncertain locks are explicitly discarded, and a new connection/write
lock precedes complete prefix verification and the remaining append. Both runs
also pass 30 NFS profiles, 18 lock profiles, 18 Linux Kerberos leaves and
automatic download recovery. Independent native verification checks retained
bytes/ownership/modes, exact artifacts, domain preservation and service cleanup;
Windows additionally verifies removal of its temporary credential copies.
This does not certify automatic mutation replay, lock reclaim, power loss,
commercial NAS or all filesystems.

<a id="reconnect-and-transfer-recovery-bounded-automatic-download-recovery"></a>
### Bounded automatic download recovery

```text
auto-uid off
auto-escape off
reget --retries 5 remote.iso local.iso
```

`--retries` must precede the remote path. It accepts 0..30 and defaults to 0,
preserving explicit recovery. Positive values permit that many fresh connection
attempts after transport loss, RPC timeout or selected NFS busy/grace/expired-state
responses. Backoff is 1, 2, 4, then 8 seconds, capped at 8 seconds. Failed
connections consume the same budget; transferred bytes do not reset it. Each
RPC retains `--timeout`; cancellation stops waiting and further attempts.

The local `.nfs-part.lock` remains held throughout the command, including
backoff and reconnection. After the first successful lookup, the command pins
the resolved source path, filesystem/file identity, size and available change
and timestamp attributes across attempts. Every saved prefix byte is reread
and compared. Reconnection preserves the selected identity, export, working
directory, NFS version, transport, security and TLS policy. Source/export changes,
prefix mismatch, local filesystem failures, permission/authentication/certificate
errors and malformed complete RPC/XDR replies stop recovery. This remains a
detectable-change guard, not a snapshot or offset-only download.

Automatic recovery requires a fixed identity, disabled automatic root discovery,
an ordinary selected export root and no outstanding NFSv4 locks. It never
discards/reclaims locks, resumes uploads, replays an uncertain mutation or renews
an expired FILE cache externally. A fresh read OPEN/session is created when
needed; old open/lock state is not reclaimed. Progress restarts from zero for
each verification pass, and recovery notices report the attempt budget.

Windows/Linux tests cut actual TCP connections to Ganesha v4.0/4.1/4.2 and
verify complete bytes after automatic recovery. In-process v3 tests cover cuts,
budget exhaustion (including failed connections), cancellation during backoff,
destination exclusion, changed source identity and permanent failures. Linux
Microsoft AD/krb5p run `interop-20260924-14` interrupts a v4.1 download after
32 KiB, actually restarts knfsd and automatically completes all 458,752 bytes
after grace. A separate held-lock session still requires explicit discard.
See [the retained AD evidence](../tests/README.md#native-fixtures).
Windows Server 2025 repeats this automatic in-flight restart scenario in
`interop-20260924-win05`, with 30 NFS/18 lock profiles, two credential-source
release flows and independently verified cleanup. Both AD clients complete the
458,752-byte file on their second pass after an interruption at 32 KiB.

<a id="reconnect-and-transfer-recovery-recursive-transfers"></a>
### Recursive transfers

```text
puttree local-directory new-remote-directory
gettree remote-directory new-local-directory
```

By default both commands require a new destination root. `--merge` reuses
existing directories and adds missing entries; existing files or links are
never replaced or silently skipped. Directory links and case-insensitive name
collisions are refused. A merge inventory is bounded to 100,000 existing entries.

Both commands preflight the source, preserve empty directories, reject special
files, unsafe portable names and case-insensitive source collisions, and cap
the walk at 100,000 entries and depth 128. `--links` copies symbolic-link text
without following it, including dangling, cyclic and external targets. It does
not make those targets available at the destination. Backslash/NUL-containing,
empty and oversized targets are refused. Windows link creation requires OS
support/privilege; failure remains explicit. Uploads require NFSv3/v4 guarded
creation. Downloads also support the existing NFSv2 per-file size limit.

`--hardlinks` preserves regular-file hardlink groups within the copied tree,
using filesystem/file identities rather than equal contents. One payload is
transferred per group; additional names use LINK. Source/name changes and
unsupported hardlink creation fail explicitly, without copying independent
files as a fallback. Relations to names outside the selected tree are not
preserved. Windows/Linux local filesystems must support hardlinks.

`--preserve-mtime` restores and verifies exact modification times for regular
files and directories; insufficient filesystem precision is an error.
`--preserve-mode` restores ordinary POSIX permission bits on Unix clients and
is refused on Windows, whose ACLs are not equivalent. Directory metadata is
applied bottom-up after child creation, including reused merge directories.
These metadata flags do not change symlink metadata or preserve owners, ACLs,
special permission bits, access time or ctime. Those are outside this profile.

Without metadata options, local files/directories use 0600/0700 and remote
objects request 0644/0755 under server policy. The tree is not snapshotted or
transactional. Failure reports a partial tree, which can include incomplete
files, copied links and metadata changes already applied. Existing unrelated
files are retained; there is no automatic rollback, overwrite or mutation replay.
Inspect partial entries before retrying: `--merge` deliberately refuses file
collisions. Concurrent namespace changes are not isolated by these checks.

UNFS3 SETATTR stores whole seconds; finer requested timestamps produce
a verification refusal. Local Windows symlink round trips require
the relevant privileges.

<a id="local-publication"></a>
## Local publication

`get` writes a sibling temporary file, then publishes it only after the transfer,
local sync/close and a final remote GETATTR succeed. Existing overwrite targets
remain intact on failure, and unpublished temporary downloads are removed.
The same checks apply to interactive and batch use, AUTH_SYS and Kerberos.

<a id="local-publication-what-is-checked"></a>
### What is checked

The initial resolved file supplies the size and available metadata. The client:

1. Requires a regular file with a known size representable by the local transfer
   API. NFSv4 also requires its `change` attribute; zero is a valid present value.
2. Caps bytes written to the temporary file at the initial size. A chunk that
   would exceed the bound is rejected before writing. Early EOF is an error.
3. Retains the original opaque file handle and authenticated identity. It does
   not re-resolve a potentially replaced path or switch identity after denial.
4. After local sync/close, obtains fresh attributes for that handle. Type/size,
   initial filesystem/file identifiers, modification and metadata times, and
   NFSv4 change value must agree wherever initially available. Disappearance of
   an initially available marker also fails verification.
5. Checks cancellation again before publishing. READ/CLOSE/GETATTR failures,
   including stale handles, withhold publication. No automatic transfer or
   mutation replay is introduced.

The limit concerns local temporary-file bytes. Existing bounded-chunk READ/EOF
semantics remain: a response can contain data beyond the initial size, which
is rejected before local writing. This is not an exact wire-byte limit. Empty
files still exercise READ access checks and final GETATTR. Progress reaching
100% reports received bytes; only the final command result means completion.

<a id="local-publication-what-is-not-guaranteed"></a>
### What is not guaranteed

Metadata checks detect observable changes; they are not a content hash, lock or
server snapshot. A modification can occur after the final check. Metadata-only
operations such as chmod can conservatively cause rejection through ctime or
change, even when file content is unchanged. A path may be renamed/replaced
while the originally selected handle continues identifying the old object.

- NFSv2/v3 timestamp resolution and server behavior can hide a same-size write.
  Restoring timestamps or a coarse/emulated ctime weakens detection further.
- **Observed UNFS3 0.11.0 limit:** the server sends whole-second mtime/ctime,
  with nanoseconds zero. Fast same-size writes within that second can pass the
  metadata guard. This failure was reproduced; it remains a recorded limitation.
- NFSv4 provides the required opaque `change` value. Compare equality only;
  do not assume it increases numerically. Recommended timestamps and file IDs
  may be absent, but a missing size/change prevents a verified `get`.
- No resumable state, ranged READ API, transfer restart, arbitrary upload
  consistency check, checksum manifest or Microsoft AD certification is added.

For a stable artifact from a changing source, use a quiescent file or a
server-provided snapshot and verify an independently trusted expected hash.
