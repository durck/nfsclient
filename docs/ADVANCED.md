# Advanced operations

[Quick start](../README.md) · [User guide](USAGE.md) · [Compatibility](COMPATIBILITY.md)

This guide covers workflows and their important limits. Exact command syntax
and available options live in the client: run `nfsclient help shell COMMAND`
without connecting, or `help COMMAND` in a session. Startup policies are
grouped under `nfsclient help`.

## Contents

- [Transfers and resume](#transfers-and-resume)
- [Recursive transfers](#recursive-transfers)
- [Permissions and replacement](#permissions-and-replacement)
- [Locks and byte ranges](#locks-and-byte-ranges)
- [Recovery and migration](#recovery-and-migration)
- [NFSv4.2 and offload](#nfsv42-and-offload)
- [pNFS FILE and Flex](#pnfs-file-and-flex)
- [pNFS block and iSCSI](#pnfs-block-and-iscsi)
- [pNFS objects](#pnfs-objects)
- [Durable journals](#durable-journals)

## Transfers and resume

`get` downloads through a sibling temporary file and publishes after local
sync/close and a final remote metadata check. Failed downloads leave an
existing destination intact. New destinations use no-replace publication.
These checks are not a snapshot against unrelated writers or a guarantee of
directory durability after power loss.

`put` publishes a staged upload. Existing legacy v2/v3 destinations refuse
ordinary overwrite; choose a new name or use the explicit replacement profile
below. Interactive collisions offer rename/cancel and overwrite where supported;
batch commands refuse collisions.

```text
reconnect
reget remote.iso local.iso
```

`reget` checks the entire retained local prefix against the remote file before
continuing. A mismatch refuses continuation. `reconnect` rebuilds transport
and session state while pinning version, identity and export identity; it does
not repeat the failed command. Reset a discovered root with `root reset` first.
Held locks block ordinary reconnect.

Automatic download recovery is opt-in:

```text
auto-uid off
auto-escape off
reget --retries 5 remote.iso local.iso
```

The identity, namespace, source metadata and retained prefix must remain
consistent. Authentication changes, stale identity or changed source data
stop recovery. Expired credentials may require external refresh.

Upload resume requires an existing regular remote file and a confirmed
whole-file write lock:

```text
lock partial.iso write
reput local.iso partial.iso
locks
```

After success, `unlock ID` using the actual printed ID. `reput` verifies the
complete remote prefix before appending; it neither truncates nor rolls back
a visible partial. A failed last WRITE may have reached the server. Reconnect
and obtain fresh confirmed ownership before an explicit retry; never assume
an interrupted upload can be blindly replayed. Legacy v2/v3 needs the monitored
NLM profile. NFSv2 sources must be smaller than 2 GiB.

## Recursive transfers

```text
puttree local-directory new-remote-directory
gettree remote-directory new-local-directory
```

Tree transfer supports explicit merge, links, hard links, mode and mtime
policies. See `help gettree` and `help puttree` for opt-in switches and budgets.
This is not whole-tree atomic publication or universal owner/ACL cloning.
Errors can leave already published entries. Windows symbolic links may
require additional OS privileges. Unsupported metadata is not silently
equivalent to preserved metadata.

## Permissions and replacement

| Commands | Behavior |
| --- | --- |
| `chmod`, `chown OWNER[:GROUP] PATH`, `chgrp GROUP PATH` | Explicit metadata changes; ownership uses same-handle readback |
| `acl PATH` | Inspect native NFSv4 ACL or legacy NFSACL access/default ACLs |
| `getacl PATH LOCAL [acl\|dacl\|sacl]` | Export policy to a new local file |
| `setacl PATH LOCAL` | Apply exported JSON and require exact readback |
| `label`, `setlabel` | Inspect/change advertised NFSv4.2 security labels |
| `xattrs`, `getxattr`, `setxattr`, `removexattr` | Explicit extended-attribute operations |
| `namedattrs`, `getnamedattr` | Inspect/export NFSv4 OPENATTR streams |

NFSv2/v3 ownership uses numeric IDs; v4 uses exact server-recognized owner/group
strings. No Windows name translation or principal-to-owner inference occurs.
Ownership changes reject final symlinks and preserve the selected identity.
A partial change or lost reply is reported as uncertain and is not replayed.

NFSv4 ACLs retain ACE ordering, flags and principal strings. DACL/SACL require
v4.1/4.2. Legacy ACLs require the NFSACL extension on the same server; regular
mode bits alone are not the complete policy. Legacy `getacl` uses `acl`, not
the DACL/SACL selectors. Server authorization still controls every operation.

OPENATTR streams are separate from RFC 8276 xattrs. Inspection uses
OPENATTR(create=false), fixed identity and bounded values (64 names, 64 KiB
per exported stream); exports refuse existing local destinations.

`replace LOCAL REMOTE` replaces an existing regular file under explicit
policy preservation rules. Keep identity/root fixed and release held locks.

- NFSv4 preserves observable supported ACL/DACL/SACL, owner/group, mode,
  security label and supported extended/named attributes, then checks readback.
  Unsupported or incomplete policy prevents publication.
- NFSv3 AUTH_SYS requires same-endpoint NFSACL GETACL/SETACL, supported ordinary
  metadata and an eligible single-link destination.
- NFSv2 AUTH_SYS additionally requires NFSACLv2, a file smaller than 2 GiB,
  disabled auto-UID/root discovery and no unsupported special mode bits.

Replacement publishes a new inode; it is not a transaction against concurrent
writers, unrestricted metadata cloning or hard-link-preserving overwrite.
An uncertain publication must be inspected before retrying.

## Locks and byte ranges

Locks are advisory: unrelated clients can ignore them. Use a fixed identity
and selected export. Inspect conflicts with `locktest PATH read|write
[OFFSET LENGTH|eof]`; absence of a reported conflict is not ownership.

```text
auto-uid off
auto-escape off
lock archive.bin write 1048576 4096
getrange archive.bin block.bin 1048576 4096
putrange modified-block.bin archive.bin 1048576
locks
```

Use `unlock ID` with the returned ID. A single confirmed covering lock must
authorize a range; several smaller locks cannot be combined. Ordinary
whole-file operations need the appropriate whole-file lock when locks are held.
Ranges are finite or explicitly extend to EOF. NFSv2 uses its smaller range limit.

NFSv4 retains OPEN/LOCK state and leases. Legacy NFSv2/v3 retained locks require
AUTH_SYS, explicit protocol/export, fixed identity, a dedicated `--nlm-client-ip`
and persistent absolute `--nlm-state-dir`. Callback/source identity must match;
NAT or an unrelated callback address is not equivalent.

`lock --wait D` selects bounded conflict waiting; consult `help lock` for
range/option ordering and native legacy callback requirements. Cancellation
or transport loss can leave unknown ownership; a timeout is not proof that
the server never granted a lock.

Legacy recovery choices are distinct:

| Policy | Meaning |
| --- | --- |
| `--nlm-reclaim` with `reconnect --reclaim-locks` | Reclaim confirmed owners during server-enforced grace |
| `nlmrecover` / `--nlm-auto-recover` | Clean up previously confirmed crashed owners before a new acquisition |
| `--nlm-auto-notify --nlm-auto-recover` | Attempt crash notification after confirmed-owner cleanup |

Unknown acquisitions stay quarantined. Cleanup does not establish uninterrupted
ownership. NSM notification has no cleanup-completion barrier, so notification
does not authorize new retained locks. Do not delete state files to bypass refusal.

## Recovery and migration

| Command or option | Scope |
| --- | --- |
| `reconnect --discard-locks` | Abandon old lock state before creating a fresh connection |
| `reconnect --reclaim-locks` | Explicit server-restart recovery of confirmed original owners |
| `reget --reclaim-locks` | Protected download with a bounded reclaim attempt |
| `reget --referral SERVER=HOST:PORT,SPN,TLS_NAME` | Follow an explicitly approved MOVED/fs_locations path |
| `reget --failover HOST:PORT,SPN,TLS_NAME` | Fresh protected download session on an approved alternate |
| `migrate SERVER=HOST:PORT,SPN,TLS_NAME` | Transfer confirmed OPEN/LOCK state to an approved v4.1/4.2 endpoint |
| `migrate --arm-failover SERVER=HOST:PORT,SPN,TLS_NAME` | Arm one protected original-session transport transition |
| `migrate --status` | Inspect the armed/consumed transition |
| `lock-save ABSOLUTE_JOURNAL` / startup `--recover-locks FILE` | Persist and recover the original retained-lock lifecycle |

Referral and read-failover mappings include explicit endpoint and security
identities; retain empty comma-separated fields where applicable. They do not
authorize arbitrary servers discovered from network responses. Read failover
revalidates source metadata and retained bytes; it does not transfer locks.

Migration needs a fixed selected export, confirmed locks, protected TCP,
explicit v4.1/4.2 and verified session/server evidence. A new unrelated session
cannot establish continuity. Reclaim needs server recovery grace and original
owner evidence. Lease loss, mismatched scope or absent cached replies refuse
recovery instead of replaying uncertain writes.

On process recovery, preserve the exact journal and startup identity/security
settings; omit `--export` because the journal selects its saved namespace.
See `nfsclient lock-state --help` before inspecting recovery state.

## NFSv4.2 and offload

Select explicit NFSv4.2; optional operations also require server support.
The ordinary connection still uses standard READ/WRITE.

| Commands | Purpose |
| --- | --- |
| `getplus`, `seek` | READ_PLUS and data/hole inspection |
| `allocate`, `deallocate`, `advise` | Space allocation and access advice |
| `copyrange`, `clonerange` | Server-side copy/clone |
| `copyasync` | Bounded asynchronous copy |
| `copyfrom` | Explicit inter-server copy |
| `writesame`, `writeadb` | Repeated data/application data blocks |
| `offload-reconcile` | Verify an eligible recorded completion after a crash |

Use `--offload` where required and satisfy the command's confirmed-lock,
destination and range requirements. Server refusal does not silently switch to
client-side copying. Inter-server copy requires explicit source/destination
approval; protected copy uses krb5p with RPCSEC_GSS v3, a selected source SPN
and copy-user identity. Unsupported child privileges do not downgrade to GSSv1.

`--offload-journal ABSOLUTE_FILE` records operations before issue and
quarantines unknown results. Additional `--offload-session-recovery` preserves
original session/slot/request evidence for later `--recover-offload FILE
--offload-operation ID`. It requires fixed credentials and protected TCP.
No fresh session can substitute for missing original cached replies.

`offload-reconcile FILE ID DESTINATION` is verification, not mutation replay.
Only eligible bounded synchronous whole-file COPY/CLONE receipts can use this
path. Unresolved asynchronous grants and missing evidence remain quarantined.

## pNFS FILE and Flex

Use `--pnfs`, explicit NFSv4.1/4.2 TCP and a fixed namespace/identity.
Data-server destinations require explicit mappings; advertised addresses alone
are not approval to connect.

```text
getpnfs report.bin local.bin 192.0.2.11:2049=192.0.2.11:2049
```

`--layout flex` selects Flex Files; the default is FILE. `--parallel 1..8`
bounds eligible parallel work. Kerberos requires an explicit
`--ds-spn TARGET=nfs/HOST` for each approved data-server identity.

`putrangepnfs LOCAL REMOTE OFFSET ...` writes to an existing regular file
under a confirmed whole-file write lock. `--extend` explicitly permits growth.
`putpnfs LOCAL REMOTE ...` creates a new file under its own guarded creation
and lock flow. Layout recall, source change, changed write verifiers or loss of
confirmed ownership stop publication; partial data may already exist.

Protected recovery options have separate contracts:

| Option | Supported use |
| --- | --- |
| `--read-failover` | One approved same-identity path recovery during FILE/tight Flex reads |
| `--mirror-failover` | One approved Flex mirror change per segment during reads |
| `--write-failover` | Original-session write recovery on approved FILE/tight Flex paths |
| `--refresh-devices` | Protected FILE/tight Flex mapping refresh with preapproved targets |
| `--session-trunking` | Shared original sessions across approved FILE read paths |

These require krb5i/krb5p and explicit identities. Read and mirror failover
cannot be combined or used for writes. Trunking cannot combine with these
failover/refresh modes and rejects Flex/writes. Refresh can accompany write
failover but not read/mirror failover or trunking. Recovery never expands the
approved destination set or changes user/SPN. Lost exact-request evidence
refuses uncertain write replay. Loose Flex devices are not supported by the
protected DS identity/callback profile.

## pNFS block and iSCSI

Select `--layout block` and approved `--block-volume IMAGE` paths or
`--block-target iscsi://IP:PORT/IQN/LUN` with `--block-initiator IQN`.
Local volumes must be regular images with exclusive consistent access, not raw
devices. The MDS topology and signatures must match the selected storage.

```text
getpnfs report.bin local.bin --layout block --block-volume volume.img
lock report.bin write
putrangepnfs patch.bin report.bin 101 --layout block --block-write --block-volume volume.img
```

Writes require `--block-write`, a confirmed whole-file write lock and complete
block initialization/COW. `putpnfs` supports guarded new files; `--extend`
permits growth with gap initialization. Storage durability and MDS commit must
complete before success. Native fencing/vendor interoperability is not implied.

iSCSI supports approved direct-access LUs with 512/4096-byte sectors,
CHAP/mutual CHAP and CRC32C digests through explicit target policies.
CHAP and CRC32C do not encrypt storage traffic, and MDS TLS/Kerberos does not
protect that separate connection. There is no storage TLS, general multipath,
write replay or automatic session reinstatement. Approved block-read
reconnection is a distinct opt-in policy. Consult `help getpnfs` for target
policy and reconnection flags before using remote storage.

`--block-journal FILE` records a block write; repeat the same operation with
`--block-resume` only after reacquiring required locks and confirming the same
source/storage/namespace. Recovery can continue verified suffix work, but
uncertain storage remains quarantined. Journals do not make storage fencing or
power-loss recovery universal.

## pNFS objects

`getpnfs ... --layout object --osd-target iscsi://IP:PORT/IQN/LUN
--osd-initiator IQN` selects OSD-1 dense RAID0 reads. Connect with `--pnfs`
and explicit NFSv4.1/4.2 TCP. Targets are approved literal endpoints; the MDS
cannot introduce another storage destination.

`--osd-secure` requires ALLDATA capabilities and refuses NOSEC fallback.
The MDS connection must protect capability keys with krb5p or verified TLS;
krb5i alone is insufficient.

`putrangepnfs ... --layout object --object-write` supports finite writes
inside an existing regular file, with a whole-file write lock and secured
capabilities. WRITE/FLUSH and MDS commit must succeed. There is no object
creation/growth, OSD-2, parity/groups/mirrors or process-crash journal.
Native OSD interoperability remains unverified.

## Durable journals

Journals are private runtime state and may contain sensitive recovery material.
Keep the original absolute path, exclusive ownership and matching client
configuration. Do not edit or delete a journal to force progress.

Use the offline command's help before acting:

```sh
nfsclient lock-state --help
nfsclient offload-state --help
nfsclient block-state --help
```

Inspection does not resolve uncertainty. An acknowledgement is an operator
assertion that the required server/storage quiescence and destination checks
were independently completed; it is not rollback or proof of successful I/O.
If an operation cannot reconstruct its exact state, leave it quarantined.
