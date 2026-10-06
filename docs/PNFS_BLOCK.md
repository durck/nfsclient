# pNFS block storage and crash recovery

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [Volume images and topology](#volume-images-and-topology)
- [Range writes and COW](#range-writes-and-cow)
- [New files and growth](#new-files-and-growth)
- [iSCSI storage](#iscsi-storage)
- [Process-crash recovery](#process-crash-recovery)

<a id="volume-images-and-topology"></a>
## Volume images and topology

[Explicit iSCSI/TCP storage](PNFS_BLOCK.md#iscsi-storage) supports this
flow directly on approved remote logical units. The image-specific filesystem
checks below remain applicable to local images; see the storage contract for
remote identity, sector, durability and failure boundaries.

`getpnfs REMOTE LOCAL --layout block --block-volume LOCAL_IMAGE [...]` selects
RFC 5663 block/volume layout type 3. Connect with `--pnfs`, explicit NFSv4.1/4.2,
and TCP. This software profile uses regular-file images of the shared volumes;
no physical RDMA adapter, OS NFS mount, driver, CGO or new runtime dependency is
required. Repeat `--block-volume` to approve up to 64 images.

```text
getpnfs report.bin report.bin --layout block --block-volume volume-a.img --block-volume volume-b.img
```

Shell paths resolve against the local directory. API callers supply absolute
`PNFSOptions.BlockVolumes` paths. Images must be nonempty, sector-aligned regular
files. Symlinks, devices, directories, duplicate paths and hardlink aliases are
refused. Downloads open images read-only and never write or resize them. No path or
network endpoint advertised by the metadata server is automatically opened.

<a id="volume-images-and-topology-identification-and-mapping"></a>
### Identification and mapping

After read OPEN and the accepted I/O-time hint, complete layout coverage is
acquired and GETDEVICEINFO resolves each data device. Every SIMPLE volume must
match exactly one approved image using **all** advertised signature components.
Embedded NUL bytes and negative offsets relative to capacity are supported.
Missing, ambiguous or out-of-range signatures stop the transfer.

Nested SLICE, CONCAT and STRIPE topologies map logical offsets onto identified
SIMPLE images. References must point to earlier entries; the final entry is the
root. Slice/total capacity, equal stripe-component sizes and stripe alignment
are verified. Each physical read stops at its stripe/slice/concat boundary.

Supported grants have finite READ-only segments containing contiguous READ_DATA
or NONE_DATA extents with 512-byte-aligned offsets/lengths. NONE_DATA generates
zeroes without storage access. The user's final read may end inside a sector.
Every data extent, including its portion beyond EOF, must fit its logical
volume before any transfer bytes reach the output writer. Incremental grants
and multiple segments reuse bounded acquisition and stateid checks.

Limits: 64 granted segments, 1024 extents per body, 64 distinct device topologies,
64 volumes per topology, 16 signature components per SIMPLE volume, 4096 bytes
per component and 32 KiB per layout/device body. Capacity/arithmetic are bounded
to int64. Device refresh, multiple workers, DS/SPN/TLS-name mappings, failover,
mirror/trunking options and write extension are refused for this profile.

<a id="volume-images-and-topology-lease-fencing-and-publication"></a>
### Lease, fencing and publication

Synchronous filesystem ReadAt/Stat cannot enforce a completion deadline. The
client advertises the RFC's unbounded maximum I/O time (all ones) in SETATTR
`layout_hint` before LAYOUTGET. It requires acknowledgement of exactly that
attribute; denied or omitted hints prevent layout/device/data access. The
metadata server must accept this profile and provide appropriate storage fencing.
The client never advertises a false finite deadline.

Cancellation, known lease expiration, metadata state loss and recall stop new
reads. Checks before/after each physical fragment prevent delivery after observed
invalidation. Cancellation cannot interrupt an already blocked filesystem call,
including signature probes. Foreground APIs remain serial.

Image identity, capacity and modification time are checked throughout. These
detect observed changes; they do not provide a snapshot or defeat a writer that
restores metadata. The operator must provide consistent images matching the
server's volume view. A signature identifies a volume, not the freshness of all
its bytes. MDS Kerberos/TLS continues normally; it does not protect local image
data or substitute for local file access controls.

The Client API pins its identity and supplementary groups. Session/CLI also pin
the client, current/base credentials, export, roots and CWD through EOF/cleanup;
Session block downloads require fixed identity/root policy and no retained
locks. Source verification occurs while OPEN/layout state is held. Type-3
LAYOUTRETURN has an empty body; return, CLOSE and subsequent source verification
must succeed before atomic local publication. Failures never publish a download
or replace an existing local file. No MDS READ/WRITE fallback or mutation replay
occurs.

<a id="range-writes-and-cow"></a>
## Range writes and COW

`putrangepnfs LOCAL REMOTE OFFSET --layout block --block-write --block-volume IMAGE [...]`
writes a finite range of an existing regular file through explicitly approved
regular-file volume images. Connect with `--pnfs`, explicit NFSv4.1/4.2 and TCP.
The caller must already hold a confirmed whole-file write lock. [New-file uploads and explicit growth](PNFS_BLOCK.md#new-files-and-growth) extend this
profile. Omit `Extend` to retain the default no-growth range behavior.

```text
lock report.bin write
putrangepnfs patch.bin report.bin 101 --layout block --block-write --block-volume volume.img
unlock 1
```

The example assumes the acquired lock ID is 1. API callers select `Layout:
"block"`, absolute `BlockVolumes` paths and `BlockWrite: true` in `PNFSOptions`.
`WritePNFSRangeFromProgress` reports only durably committed input bytes. Any
error may leave additional changes; this is an in-place operation without
rollback or replay. Use the [upload/growth contract](PNFS_BLOCK.md#new-files-and-growth) for new files or `--extend`.

<a id="range-writes-and-cow-preflight"></a>
### Preflight

The [block image identification and topology contract](PNFS_BLOCK.md) applies.
Write approval opens the supplied images read/write, without creation or
resizing. Require exclusive, consistent access to those images for the entire
operation; this backend does not implement storage fencing or snapshotting.
The original lock stateid, client identity and supplementary groups are pinned.
Session/CLI additionally pin namespace, base credentials and local source
identity/size/modification time. Source checks surround each input read. A
source file that aliases a volume image is refused; opaque Client API readers
must supply stable bytes and must not read from the images being modified.

Before storage changes, the client obtains the destination size and advertised
`layout_blksize` (attribute 65), requires acceptance of the truthful unbounded
I/O-time hint and acquires complete writable coverage through the end of the
last server block. Supported block sizes are positive multiples of 512 through
1 MiB. No fallback block size is guessed. A range must fit the current EOF unless explicit `Extend` is selected.

Writable extents are contiguous READ_WRITE_DATA or INVALID_DATA. Optional
READ_DATA extents supply old COW contents and must be fully covered by INVALID
extents. Lists require RFC offset/state ordering and reject other overlaps,
NONE_DATA, gaps, overflow and malformed replies. Writable offsets, lengths,
storage offsets and effective grant boundaries require server-block alignment.
An expanded newer grant supersedes the old mapping, including its COW source.

Every device topology is identified and every extent checked against capacity.
The complete effective grant is translated into at most 16384 physical windows.
Overlapping writable physical ranges, overlap with COW source ranges and writes
into any advertised signature are rejected before the first write. These checks
include untouched grant regions and aliases through nested slice/concat/stripe
topologies. The profile conservatively rejects such aliases rather than
assuming that an overwrite is harmless. Existing block layout/device limits
also apply. No DS mappings, parallel workers, refresh or recovery options are
accepted.

<a id="range-writes-and-cow-initialization-and-durability"></a>
### Initialization and durability

Work proceeds in ascending whole server blocks with bounded memory. For
READ_WRITE_DATA, the existing block contents up to EOF are preserved. For
INVALID_DATA, the buffer starts at zero; overlapping READ_DATA supplies old
COW bytes. Uninitialized destination storage is never read. Input bytes replace
their requested part, and bytes from EOF to the end of an initialized block are
zeroed. Old COW blocks and unrelated image bytes remain unchanged.

Physical fragments are written only while the original lease, grant and lock
remain usable. Each touched image is synchronized before LAYOUTCOMMIT. INVALID
blocks use an RFC 5663 commit list containing the now-initialized whole block
with READ_WRITE_DATA state; already valid blocks use an empty extent list.
Progress advances only after a successful metadata acknowledgement. Local file
writes can be fragmented and are not atomic; a failure before synchronization
or commit can leave a partially modified block. A file Sync acknowledgement is
the durability boundary exposed by this software backend, not a hardware
certification.

Recall stops new blocks. A known completed storage block may be synchronized
and committed while recall is pending, provided the lease and lock remain
valid. Uncertain WriteAt/Sync/LAYOUTCOMMIT outcomes quarantine and close the
original metadata session without returning the layout or replaying writes.
A credential change also closes that session, preventing cleanup under another
identity. A confirmed prefix remains reported even when later cleanup fails.
Cancellation cannot interrupt a blocked filesystem operation; no finite I/O
deadline is advertised. An optional persistent block crash-recovery journal
and bounded fresh-client resume are described in the
[recovery extension](PNFS_BLOCK.md#process-crash-recovery).

<a id="new-files-and-growth"></a>
## New files and growth

The [block range-write contract](PNFS_BLOCK.md#range-writes-and-cow) now also supports
new-file uploads and explicit growth through approved regular-file volume
images. Signature checks, complete topology/alias preflight, whole-block
initialization, image Sync and type-3 LAYOUTCOMMIT still apply. This software
backend requires consistent, exclusive image access and server acceptance of
the truthful unbounded I/O-time hint; native storage/fencing is unverified.

```text
putpnfs source.bin new.bin --layout block --block-write --block-volume volume.img
lock existing.bin write
putrangepnfs patch.bin existing.bin 2701 --layout block --block-write --extend --block-volume volume.img
unlock 1
```

Use the actual returned lock ID for unlock. Range growth requires `--extend`
(`PNFSOptions.Extend`); omission refuses a range beyond the original EOF before
LAYOUTGET. New-file `putpnfs` permits growth automatically. Both require explicit
`--block-write` (`BlockWrite: true`) and approved absolute image paths for API
callers. Reads still reject write-only options. No remote path or device image
is automatically selected, created or resized.

<a id="new-files-and-growth-new-files"></a>
### New files

Session validates the complete write profile and image file access before
CREATE. It checks a regular source, refuses source/image aliases, pins source
identity/size/modification time and retains session namespace/credentials.
Checks after the initial progress callback precede guarded CREATE, so changing
credentials, CWD, source or lock inventory cannot silently redirect creation.
An existing destination is never replaced. A lost or malformed CREATE result
is not replayed, and a file may remain on the server.

A nonempty upload obtains a temporary whole-file write lock on the new handle,
then writes through its type-3 layout. The original client is retained for lock
cleanup. Confirmed cleanup removes the temporary lock; unknown acquisition or
mutation leaves explicit local lock tracking for recovery, without replay.
Source/profile checks precede each physical operation, including zero-only gap
blocks, and the final source/handle/size check must pass before reporting success.
A zero-length source creates an empty file without acquiring a data layout or
writing storage. Validation and source/profile guards still apply.

Failure may leave an empty or partially written new destination. There is no
automatic delete, replacement, rollback or mutation retry.

<a id="new-files-and-growth-growth-and-gap-initialization"></a>
### Growth and gap initialization

The writer preserves existing bytes up to the original EOF, using the valid
extent or readable COW source. If the input offset lies beyond that EOF, work
starts at the server block containing the old EOF. Every gap byte is initialized
to zero; INVALID storage is never read. Bytes beyond the final input EOF are
zeroed through the end of the last initialized server block.

Each completed block is synchronized and committed before progressing. The
LAYOUTCOMMIT last-write offset covers initialized gap bytes as well as input
bytes, so file size can increase incrementally. An optional returned size must
match the expected acknowledged size. Gap zeroing contributes no input progress.
Consequently an error can leave confirmed file growth with an input byte count
of zero. This is an explicit in-place growth operation, not a transaction.
Cancellation/recall/source invalidation stop new physical fragments. An
uncertain commit closes/quarantines the original session and is never replayed.

<a id="iscsi-storage"></a>
## iSCSI storage

The block backend now reads and writes approved remote logical units directly
through a Go iSCSI initiator. It uses no OS mounts, device drivers, CGO or local
shadow images. Local images and remote targets may be combined, up to 64
approvals per operation. Existing block layout, COW, growth, source/session,
lease/recall and publication rules still apply.

<a id="iscsi-storage-explicit-approvals"></a>
### Explicit approvals

Connect to the MDS with `--pnfs`, NFSv4.1/4.2 and TCP. Supply repeatable
`--block-target iscsi://IP:PORT/IQN/LUN` and one `--block-initiator IQN`.
IP addresses and nonzero ports are explicit; DNS, discovery and redirected
target addresses cannot add destinations. LUN is canonical decimal 0..255
(peripheral-device addressing). IQNs use normalized lowercase ASCII names.
API callers use `PNFSOptions.BlockTargets` and `BlockInitiator`.

```text
getpnfs report.bin report.bin --layout block --block-target iscsi://127.0.0.1:3260/iqn.2026-10.org.example:volume/0 --block-initiator iqn.2026-10.org.example:viewer
lock report.bin write
putrangepnfs patch.bin report.bin 101 --layout block --block-write --block-target iscsi://127.0.0.1:3260/iqn.2026-10.org.example:volume/0 --block-initiator iqn.2026-10.org.example:viewer
unlock 1
putpnfs source.bin new.bin --layout block --block-write --block-target iscsi://127.0.0.1:3260/iqn.2026-10.org.example:volume/0 --block-initiator iqn.2026-10.org.example:viewer
```

Range growth additionally requires `--extend`. New-file uploads use guarded
CREATE and a temporary whole-file write lock. Upload validation probes approved
storage before CREATE; the transfer then opens its own storage session and
matches all MDS signatures before changing data. An empty upload probes storage
but issues no data WRITE or layout acquisition.

<a id="iscsi-storage-supported-protocol-profile"></a>
### Supported protocol profile

- One normal session/connection with bounded security and operational login
  negotiation, no continuation text or connection reinstatement.
- Default `AuthMethod=None`, `HeaderDigest=None`, `DataDigest=None`; explicit
  per-target policies can require CHAP/mutual CHAP and CRC32C header/data digests.
  Required selections cannot downgrade. CHAP authenticates and CRC32C detects
  transmission errors; neither encrypts traffic or provides cryptographic data
  integrity. Storage TLS is not implemented. MDS Kerberos/mutual TLS are separate
  and do not protect storage traffic.
- Sequential SIMPLE tasks, InitialR2T=Yes, ImmediateData=No,
  MaxOutstandingR2T=1, ordered PDUs/sequences, ErrorRecoveryLevel=0,
  MaxBurstLength=65536. A target receive limit of 512..16777215 is accepted;
  outgoing segments are capped at 65536. Unsupported login offers are refused.
- Direct-access LUs, 512-byte or 4096-byte logical sectors and positive int64
  capacity, with overflow checked before multiplication.
  INQUIRY VPD page 83 must fit the 252-byte allocation and expose one unambiguous
  binary logical-unit NAA (8 or 16 bytes). Approving two portals with the same
  NAA is refused before data modification.
- READ CAPACITY(16), READ(16), WRITE(16), SYNCHRONIZE CACHE(16). Reads may use
  bounded sector bounce buffers; writes contain complete sectors and never
  read INVALID destination storage for read-modify-write. The full server block
  is constructed by the block COW/growth layer. The NFS WriteSize hint is rounded
  down to native logical sectors, with a minimum of one sector for this backend.
  Writable physical windows and the advertised server block must contain whole
  native sectors; incompatible 512-byte layouts on 4Kn storage refuse before WRITE.
  Recovery fingerprints bind the selected NAA, byte capacity and logical sector
  size. Fresh verification storage and resumed writes reject changed geometry
  or device identity even when the endpoint is unchanged.
- Commands transfer at most 64 KiB. PDU headers, task/status/command/data
  sequence numbers, offsets, R2T ranges and transfer residuals are checked.
  Short transfers are permitted only for the VPD inquiry with an exact residual.
  Data-In can carry status or precede a separate SCSI response. Several ordered
  read sequences are supported: F ends a sequence, while S or a valid separate
  response completes the command. Bidirectional commands share incoming
  R2TSN/DataSN numbering; outgoing DataSN restarts for each solicited burst.
  ExpDataSN, offsets and exact transfer accounting remain checked. Up to 1024
  Data-In PDUs and eight target pings are accepted per command.

The implementation follows [RFC 7143](https://www.rfc-editor.org/rfc/rfc7143.html)
for the supported login/PDU profile. The SCSI command family is defined by
T10 SBC/SPC; see [T10's 16-byte opcode assignment](https://www.t10.org/ftp/t10/document.00/00-152r0.pdf).
No claim of general iSCSI/SCSI compliance or native target interoperability is
made by the scripted protocol evidence.

Use `--block-security TARGET_URL=PROFILE_FILE` for block targets or
`--osd-security TARGET_URL=PROFILE_FILE` for object targets. The target must
exactly match an approved canonical URL; repeat for different targets. The
profile path and secret paths are absolute. For example:

```json
{
  "auth_method": "mutual-chap",
  "username": "viewer",
  "secret_file": "/config/viewer.secret",
  "target_username": "storage",
  "target_secret_file": "/config/storage.secret",
  "header_digest": "crc32c",
  "data_digest": "crc32c"
}
```

On Windows use absolute Windows paths with JSON backslash escaping. Required
fields are `auth_method` (`none`, `chap`, `mutual-chap`), `header_digest` and
`data_digest` (`none`, `crc32c`). Unknown, duplicate or null fields refuse.
CHAP secret files contain 12..1024 raw bytes without implicit newline trimming;
mutual CHAP requires distinct identities, files and secret bytes. Secrets are
not placed in URLs, logs or recovery records. API callers select
`PNFSOptions.BlockSecurity` / `OSDSecurity` by canonical target URL. Recovery
binds the selected policy and file paths without persisting secret material.
Malformed authentication, reflected mutual challenges, policy downgrades and
corrupt digests terminate login or the current connection.

<a id="iscsi-storage-durability-and-failure-boundary"></a>
### Durability and failure boundary

All topology, signature, capacity and physical alias checks precede writes.
Complete aligned writable windows are required, including untouched grants.
Each server block is written, then SYNCHRONIZE CACHE is confirmed on every
changed LU, then type-3 LAYOUTCOMMIT is confirmed before input progress advances.
These acknowledgements rely on the target honoring SCSI cache synchronization.

Each command has the configured connection timeout and the transfer context
deadline. Cancellation closes the storage socket. An iSCSI transport/protocol
error or any non-GOOD SCSI completion permanently invalidates that session.
The optional read recovery below can establish a fresh read-only session;
writable sessions have no reconnect, task recovery, write replay or MDS
data fallback. A failed/unknown WRITE, cache sync or metadata commit leaves zero
new confirmed input progress for that block and quarantines the original NFS
session without returning the uncertain layout. Physical bytes may have changed.
Normal disposal closes the TCP session; it does not send a Logout command.

Require exclusive, stable LU access and server-side fencing. NAA/capacity are
pinned within one connection; unit attention causes refusal, never automatic
reprobe/retry. This profile cannot detect another writer silently changing the
same LU or provide persistent reservations. Do not resize/remap LUs during a
transfer. The conservative unbounded block I/O-time hint remains necessary when
local file images can also participate. Bounded [block process-crash recovery](PNFS_BLOCK.md#process-crash-recovery)
and [T10 OSD](PNFS_OBJECT.md) are implemented as separate profiles;
hardware is N/A.

### Approved read reconnection

`getpnfs ... --layout block --read-failover` permits one fresh read-only session
on the original approved portal after a transport failure during READ. To use
other explicitly approved portals, repeat
`--block-alternate PRIMARY_URL=ALTERNATE_URL` in the desired order, up to eight
alternates per primary. Each selected portal gets at most one fresh attempt for
the transfer; repeated calls cannot replenish this budget. API callers use
`PNFSOptions.ReadFailover` and `BlockReadAlternates`.
Recovery is armed after initial storage/layout/signature binding; initial
connection or probe failures do not automatically choose another portal.

An alternate must preserve target IQN/LUN, initiator and the primary's exact
CHAP/digest policy and secret material. Discovery/redirection cannot add portals.
The new session probes the original NAA, capacity and logical-sector size and
rechecks every applicable MDS volume signature before retrying the failed READ.
Identity, retained I/O state, lease and layout guards run before reconnect,
after validation and before exposing returned bytes. Changed devices, geometry,
signatures, credentials or expired/recalled state refuse.

Only transport failures qualify. Corrupt digests/protocol replies, non-GOOD SCSI
status and cancellation terminate the read. Failed-command bytes are discarded;
an already confirmed prefix remains valid under the enclosing guards. Local
download publication still requires full final verification. This policy never
applies to writable volumes, OSD commands, unknown writes or cache sync; it is
not general multipath scheduling or iSCSI task reinstatement.

<a id="process-crash-recovery"></a>
## Process-crash recovery

The `pnfs-block-recovery` profile extends the
[block write contract](PNFS_BLOCK.md#range-writes-and-cow), [uploads/growth](PNFS_BLOCK.md#new-files-and-growth)
and [explicit iSCSI storage](PNFS_BLOCK.md#iscsi-storage). Hardware remains N/A.

<a id="process-crash-recovery-starting-and-resuming-an-operation"></a>
### Starting and resuming an operation

Block writes optionally take `--block-journal STATE`, a dedicated local regular
file. The API requires an absolute path; shell paths are resolved against the
local working directory. Its parent must exist. Keep this file private: it
contains cached complete blocks and destination handles. Inspection redacts
these bytes; checksums detect corruption, not malicious tampering.

```text
lock target write
putrangepnfs source target 2701 --layout block --block-write --extend --block-volume image --block-journal state
```

After a process crash, connect with the same explicit MDS/auth/storage profile,
wait until the server can grant a new whole-file write lock, and use the
original source, destination, offset and growth approval:

```text
lock target write
putrangepnfs source target 2701 --layout block --block-write --extend --block-volume image --block-journal state --block-resume
unlock 1
```

The client automatically reconciles the journal with fresh READ grants, checks
already confirmed blocks and EOF, and writes only the remaining input using
fresh RW grants. Saved stateids or physical INVALID mappings never authorize
continuation. Each recovery attempt records its new client incarnation before
further writes; reusing that incarnation for another resume is refused.

`putpnfs` accepts a journal for its data writes. Resume uses `putrangepnfs` on
the existing destination with a new explicit lock. Guarded CREATE and empty
uploads retain their existing rules; the journal does not replay an uncertain
CREATE. No automatic reconnect, lease bypass or lock reclaim is introduced.

<a id="process-crash-recovery-durable-stages-and-reconciliation"></a>
### Durable stages and reconciliation

Before the first physical write of a server block, the client durably appends
its preimage hash and full proposed bytes, followed by `write-issued`. Storage
Sync must succeed before `storage-synced` and `commit-issued` are appended.
After a valid LAYOUTCOMMIT acknowledgement, `confirmed` is synchronized before
input progress advances. The final verified EOF precedes `completed`.

| Persisted state | Fresh-client action |
| --- | --- |
| Ready or completed | Verify confirmed blocks and exact EOF; continue or report the verified result without replaying data |
| Prepared, before storage issue | Require the original visible preimage and EOF, then start a new write with fresh grants |
| Storage-synced or commit-issued | Accept the exact visible postimage/EOF as reconciled; otherwise require the exact preimage/EOF before a new semantic write |
| Write-issued, without durable Sync evidence | Quarantine; a matching read cannot prove old storage requests are finished |
| Any different confirmed bytes, pending bytes, EOF, source or profile | Refuse continuation |

This proves content and EOF, not identical timestamps or the disposition of
an old RPC. Safe recovery requires server-enforced block fencing and the new
whole-file lock. iSCSI transport errors are never retried on the old session.

<a id="process-crash-recovery-inspection-and-uncertain-storage"></a>
### Inspection and uncertain storage

```text
nfs-viewer block-state inspect ABSOLUTE_STATE_FILE
nfs-viewer block-state ack ABSOLUTE_STATE_FILE OPERATION_ID --storage-quiesced --destination-verified
```

Both commands are offline. `ack` requires external proof that old requests
cannot still change storage and that the destination was verified or repaired.
It records `acknowledged-unknown`, without certifying success or enabling resume
of that operation. Its exact ID prevents acknowledging a different intent.
A new operation can subsequently use the same v2 file. Checkpoints retain the
current transition and preceding state, not an unbounded historical event log.

The journal holds an exclusive OS file lock throughout an operation. Version 2
uses two alternating fixed-size checkpoint banks with SHA-256 checksums,
sequence/lineage validation and synced invalidation, body and commit footer.
Its total size stays 4,194,423 bytes. A torn inactive bank leaves the preceding
committed checkpoint usable; malformed committed data is quarantined. A journal
cannot alias an image/source. An unresolved intent blocks a normal new write.
Legacy v1 journals remain inspectable/acknowledgeable; resume or new work requires
a fresh v2 journal, with a precise refusal rather than destructive conversion.

<a id="process-crash-recovery-bounds-and-evidence"></a>
### Bounds

Recovery supports large regular destinations and nonempty ranges within checked
signed 64-bit offset bounds. Preparation reads 64 KiB chunks into a private,
automatically removed spool and hashes them; cancellation, source identity and
layout/lock checks run between chunks and before durable begin. Memory does not
grow with source length. Confirmed ranges use an ordered hash chain and fresh
streaming READ verification; only one pending block retains pre/post-images.

Observable stable attributes, advertised server blocks that are positive
multiples of 512 bytes through 1 MiB, and approved storage/layout bounds remain
required. Full disks, failed Sync and corruption cause refusal. Windows/Linux
checks include a small patch beyond 32 MiB, an 80 MiB bounded-memory source and
a packaged transfer above 20 MiB with two process crashes/resumes, changed
source/device refusal and a full backing-image check for unrelated bytes.
This is process-death recovery; power-loss guarantees, directory fsync, general
NFSv4 state migration and native server/fencing interoperability remain outside
this implemented profile.
