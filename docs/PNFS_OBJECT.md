# pNFS OSD objects

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [OSD object reads](#osd-object-reads)
- [Authenticated capabilities](#authenticated-capabilities)
- [Existing-object range writes](#existing-object-range-writes)

<a id="osd-object-reads"></a>
## OSD object reads

`getpnfs REMOTE LOCAL --layout object --osd-target iscsi://IP:PORT/IQN/LUN
--osd-initiator IQN` selects the object read profile on an explicit
NFSv4.1/4.2 TCP connection with `--pnfs`. Repeat `--osd-target` for up to 64
approved literal endpoints, normalized target IQNs and flat LUNs (0..255).
The MDS cannot introduce another endpoint or redirect the storage session.

The implementation decodes layout type 2 as specified by
[RFC 5664](https://datatracker.ietf.org/doc/html/rfc5664): a complete dense RAID0
array of 1..64 components, stripe units of 1..1048576 bytes, no groups or mirrors.
Component credentials use OSD-1 and an 80-byte capability: either NOSEC without
a key or the bounded ALLDATA profile below. Reserved user object/partition
identifiers, duplicate components, partial arrays and unsupported security
methods refuse the transfer. RAID parity, groups, mirrors, OSD-2 and SSV key
encoding remain excluded. NOSEC reads require operator approval for that storage
policy. iSCSI CHAP/digests can be selected separately through
`--osd-security TARGET_URL=PROFILE_FILE`; see the
[storage security policy](PNFS_BLOCK.md#iscsi-storage-supported-protocol-profile).

Before publishing any bytes, the client probes every referenced approved
device. Standard INQUIRY must identify an OSD LUN; root GET_ATTRIBUTES must
match the mandatory 20-byte system ID and the optional advertised device name.
Root device IDs and the target/LUN mapping must match. Distinct device IDs may
not alias the same approved LUN. Connections retain one TCP login each.
Extended CDB and bidirectional iSCSI AHS follow
[RFC 7143](https://datatracker.ietf.org/doc/html/rfc7143); OSD-1 CDB/attribute
encodings follow the protocol definitions in the
[Linux SCSI OSD header](https://github.com/torvalds/linux/blob/v4.9/include/scsi/osd_protocol.h).

Reads address objects directly, in at most 64 KiB per NOSEC command or 65024
payload bytes per authenticated command. Object
logical length is checked before and after each stripe fragment. Bytes beyond
the component object's logical length are zero-filled within the MDS file EOF.
Identity, lease, layout recall and cancellation guards run between fragments,
after data reception and before completion verification. The Session transfer
retains its source/namespace guards, stages locally and publishes only after
successful verification, LAYOUTRETURN and CLOSE. Failures never fall back to
MDS READ, reconnect or replay a SCSI command. OSD I/O errors produce a bounded
component error report in the type-2 layout return.

Native OSD interoperability and storage fencing remain unverified; hardware is
N/A under the user-defined scope. This is a bounded implementation, not
a claim of support for every OSD security, version or layout algorithm.

## Authenticated capabilities

`--osd-secure` requires ALLDATA capabilities for every root and component and
refuses NOSEC fallback. Secured credentials require `krb5p` or authenticated,
verified TLS on the MDS connection, because the layout carries a capability key.
`krb5i` alone and unverified TLS do not protect that key sufficiently.
The credential key uses the RFC 5664 `SEC_NONE` encoding inside this protected
MDS channel; this encoding name does not select unauthenticated OSD commands.

The implemented OSD-1 profile selects ALLDATA, algorithm slot zero/HMAC-SHA1,
a 20-byte capability key, exact root or object scope and a finite millisecond
expiry. Root policy attributes must authenticate and confirm that slot's
algorithm before device discovery completes. Every command checks capability
scope, expiry and rights. READ requires READ/GET_ATTRIBUTES; subsequent write
operations also require WRITE and OBJECT_MANAGEMENT for FLUSH.
The security wire reference is the [T10 04-193r4 proposal](https://www.t10.org/ftp/t10/document.04/04-193r4.pdf),
corroborated by the Linux OSD-1 header linked above; this is a bounded implemented
profile, not certification against every revision of the OSD standard.

Command nonces and HMACs authenticate the CDB, outgoing data/attributes, returned
data/attributes and successful response. Received bytes stay staged until all
checks pass. Malformed or altered replies, wrong keys, expired credentials and
unsupported status terminate the operation; a failed command is never retried.
This provides authentication and integrity, not storage payload encryption.

Credentials are cloned into operation memory, never written to recovery records
or logs. Decoder key buffers and owned credentials are cleared on transfer
completion and failure; closing a credential waits for its active command.
Software evidence uses a separately implemented capability issuer/OSD peer,
encrypted GSS/TLS NFSv4.1/4.2 exchanges and CLI publication checks. Native OSD
interoperability remains unverified.

## Existing-object range writes

`putrangepnfs LOCAL REMOTE OFFSET --layout object --object-write` modifies a
finite range inside an existing regular file. Select approved `--osd-target`
URLs and an `--osd-initiator`, and retain a whole-file write lock:

```text
lock report.bin write
putrangepnfs patch.bin report.bin 41 --layout object --object-write --osd-target iscsi://127.0.0.1:3260/iqn.2026-10.org.example:objects/0 --osd-initiator iqn.2026-10.org.example:viewer
unlock 1
```

The connection must have `--pnfs`, explicit NFSv4.1/4.2 and confidential,
authenticated MDS transport as described above. Writes always require ALLDATA
root and component capabilities, even when `--osd-secure` is omitted.
`putpnfs` creation, `--extend` growth, unbounded write grants, parity and mirrored
layouts refuse. Every component must already exist and cover its affected
physical range; a short component is not extended or treated as a hole.

Before the first write, the client validates the complete dense RAID0 layout,
all component rights, device identities and physical bounds. Stripe fragments
are limited to 65024 payload bytes and the negotiated client write size. Each
fragment completes an authenticated WRITE, authenticated FLUSH and MDS
LAYOUTCOMMIT before count/progress advances. Source identity, retained lock,
lease, layout state and capability lifetime are checked between operations.
The final file size must remain unchanged.

An error can leave a confirmed prefix and additional changed bytes. A lost or
invalid WRITE/FLUSH/commit response quarantines the original MDS session; no
unknown mutation is repeated. Component errors are reported when the remaining
session state permits it. Recall, expiry, cancellation and completion failures
cannot report full success. Confirmed prefix counts are an in-process result;
this profile has no process-crash journal or automatic restart resume.
