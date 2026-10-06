# Policy-preserving replacement

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [Native NFSv4 ACL management](#native-nfsv4-acl-management)
- [Publication and ACL policy](#publication-and-acl-policy)
- [Extended NFSv4 policy](#extended-nfsv4-policy)
- [Extended and named attributes](#extended-and-named-attributes)
- [NFSv2/v3 ACL inspection, export and import](#nfsv3-acl-inspection)
- [Explicit NFSv3 replacement](#explicit-nfsv3-replacement)
- [Explicit NFSv2 replacement](#explicit-nfsv2-replacement)

## Native NFSv4 ACL management

With fixed credentials, `acl PATH` displays the ordered NFSv4 ACL as JSON.
`getacl PATH LOCAL [acl|dacl|sacl]` exports a policy to a new private local file;
it refuses to overwrite an existing file. `setacl PATH LOCAL` reads that JSON,
checks the server's advertised support, sets the selected attribute once and
requires exact readback. DACL/SACL require NFSv4.1 or 4.2. The server decides
whether the selected identity may read or change the policy.

The JSON contains `attribute`, `flags` and ordered `entries`; every entry has
`type`, `flags`, `mask` and `who`. Missing or duplicate fields, unknown values and
malformed identities are refused. ACE order and duplicate ACEs are preserved;
an explicit empty list remains distinct from an omitted list. For example:

```json
{"attribute":"acl","flags":0,"entries":[{"type":0,"flags":0,"mask":2032127,"who":"OWNER@"}]}
```

These operations do not open or rewrite file payloads. A lost SETATTR response
or a readback mismatch is reported as potentially applied; there is no automatic
retry or rollback. Exact comparison deliberately exposes server normalization.
NFSv2/v3 `acl PATH` uses the NFSACL inspection format described below.

Stock Linux kernel checks from Windows and Linux cover v4.0/4.1/4.2, successful
named-user grant and revocation, denied policy changes and unchanged payload and
owner identity. Rich DENY/AUDIT/ALARM and DACL/SACL profiles have independent wire
checks; the Linux POSIX ACL backend does not provide native evidence for all of
them.

<a id="publication-and-acl-policy"></a>
## Publication and ACL policy

Confirmed replacement of an existing regular file on NFSv4.0/4.1/4.2 now
preserves a bounded, server-exposed `acl` policy or refuses publication. This does not change
ordinary new uploads, and it is not native ACL editing. Existing NFSv2/v3 upload
destinations are now refused before staging or payload; choose a new name.

<a id="publication-and-acl-policy-legacy-refusal-and-new-name-publication"></a>
### Legacy refusal and new-name publication

NFSv2/v3 base attributes contain no ACL. Successful GETATTR, ordinary mode bits
or a server's filesystem type cannot establish the absence of named-user grants
or default inheritance. Earlier mode-only replacement demonstrably lost or added
access on Linux/ext4 while retaining mode `0640`. The current client refuses
ordinary existing regular-file replacements on these protocols, including direct
`UploadV2` and session `Overwrite` calls. There is no unsafe opt-in or fallback.
The interactive upload dialog explains the limit and offers rename/cancel;
download overwrite and bounded NFSv4 replacement remain available.

If initial LOOKUP finds no destination, an overwrite request becomes ordinary
new-file creation. NFSv3/v4 use guarded CREATE/OPEN; v2 stages privately and
publishes with LINK. A file arriving between LOOKUP and publication must cause
a collision error, not be replaced by RENAME. V3/v4 new-file errors can leave
the client's own partial file; the guard does not add rollback or snapshots.

Linux's separate NFSACL RPC program 100227 now has explicit read-only
[GETACL inspection and an internal complete-policy SETACL primitive](REPLACEMENT.md#nfsv3-acl-inspection).
The latter validates input, retains identity/security, sends once and requires
exact raw-policy readback, including mask-hidden rights. Explicit NFSv3
`replace` uses it after private staging and stable payload transfer. The
read-only preflight captures complete policy and checks the source name and
empty private staging; its bounded contract is in
[the NFSACL guide](REPLACEMENT.md#nfsv3-acl-inspection-internal-read-only-replacement-preflight).
Private creation, policy restoration, source/stage checks and verified
publication are implemented for the explicit bounded lifecycle. Unknown
metadata or missing extensions still refuse. Generic low-level WRITE/RENAME operations
remain available; this contract covers upload replacement, not ACL editing.

<a id="publication-and-acl-policy-nfsv4-publication-sequence"></a>
### NFSv4 publication sequence

1. Read the destination's supported attributes and a complete snapshot of its
   type, change identifier, ACL, ACL-support flags, mode, owner and group.
   Missing, denied or unsupported metadata causes refusal before staging.
2. Create an empty sibling with mode `0600` and inspect its ACL/DACL. If its
   owner/group differs, require ACCESS read/modify/extend for the uploader. An ALLOW
   entry granting read, write or append data to any identity except `OWNER@`
   causes refusal before payload bytes. This deliberately conservative check
   does not attempt general ACL evaluation or account/group expansion.
3. Write the new bytes stably. Restore differing ownership before the final
   mode/ACL/DACL/SACL/label operation, since chown may clear set-ID bits. Require
   exact attribute acknowledgements and separately read back the complete policy.
4. Re-resolve the original destination name and compare its handle, change
   identifier and policy. Also bind the temporary name back to the checked
   handle and policy. Publish with RENAME only after all checks succeed.

Cancellation and detected failures keep the original destination and attempt
to remove the owned temporary. If the staging name refers to a different
handle, cleanup is withheld and reported instead of deleting that object.
Cleanup or publication errors never trigger replay. A lost RENAME response
still leaves publication uncertain; inspect the destination before retrying.

The client keeps the checked uploader identity and security mode. It restores
the original ownership using the same credentials; server denial causes refusal
without publication. Uploading to a new name remains available.

<a id="publication-and-acl-policy-bounded-support-and-remaining-limits"></a>
### Bounded support and remaining limits

- Supported policy: regular files with explicit owner/group, defined mode bits,
  ordered ACL/DACL/SACL containing their known allow/deny/audit/alarm entries,
  and advertised NFSv4.2 labels. Unknown flags, masks,
  identities or omitted required attributes cause an explicit error. Empty ACL
  is distinguished from missing ACL; successful round-trip validation is still
  required.
- Advertised DACL/SACL and labels must be returned in full. Their exact flags,
  entry order and opaque label bytes are preserved and verified separately from
  the legacy ACL model; missing or malformed attributes refuse publication.
- Attribute data is bounded to 64 KiB, 1024 ACEs and 4096 bytes per principal,
  with separate negotiated request/reply budgets. Large ACL metadata does not
  borrow the file READ/WRITE chunk size. SETATTR remains cached where sessions
  support it; the separate ACL GETATTR is an uncached read-only response.
- Exact readback intentionally rejects server normalization that produces a
  different NFSv4 ACL, even if a human might consider it equivalent. No mode-only
  fallback is used after an ACL failure.
- A server can expose only a translation of its filesystem ACL. The Linux/ext4
  fixture preserves the exposed NFSv4 ACL and Bob's effective read access, but
  `getfacl` shows masked-off POSIX permissions normalized from `rwx` to `r--`.
  Byte-identical POSIX ACLs and future access after expanding the mask are not
  preserved by this contract, even when the NFSv4 readback matches exactly.
- Checks detect observable changes, but LOOKUP/GETATTR/RENAME is not an atomic
  compare-and-swap. Concurrent writers can still race the final checks. The
  client does not lock directories or protect against another process using
  the same identity, a privileged server administrator or a dishonest server.
- Bounded xattrs and named attributes are now preserved as described in
  [the attribute contract](REPLACEMENT.md#extended-and-named-attributes). Timestamps and other
  filesystem metadata remain outside the contract. This is not a full metadata clone or
  a claim about Microsoft AD/PAC/domain ACL behavior.

<a id="extended-nfsv4-policy"></a>
## Extended NFSv4 policy

Existing NFSv4 `replace LOCAL REMOTE` and overwrite uploads automatically
preserve a bounded metadata snapshot on a new inode. The implementation keeps
ordered ACL ACEs, DACL/SACL flags and ACE inheritance flags, explicit owner/group
strings, all defined mode bits (07777), and an advertised NFSv4.2 security label.
Security labels remain opaque format/policy/value triples of at most 4096 bytes.
ACLs are limited to 1024 ACEs and negotiated request/reply budgets.
Definitions and mode/ACL ordering follow
[RFC 8881 sections 6.2–6.4](https://datatracker.ietf.org/doc/html/rfc8881#section-6.2);
labels follow [RFC 7862](https://datatracker.ietf.org/doc/html/rfc7862).

Every advertised preservation attribute must be returned. Unknown ACL support,
ACL flags, ACE types/flags, malformed identities, missing policy or oversized
values refuse the operation. Audit/alarm ACEs remain distinct from allow/deny;
DACL admits only allow/deny and SACL only audit/alarm entries. DACL/SACL and
legacy ACL readback retain exact order and values. When DACL is exposed, it is
set directly rather than rewriting its inheritance flags through legacy ACL.

An empty, uniquely named stage must retain mode 0600 and must not grant data
access to another identity in its ACL or DACL. A stage may have a different
owner/group from the original; in that case ACCESS must confirm read, modify
and extend rights for the current uploader before payload. After payload and
normal durable NFS write completion, owner/group are restored first when they
differ, then mode and policy are set. This ordering handles servers that clear
set-ID bits on ownership changes. No payload is written after the ownership
transition. Insufficient ownership/MAC/ACL rights fail the replacement.

Every SETATTR is issued once and must acknowledge precisely the requested
attributes. Final readback verifies mode, owner/group, ordered ACL/DACL/SACL
and label. The checked stage pins the client and current authentication profile
through metadata and publication checks. The original pathname/handle/change
and all captured policy are rechecked; the temporary pathname must still name
the verified stage before RENAME. Failures preserve the original destination
and attempt handle-checked staging cleanup; an uncertain RENAME remains an
uncertain mutation and is never replayed. Checks do not make RENAME an atomic
compare-and-swap against concurrent writers.

Bounded arbitrary xattrs/named attributes are now automatically preserved;
see [the attribute contract](REPLACEMENT.md#extended-and-named-attributes). Existing
NFSv2/v3 NFSACL replacement boundaries remain as documented in [NFS3_ACL](REPLACEMENT.md#nfsv3-acl-inspection).
This profile does not claim hidden POSIX mask normalization or native server
interoperability for the new metadata models.

<a id="extended-and-named-attributes"></a>
## Extended and named attributes

NFSv4 replacement automatically copies all names and binary values exposed by
RFC 8276 xattrs (v4.2) and OPENATTR named attributes (v4.0/4.1/4.2). There is no
name allowlist or text conversion. Empty values are retained. This extends
[the policy contract](REPLACEMENT.md#extended-nfsv4-policy) for ordinary overwrite uploads and
`replace LOCAL REMOTE`; no additional flag is needed.

Each attribute list contains at most 64 names, each value at most 64 KiB, and
all values together at most 1 MiB, including xattrs on named-attribute files.
Limits, absent required `named_attr`, contradictory advertisements, inaccessible
values, malformed names, incomplete listings, cookie cycles, changing directory
verifiers and missing entry type/handles refuse replacement. Named-attribute
files must have type NF4NAMEDATTR, observable size/change and no recursive named
attributes. Their owner/group, mode, ACL/DACL/SACL and advertised label are also
preserved under the same bounded policy contract.

Source capture precedes creation and payload. Named values are read through
ordinary OPEN/READ/CLOSE, bounded independently of transfer chunk size. Exact
EOF/size, policy and change readback, a repeated complete directory listing and
parent change checks reject observable mixed snapshots. Source publication
checks compare named-file handles and changes as well as names, values and
policy. A server must report conforming changes; these are not atomic snapshots.

Staging must be private and have no inherited xattrs or named values. ACL/DACL
checks include READ_NAMED_ATTRS and WRITE_NAMED_ATTRS access. After durable main
payload, privacy and emptiness are checked again, xattrs are CREATE-only, and
named files are created guarded with mode 0600. Each named value receives stable
writes, its ownership, then final mode/policy. Parent ownership/final policy
follow attribute copying. Exact readback and original/staging pathname checks
precede RENAME. No uncertain mutation is replayed. Failed staging cleanup can
leave a temporary file; the original is preserved until publication, whose
lost reply remains uncertain.

Attributes unavailable through the advertised protocol, timestamps and hidden
filesystem metadata remain outside this contract. Exact protocol policy
readback can refuse server normalization. RENAME is not compare-and-swap and
cannot prevent an undetectable concurrent writer or privileged same-identity
mutation. NFSv2/v3 replacement rules are unchanged. Native named/xattr replacement
interoperability remains unverified; hardware and an external stand are N/A.

<a id="nfsv3-acl-inspection"></a>
## NFSv2/v3 ACL inspection and editing

`acl PATH` reads access and default POSIX ACLs through the separate NFSACL
extension (RPC program 100227, version matching NFS 2 or 3, GETACL procedure 1). This command is
explicit: ordinary listing and connection setup do not probe for the extension.
It applies to regular files and directories on NFSv2/v3. All path components
are resolved without symlinks or automatic UID adoption, including components
that would later be cancelled by `..`.

The extension must be available at the selected NFS endpoint. The client keeps
the existing transport, RPC connection, AUTH_SYS identity or authenticated GSS
principal/security. The command does not adopt owner IDs through `auto-uid`,
discover another port, lower authentication or guess ACLs from mode bits after
an error. Unavailable-program/version/procedure and NFS NOTSUPP replies are
explicit capability errors; permission, malformed-response and transport errors
remain distinct. All errors return no partial ACL output.

`getacl PATH LOCAL_JSON` exclusively creates a private local JSON document;
`setacl PATH LOCAL_JSON` imports it for the currently selected NFS version.
The strict schema contains `version`, `type`, `uid`, `gid`, `mode`, `access`
and `default`; entries contain numeric `tag`, `id`, `perm`. Duplicate, unknown,
omitted or mistyped fields refuse. Empty `default: []` explicitly clears defaults.
Imports are bounded to 1 MiB. Version, type and ownership must match the selected
target. Imported ordinary mode must agree with the imported ACL; it may change
with that policy. Special mode bits refuse. The operation does not change owner.

The separate in-place API revalidates file identity and stable attributes before
one SETACL and verifies exact complete access/default lists afterwards. A lost
reply or failed post-write verification reports an uncertain mutation, never a
retry or claimed rollback. The existing staging-only `SetNFS3ACL` contract and
recursive replacement restrictions remain unchanged.

Example output from a synthetic masked-file fixture:

```text
# NFSv3 ACL (read-only)
# owner: 20001  group: 20001
user::rw-
user:20002:rwx	#effective:---
group::---
mask::---
other::---
# Masked permissions are not a server access decision.
```

Numeric identities are preserved. The `#effective` annotation is the entry's
permission bits intersected with the ACL mask, shown only when they differ.
It is not a complete evaluation for the current user: supplementary groups,
directory traversal, export policy and other restrictions still matter. Default
ACLs use `default:` lines and have their own mask; their permissions need not
match the containing directory's current mode.

Linux can return GETACL for a searchable file whose contents the caller cannot
read. It can also synthesize the four-entry minimum wire ACL from inode mode.
Neither result establishes access to the data or absence of stored filesystem
policy. See the [Linux GETACL implementation](https://github.com/torvalds/linux/blob/v6.8/fs/nfsd/nfs3acl.c).

<a id="nfsv3-acl-inspection-bounded-supported-representation"></a>
### Bounded supported representation

- Request complete access/default entries and counts with mask `0xf`; require
  matching response mask, both lists and regular-file/directory post attributes.
- At most 1024 entries per list and 32 KiB of decoded ACL reply payload. These
  are parser acceptance limits; RPC framing retains its existing 8 MiB bound.
- Accept known owner, named-user, owning-group, named-group, mask and other
  tags with `rwx` bits only. Validate each list's DEFAULT flag, matching counts,
  object UID/GID, required base entries and duplicate identities per tag.
  Mask/other IDs must be zero; undefined named IDs are refused.
- Accept arbitrary wire order and sort numerically within tag classes for
  display. Preserve raw permissions, including rights hidden by the mask.
  Named-user and named-group IDs are separate namespaces.
- Require access owner/mask/other permissions to match the returned mode;
  inconsistent observations refuse. Do not project default ACLs onto mode.
  Empty defaults are valid; empty access lists and regular-file defaults refuse.

This is a strict subset of the Linux/Solaris extension representation, not
Solaris certification. Some Solaris MASK values contain extra bits that Linux
discards; this client explicitly rejects them. Minimal wire ACLs retain the
synthetic MASK entry. [Linux wire representation](https://github.com/torvalds/linux/blob/v6.8/fs/nfs_common/nfsacl.c),
[extension constants](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/nfsacl.h).

Only GETACL is added to the UDP read-retry allowlist. It uses existing bounded
retry/deadline behavior: identical AUTH_SYS retransmissions or fresh GSS
sequence/XID pairs. SETACL and unknown procedures are not retried. Existing
reply authentication is unchanged; public NFSv3 UDP supports `krb5`, `krb5i`
and `krb5p` within the [protected UDP contract](TRANSPORT.md#protected-nfsv3-udp).
[RPCSEC_GSS request protection](https://www.rfc-editor.org/rfc/rfc2203.html#section-5.3.1).

<a id="nfsv3-acl-inspection-internal-complete-policy-setacl-and-readback"></a>
### Internal complete-policy SETACL and readback

`Client.SetNFS3ACL` is an internal primitive used by the explicit private-staging
replacement lifecycle; it is not a standalone shell ACL setter. It accepts complete access/default
lists and ordinary mode bits, with the same strict numeric representation and
1024-entry-per-list limit. Inputs are copied and canonicalized before use;
special mode bits and invalid policies are rejected before any request.

The selected endpoint/security/identity are retained. A GETACL preflight
requires the target's type, UID and GID to match the supplied policy and its
mode to contain no special bits. Other source attributes in the supplied
policy are not copied. The mutation is program 100227/v3 procedure 2, mask
`0x5`, with both complete lists; an empty default list explicitly clears it.

SETACL is sent once. An ordinary success response may omit post-operation
attributes; a complete GETACL readback is always required afterward. Raw
access/default entries and mode must match exactly, including permissions
hidden by the mask. Type, numeric ownership, FSID/file ID, size and mtime must
remain stable against preflight. Ctime changes are expected. Optional returned
attributes are checked too. Concurrent changes can still race these observations.

Linux applies access and default policy sequentially. A server error can follow
partial application. Every error after attempting SETACL therefore wraps
`ErrNFSACLMutationUnverified` and retains its underlying cause. The client does
not retry the mutation, roll it back, change identity or interpret an error as
an unchanged target. A failed/mismatched readback also reports this condition.

Direct API callers should use this primitive only on disposable caller-owned
objects; the `replace` lifecycle supplies the checked private staging. It does not preserve arbitrary
metadata or provide a transaction. Protocol sources: [Linux SETACL server](https://github.com/torvalds/linux/blob/v6.8/fs/nfsd/nfs3acl.c),
[NFSACL working draft, full replacement ambiguity](https://datatracker.ietf.org/doc/html/draft-ietf-nfsv4-nfs-acl-05#section-4.6.2.1).
The draft is work in progress, not an RFC.

<a id="nfsv3-acl-inspection-internal-read-only-replacement-preflight"></a>
### Internal read-only replacement preflight

Three read-only client APIs supply the bounded preflight used by explicit
NFSv3 replacement:

- `CaptureNFS3Replacement(parent, name)` retains an opaque snapshot with complete
  canonical raw access/default ACLs, numeric ownership, ordinary mode, size,
  FSID/file ID, link count, mtime and ctime. Only single-link regular files are
  accepted. A snapshot copies the name/handles and AUTH_SYS groups and binds to
  the client, RPC wrapper, underlying connection and selected identity/security.
- `VerifyNFS3ReplacementSource(snapshot)` rechecks the original captured parent
  handle and basename, file handle, every listed attribute and exact raw ACL.
  An ACL-only change is rejected even if permissions hidden by a zero mask do
  not affect current access and timestamps remain unchanged.
- `CheckNFS3ReplacementStage(parent, name, createdHandle, snapshot)` requires
  the name still to identify the caller's created handle, distinct from the
  source by both handle and file ID, with matching FSID/UID/GID. The stage must
  be empty, single-linked and mode 0600. Every nonowner raw ACL permission must
  be zero; inherited masked-off rights are deliberately refused too.

Accepted observations use `LOOKUP -> GETACL -> LOOKUP`. File handles and the
complete attribute tuple must match across all three responses. The bounded
LOOKUP decoder requires object postattrs and rejects empty/oversized handles,
trailing bytes and malformed attributes before follow-up requests; legal absent
object postattrs are deliberately unsupported here rather than synthesized.
Directory postattrs remain optional. Names must be single components of 1..255
bytes; handles must contain 1..64 bytes. Invalid local arguments and changed
identity/connection refuse before network I/O. Legitimate GSS context renewal
on the same connection/identity remains allowed. Serial Client use is required.

These methods only send LOOKUP/GETACL. They do not create, upload, mutate ACLs,
publish, remove staging or establish server authorization. The explicit
replacement lifecycle adds private staging, complete policy restoration,
post-write identity/name verification and verified publication, with real-server
evidence linked at the top. Ordinary `put`/`Overwrite` stays refused for an
existing destination. Arbitrary xattrs/security labels are not
represented by this ACL extension.

The snapshot binds a parent handle and basename, not all ancestor pathnames.
Bracketing observations cannot detect every same-timestamp or ABA change and
cannot make a later RENAME conditional. Ctime is a timestamp, not NFSv4's change
value; FSINFO may advertise coarse time precision. Access time and allocated
space are excluded from equality. Single-link refusal avoids later silently
splitting one name from its hard-link aliases. Strict raw privacy can refuse
an inherited ACL that Linux currently masks to zero; no mode-only relaxation
or server policy change is introduced.

Primary sources: [RFC 1813 file attributes](https://www.rfc-editor.org/rfc/rfc1813.html#section-2.5),
[LOOKUP](https://www.rfc-editor.org/rfc/rfc1813.html#section-3.3.3),
[RENAME](https://www.rfc-editor.org/rfc/rfc1813.html#section-3.3.14),
[time precision](https://www.rfc-editor.org/rfc/rfc1813.html#section-3.3.19),
[Linux GETACL ordering](https://github.com/torvalds/linux/blob/v6.8/fs/nfsd/nfs3acl.c),
and [POSIX ACL inheritance/masks](https://github.com/torvalds/linux/blob/v6.8/fs/posix_acl.c).

<a id="nfsv3-acl-inspection-internal-private-staging-creation"></a>
### Internal private staging creation

`CreateNFS3ReplacementStage` rechecks the captured source, then attempts one
GUARDED CREATE for a distinct sibling name with mode 0600 and size zero. It
does not request UID/GID changes. It requires a bounded, complete CREATE reply
with an acknowledged file handle, object attributes and strictly parsed WCC.
An omitted handle/attribute is refused; a later LOOKUP never substitutes for
proof of which object was created.

The stage must be a distinct single-link regular file on the same filesystem,
with matching UID/GID, zero size and mode 0600. Two bracketed ACL observations
must bind its name to the CREATE handle and metadata. All raw nonowner rights,
including rights hidden by the ACL mask, must be zero. Some inherited default
ACLs therefore deliberately refuse; this primitive does not normalize them.

Every error after attempting CREATE wraps `ErrNFS3StageUnverified` and its
cause. The name may remain even after an explicit server error. The method
returns no usable node on failure and never retries, adopts by name or removes
an unproven object. A successful observation is not a lock. The integrated
replacement lifecycle separately supplies payload, restored policy, post-write
source/stage checks, publication and owned cleanup. Ordinary v2/v3 `put`/
`Overwrite` refusal is still enabled.

Sources: [RFC 1813 CREATE](https://www.rfc-editor.org/rfc/rfc1813.html#section-3.3.8),
[Linux post-create handling](https://github.com/torvalds/linux/blob/v6.8/fs/nfsd/nfs3proc.c#L296-L315).

<a id="explicit-nfsv3-replacement"></a>
## Explicit NFSv3 replacement

<a id="explicit-nfsv3-replacement-explicit-bounded-nfsv3-replacement"></a>
### Explicit bounded NFSv3 replacement

```text
auto-uid off
replace local-file existing-remote-file
```

`replace` requires NFSACL GETACL/SETACL on the existing NFS endpoint, a fixed
identity and an ordinary single-link target. It captures the complete raw POSIX
policy, including mask-hidden named-user rights, uploads into a verified private
guarded stage, performs stable writes, restores and verifies ACL/mode and checks
both names before one RENAME. Unsupported ACLs, changed identity/ownership,
changed source/stage, special mode bits or hard links refuse publication.

The ordinary NFSv3 `put` overwrite dialog retains its refusal; use the explicit
`replace` command for this contract. NFSv2 has the separate bounded profile below. NFSv4
`replace` uses the existing bounded NFSv4 ACL-preservation path.

RENAME publication is atomic but is not compare-and-swap against concurrent
namespace writers. Arbitrary xattrs, security labels and other unexposed metadata
are outside the contract. Failure reports a retained staging name instead of
deleting a possibly substituted object; an uncertain rename is never replayed.
Inspect both names before retrying. Local source size/mtime changes are checked
before publication; this is not a local snapshot either.

<a id="explicit-nfsv2-replacement"></a>
## Explicit NFSv2 replacement

<a id="explicit-nfsv2-replacement-explicit-bounded-nfsv2-replacement"></a>
### Explicit bounded NFSv2 replacement

`replace LOCAL REMOTE` also supports NFSv2 AUTH_SYS when the same NFS endpoint
implements NFSACL version 2 GETACL/SETACL. Select an export and disable both
`auto-uid` and `auto-escape`. Held locks, missing ACL support, hard links, special
mode bits and files above 2 GiB minus one byte are refused. Ordinary `put`
overwrite behavior is unchanged; a missing destination is not created by `replace`.

The destination's complete exposed POSIX ACL, owner, group and ordinary mode
are retained. Source owner/ACL copying is not required. Since NFSv2 CREATE has
no exclusive mode, the payload is created only inside a newly acknowledged
0700 directory with verified private ACL and no default ACL. The stage must
have the same owner/group/filesystem as the destination. Inherited masked-off
rights cause refusal; policy is not silently weakened to make staging succeed.

The client checks synchronous WRITE acknowledgements, source length/metadata,
stage identity and complete ACL restoration/readback before rechecking the
original name and performing one RENAME. NFSv2 mode type bits and link counts
are decoded explicitly. The namespace must be quiescent: the checks and RENAME
are not compare-and-swap, and timestamps do not provide a snapshot. Unexposed
security labels/xattrs, remote power loss and other server implementations are
outside the verified contract.

Failed stages remain inside the reported private directory for inspection.
An uncertain RENAME must never be retried automatically. Successful publication
followed by failed empty-directory cleanup is reported as already published,
so retrying the upload is unnecessary. The protocol layout is based on the
[Linux NFSACL v2 implementation](https://github.com/torvalds/linux/blob/v6.6/fs/nfsd/nfs2acl.c).
See the [independent kernel fixture](../tests/README.md#fixture-catalog) for
exact server configuration, evidence and limits.

