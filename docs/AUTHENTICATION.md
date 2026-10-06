# Kerberos identities and credential profiles

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

The default portable provider selects `--sec krb5|krb5i|krb5p` with an explicit `--krb5-config`,
`--principal`, `--spn` and keytab or selected cache. Authentication
failure never downgrades to AUTH_SYS. FILE formats 3/4 import a valid
home TGT. Renewable FILE TGTs are renewed automatically while the connection
is open, including during idle periods; see below. AES128/AES256 privacy is
supported. Kerberos supports v2/v3/v4 TCP and v2/v3 UDP. Numeric AUTH_SYS IDs do not
select a Kerberos identity. Windows/Linux ordinary operation is CGO-free;
FAST/PKINIT use the standalone Go implementation on Windows and Linux by
default. An explicitly selected MIT helper remains optional on Linux.

AD deployments must provision the exact NFS SPN and current matching
server keys, then map domain principals/groups to server permissions.
No client-side domain join is needed. A machine TGT or successful kinit
does not prove NFS authorization. General forest/PAC/NAS behavior and
positive native Windows LSA import remain unverified.

## Automatic FILE TGT renewal

Each live connection owns an in-memory copy of its selected FILE credentials.
It renews an eligible home TGT before expiry, including while the interactive
client is idle, and retains that renewed TGT across RPC GSS context replacement.
Renewal uses a verified KDC TGS exchange with the same client, home realm and
TGT service; referrals, changed identity, invalid replies and extended renewal
limits are rejected. Each exchange has a five-second bound. Closing the
connection cancels and joins background and foreground renewal.

The original FILE cache is not rewritten. Each replacement/renewal rechecks the
selected input; an externally refreshed file is authoritative, and a removed,
invalid or mismatched cache is not bypassed. The renewal lifetime and KDC policy
still apply: expired, nonrenewable or exhausted tickets require external login
and reconnect. A fresh process cannot inherit the previous process's in-memory
renewal. KCM, KEYRING and LSA remain externally managed credential sources.
Renewal does not replay an NFS operation or change the selected security flavor.

Encrypted negative tests cover altered identities, nonces, lifetimes and replies;
independent MIT KDC runs on Windows/Linux verify service-ticket acquisition
past the original ten-second FILE TGT expiry without rewriting the cache.

## Contents

- [Automatic FILE TGT renewal](#automatic-file-tgt-renewal)
- [Client trust paths](#client-trust-paths)
- [Pinned AS aliases](#pinned-as-aliases)
- [Enterprise UPN routing](#enterprise-upn-routing)
- [Linux KCM](#linux-kcm)
- [Linux KEYRING](#linux-keyring)
- [Windows LSA](#windows-lsa)
- [Windows SSPI](#windows-sspi)
- [Required FAST (Windows/Linux)](#linux-required-fast)
- [PKINIT (Windows/Linux)](#linux-pkinit)

<a id="client-trust-paths"></a>
## Client trust paths

The CGO-free Kerberos client accepts a bounded `[capaths]` policy in the same
file selected by `--krb5-config`. Without that section it retains KDC-directed
routing. Its presence makes foreign service realms an explicit allowlist:
the home realm stays allowed, but every foreign destination needs a route under
the selected client's exact home realm. An empty section permits only the home
realm. This does not discover a service realm; keep `[domain_realm]` explicit.

```ini
[capaths]
 CLIENT.TEST = {
  NFS.TEST = MID.TEST
 }
```

This selects `CLIENT.TEST -> MID.TEST -> NFS.TEST`. Replace the example realms
and configure their KDCs in the same file. `NFS.TEST = .` instead requires direct
trust. The policy must describe existing authorized trusts; it creates none.

<a id="client-trust-paths-syntax-and-limits"></a>
### Syntax and limits

- One normalized lowercase `[capaths]` section. The file loader coalesces
  repeated sections/home blocks before route parsing; conflicting routes refuse.
- Case-sensitive ASCII realm names of 1..255 bytes, using letters, digits,
  `.`, `-` and `_`; a realm name cannot be `.` alone.
- Each home relation has its opening brace on the same line; its closing brace
  is on a separate line. Destination relations contain `.` or up to five
  ordered intermediate realms. Repeated indirect relations append intermediates
  in order within that same five-hop bound.
- At most 64 home blocks, 256 destination routes and 1 MiB of configuration;
  lines must be shorter than 64 KiB. `#` and `;` begin comments.
- Cycles, endpoints repeated as intermediates, duplicate/mixed direct routes,
  quoted realm names, final markers and malformed capaths syntax are refused.
  Dynamic `module` profiles remain refused. File `include` and `includedir`
  directives are handled by the shared loader described below.

### Configuration includes

Explicit file configuration accepts absolute `include PATH` and `includedir DIR`
directives outside relation blocks. Each included file starts its own section
context. Directory names are sorted; eligible names contain only ASCII letters,
digits, `_`, `-`, or end in `.conf` without starting with `.`. Limits are 64
files, 1 MiB total content, eight include/block levels and 1024 directory entries.
Cycles, unreadable files, conflicting scalar settings, inline blocks, final
markers and executable modules refuse. Multiple KDCs and ordered capaths hops
are retained; repeated sections are coalesced before either parser sees them.

Authentication and trust-path enforcement consume the same immutable normalized
text. The loader records contents, identity, metadata and directory membership;
renewal/reconnect verify those dependencies instead of silently accepting changed
policy. Recovery fingerprints include the dependency snapshot. A policy change
requires an explicitly selected fresh connection. Direct text-only API input
cannot resolve file includes and must supply a loaded snapshot or normalized text.

<a id="client-trust-paths-authentication-and-refresh"></a>
### Authentication and refresh

The client validates a configured route before using its service-ticket cache.
It requests each adjacent TGT in order and refuses substituted referrals before
insertion or further I/O. It does not reuse an intermediate TGT from a different
route. The home TGT and an eligible service ticket under the same immutable
client policy remain reusable. An imported cache contributes the validated
home TGT to this route, rather than selecting a foreign path implicitly.

Policy is parsed before credential login. Context establishment/replacement
rereads the chosen file and validates it before issuing the pending NFS
operation. Editing the file does not immediately revoke an active context.
Route failures never fall back to automatic traversal or weaker NFS security.

The [three-realm fixture and explicit variant](../tests/README.md#fixture-catalog)
record one intermediate MIT realm without a direct first-to-last trust.
Encrypted loopback tests additionally check direct and two-intermediate routes.
These results do not certify arbitrary AD forests, mixed trusts or NAS policy.
KDC/server transited checks remain authoritative.

Implementation: [parser and route enforcement](../internal/krbclient/capaths.go),
[GSS integration](../internal/krbgss/initiator.go).

<a id="pinned-as-aliases"></a>
## Pinned AS aliases

Supply `--as-alias ALIAS@REALM` alongside an explicit canonical `--principal
NAME@REALM` and `--keytab`. API uses `KerberosConfig.ASAlias`. The alias and
canonical principal must share a realm. FILE/KCM/KEYRING and ambient keytabs
cannot be combined with this option. Alias names are bounded UTF-8, at most
1024 bytes/16 components/256 bytes per component, without empty components,
backslash, NUL or newlines; krbtgt aliases are refused. Invalid configuration
is rejected before NFS network access.

The AS request carries the alias, canonicalize option and exactly one empty
PA-REQ-ENC-PA-REP. Preauthentication uses only the selected canonical keytab.
The reply must name that exact canonical principal/realm; no credential name
is updated from network data. AES128/AES256 reply decryption and integrity,
nonce, authenticated home-TGT/ticket identity, addresses and ticket times are
checked before session insertion. The encrypted reply must set enc-pa-rep and
contain exactly one correctly typed/length-bounded checksum of the actual final
AS request bytes with the reply key and key usage 56. Missing, duplicated,
malformed or nonmatching protection refuses login even if alias equals the
canonical name. A preauthentication challenge updates the tracked request
bytes; the checksum never covers an earlier request or a reconstructed alias.

The profile follows [RFC 6806 section 11](https://www.rfc-editor.org/rfc/rfc6806.html#section-11).
PA-FX-FAST negotiation may be present; it is not required by checksum verification
and does not implement FAST armoring. WRONG_REALM remains refused. Explicit [enterprise UPN/client-realm routing](AUTHENTICATION.md#enterprise-upn-routing) is a separate
opt-in profile. Protected same-realm
aliases do not relax TGS service-SPN checks, select another principal, replay
NFS operations or authenticate arbitrary KDC-provided aliases. Context renewal
uses the same explicit alias and canonical keytab, including after lcd.

<a id="enterprise-upn-routing"></a>
## Enterprise UPN routing

Use `--enterprise-upn USER@SUFFIX --as-start-realm MAP.REALM
--as-referral-realms MAP.REALM,HOME.REALM` together with the expected canonical
`--principal NAME@HOME.REALM`, its explicit keytab, configuration and NFS SPN.
API fields are `EnterpriseUPN`, `ASStartRealm`, `ASReferralRealms`. This option
is separate from `--as-alias` and cannot use FILE/KCM/KEYRING/ambient credentials.
Selection is copied before connecting and reused unchanged for GSS replacement,
including after lcd. Invalid selections are rejected before NFS I/O.

The UPN is one KRB_NT_ENTERPRISE component, at most 512 UTF-8 bytes, with one
nonempty USER/SUFFIX separated by @ and no slash/backslash/whitespace/control
characters. The canonical principal is never inferred from the UPN suffix or
network data. Supply 1..6 unique, bounded realms including both start and home;
each must have explicit KDC endpoints in krb5.conf before any AS I/O. Unlisted
realms are not discovered through DNS. Existing endpoint/transport limits and
the same caller setup deadline cover all hops and preauthentication.

Every lookup preserves the original UPN and requests canonicalization plus
exact-request protection. Follow at most five WRONG_REALM referrals through the
explicit realm allowlist; reject cycles, absent/unapproved targets and a home
realm redirect. Ignore CName supplied in those unauthenticated errors. Mapping
realms receive the name only, including on context renewal after preauth has
been negotiated. A challenge or AS reply outside the pinned canonical home
realm fails. Only the selected home KDC may receive encrypted preauthentication
with the canonical keytab. At most one challenge response is sent there.

Before saving the home TGT, require the fixed canonical name/realm and the
[protected AS checks](AUTHENTICATION.md#pinned-as-aliases): reply-key integrity, exact final
request checksum, nonce, home-TGT/ticket identity, addresses and valid times.
TGS/GSS thereafter use the canonical credentials. Routing never changes the
selected user, imports intermediate AS tickets, relaxes NFS SPN checks, retries
authentication denial or replays NFS mutations. This explicit mapping policy
follows [RFC 6806 sections 5, 7 and 11](https://www.rfc-editor.org/rfc/rfc6806.html).
It is not arbitrary domain discovery or acceptance of every referred realm.

<a id="linux-kcm"></a>
## Linux KCM

Select `--ccache KCM:NAME --kcm-socket /absolute/path/to/socket` instead of a
keytab or FILE cache. Continue supplying `--krb5-config`, `--principal`, `--spn`
and `--sec krb5`, `krb5i` or `krb5p`. API uses `KerberosConfig.CCache` and
`KerberosConfig.KCMSocket`. The process uses its real effective UID; AUTH_SYS
UID options cannot choose a Kerberos cache identity.

Only Linux Unix-socket KCM 2.0 is supported. Windows refuses this source before
network access. Cache names must be explicit, nonempty, valid UTF-8 and at most
256 bytes without NUL/newline. Socket paths must be absolute and at most 107
bytes. The client does not discover default caches, consult KRB5CCNAME, switch
collections, mutate the cache, invoke kinit or fall back to another source.
Socket symlinks, non-sockets and replacement during connection are refused.
The socket owner and SO_PEERCRED daemon UID must be root or the current user;
the selected trusted daemon must enforce its own cache access policy.

Read-only GET_PRINCIPAL, GET_CRED_UUID_LIST, GET_CRED_BY_UUID and GET_KDC_OFFSET
use big-endian Heimdal IPC with FILE v4 principal/credential serialization.
Both transport and operation status are checked. Each reply and the complete
snapshot are at most 4 MiB, with 1..64 unique nonzero UUIDs and exactly one
credential per UUID. One terminal NUL from MIT's published test daemon is
accepted on the principal only; other suffixes are errors. Nonzero/malformed
clock offsets, incomplete or changing replies are refused. Repeated credential,
principal, UUID-list and offset reads reject observable mixed snapshots. The
five-second total deadline honors cancellation; reads are not retried. These
checks do not constitute an atomic daemon snapshot.

The existing parser requires the configured principal, an ordinary currently
valid home-realm TGT and matching ticket metadata. Service tickets are fetched
afresh through authenticated TGS replies; cached service-ticket lifetimes are
not trusted. Temporary raw buffers are cleared and never exported to files or
diagnostics; retained credentials use the existing Go key handling. GSS context
replacement rereads the same name/socket, including after lcd. It does not
perform AS login, renew the cache TGT, change principals or replay NFS mutations.
An expired/changed cache refuses subsequent authentication.

Native SSSD 2.9.4 KCM with MIT 1.20.1 and Ganesha 4.3 now passes explicit cache
selection, same-principal refresh, and missing/destroyed/replaced/expired-cache
controls. Twelve NFSv3/v4.0/v4.1/v4.2 × krb5/i/p profiles continue transfers
across actual service-ticket expiry without replacing the original NFS session.
Mutation-boundary refusals retain unchanged file bytes, checked by an independent
keytab client. Other daemon/version combinations are not certified by this run.

<a id="linux-keyring"></a>
## Linux KEYRING

Use `--ccache KEYRING:session:COLLECTION:CACHE` instead of a keytab/FILE/KCM
source, with the usual explicit `--krb5-config`, `--principal`, `--spn` and
`--sec`. `process` and `user` anchors are also supported when the selected
keyring is already accessible. `KEYRING:persistent:UID:CACHE` explicitly selects
a named cache under the current effective UID's persistent `_krb` collection;
UID must be canonical decimal and match the process before any kernel call. The effective OS UID supplies the identity;
AUTH_SYS UID options do not select kernel credentials. The kernel must enable
keys and permit keyctl. Windows refuses this source before network access.

Both collection and subsidiary are mandatory UTF-8 names of 1..256 bytes,
without colon, semicolon, NUL or newlines. The client reads direct children of
`_krb_COLLECTION`, then the exact CACHE keyring. It never follows recursive
aliases, consults a primary cache/KRB5CCNAME, invokes kinit or writes credentials.
Persistent lookup uses KEYCTL_GET_PERSISTENT linked into the process keyring;
the kernel may create its anchor, but the client never creates the Kerberos
collection/cache or falls back to another anchor. Thread, legacy, foreign-UID,
implicit/default subsidiaries and DIR/MSLSA remain outside this profile.
An inherited session keyring is the native interoperability profile verified
below; persistent selection has deterministic snapshot and encrypted TGS/GSS
refresh evidence on Windows/Linux, not native persistent-kernel certification.

Selected collection/cache and credential keys must belong to the effective
UID. Kernel permission, expiry and revocation checks remain authoritative.
Only user/big_key credentials are accepted; principal/clock-offset metadata must
be user keys. A cache contains exactly one FILE-v4 principal and 1..64 single
FILE-v4 credentials. Offset metadata, when present, must be exactly eight zero
bytes. Parent scans stop at 4096 direct children, cache scans at 66; individual
payloads and the full assembled snapshot are limited to 4 MiB. Duplicate IDs,
ambiguous ring names, nested cache rings and malformed data are refused.

Repeated payload/description/membership and selected-path reads reject observed
changes without retry. This is a consistency check, not an atomic kernel
transaction. Kernel buffer sizes are checked before allocation and after read;
raw credential buffers are cleared without exporting keys to files/logs. A
single OS thread resolves and reads the inherited anchors under a five-second
context budget; cancellation is checked between bounded kernel calls.

Existing principal/home-TGT checks and authenticated fresh TGS service tickets
are unchanged. GSS replacement rereads the same explicit KEYRING name after
service-ticket expiry, including after lcd. External tooling must refresh an
expired home TGT; no AS login, cache-TGT renewal or NFS mutation replay occurs.

The format follows the [MIT KEYRING implementation](https://github.com/krb5/krb5/blob/krb5-1.22-final/src/lib/krb5/ccache/cc_keyring.c).

## Windows SSPI

Select `--krb5-provider sspi --sec krb5|krb5i|krb5p` with explicit
`--principal NAME@REALM --spn nfs/server-hostname` on Windows. This provider uses
the current logon's Kerberos credential/context handles for mutual context
establishment, signing and sealing; it never exports a session key or selects
Negotiate/NTLM. The default provider remains `portable`.

The established client identity, server SPN, Kerberos package, requested
integrity/privacy flags and finite lifetime must match the selected profile.
RPC sequence binding and verified responses enforce replay protection.
Expired contexts refuse use; renewal obtains a new OS context for the same
identity. Handles are released on failure, cancellation and connection close.

Explicit config files, keytabs, caches, FAST/PKINIT and AS routing options cannot
be mixed with SSPI. TLS channel binding, pNFS/offload callbacks and RPCSEC_GSS v3
are rejected before connecting. Ordinary NFSv2/v3/v4 TCP and v2/v3 UDP use the
shared RPC framing. Linux rejects SSPI selection without trying another provider.

Windows native-call/ABI tests, current-logon refusal tests and the independently
encrypted provider/RPC fixture pass. `TestSSPINativeCurrentLogonRPC` is an opt-in
read-only real-domain test for krb5/i/p; its positive native path has not been
executed in this environment. These test layers do not claim native domain
interoperability from a portable-provider test.

<a id="windows-lsa"></a>
## Windows LSA

On Windows, `--ccache MSLSA:CURRENT` imports a selected home-realm TGT from
the current process logon. Keep an explicit `--principal NAME@REALM`,
`--krb5-config` and service `--spn`. It works with the existing `krb5`, `krb5i`
and `krb5p` RPCSEC_GSS implementation; KDC access for fresh service tickets is
still required.

```powershell
.\nfs-viewer-windows-amd64.exe nfs.example.test --sec krb5p --export /data `
  --krb5-config C:\NfsConfig\krb5.conf --ccache MSLSA:CURRENT `
  --principal client@EXAMPLE.TEST --spn nfs/nfs.example.test
```

<a id="windows-lsa-selection-and-boundaries"></a>
### Selection and boundaries

Only the exact selector `MSLSA:CURRENT` is accepted. Other logon IDs, implicit
default selection, KCM sockets, keytabs, AS aliases and enterprise routing are
refused. Non-Windows selection fails before DNS or network access. No ambient
cache or password acquisition follows an error.

The native adapter connects using `LsaConnectUntrusted`, selects the Kerberos
package, queries `KerbQueryTicketCacheExMessage` and retrieves only
`krbtgt/HOME_REALM` using `KerbRetrieveEncodedTicketMessage` and
`KERB_RETRIEVE_TICKET_USE_CACHE_ONLY`. LogonId is zero; it neither registers a
privileged logon process nor selects another logon session. Thread impersonation
is refused. It never writes a FILE cache or renews the OS cache itself.

At most 64 entries and a 4 MiB return allocation are accepted. Every Unicode,
name, session-key and ticket pointer must remain inside the returned allocation.
The detached parser uses numeric offsets, verifies 32/64-bit native layouts,
rejects malformed UTF-16 and bounds lengths before decoding ASN.1.

Exactly one home TGT must match the pinned client and realm. Its encoded ticket,
queried metadata and returned names must agree. Ordinary currently valid AES128
or AES256 tickets and session keys are supported. Ticket encryption type and
session-key encryption type are independently checked; they may differ.
Protected, missing or zeroed session keys are refused. In particular, systems
that prevent TGT key export require a different credential profile. LSA import
does not bypass that policy; the separately selected [SSPI provider](#windows-sspi)
uses OS handles without key export for its supported ordinary-RPC profile.

Local time must agree with the ticket lifetime; nonzero native TimeSkew is
unsupported. External-ticket StartTime supplies the imported cache AuthTime,
because this API does not return a separate authentication timestamp. No cached
service ticket substitutes for home-TGT validity.

Two cache queries surround two selected-ticket retrievals. Metadata, encoded
ticket and session key must remain identical; renewal during that interval
causes refusal. Raw native buffers are cleared before freeing them, detached
snapshots and duplicate keys are cleared after use. Context cancellation is
checked before and after OS calls. A synchronous local LSA call has no hard
deadline; the adapter does not leave background credential calls running.

When a GSS context needs replacement, the same selector and principal are read
again. Windows must have refreshed the TGT before it expires. An expired,
changed or inaccessible cache closes the affected flow without switching
identities or replaying an uncertain file mutation.

<a id="linux-required-fast"></a>
## Required FAST (Windows/Linux)

`--require-fast` authenticates an explicitly pinned canonical keytab or certificate identity
inside mandatory RFC 6113 FAST armor. Both standalone binaries implement this
in Go; no helper or system Kerberos library is required.

```text
nfs-viewer SERVER --sec krb5p --principal USER@REALM --spn nfs/SERVER --krb5-config /absolute/krb5.conf --keytab /absolute/client.keytab --require-fast --fast-armor FILE:/absolute/armor.ccache
```

Use absolute Windows paths on Windows, for example `FILE:C:\NfsState\armor.ccache`.
The armor must contain a currently valid home-realm TGT; its principal may differ
from the keytab identity. Armor is not renewed by this feature: refresh its
selected file explicitly before expiry. AES128/AES256 (enctypes 17/18) are supported.

<a id="linux-required-fast-supported-boundary"></a>
### Supported boundary

Both AS requests are armored. Request checksum, encrypted response, nonce,
finished ticket checksum, client identity and time are verified. Encrypted
challenge and reply strengthening are mandatory when that preauthentication
method is selected. Invalid/missing FAST never falls back to an unarmored request,
another principal, a password or another credential source. GSS replacement
repeats this same pinned AS flow.

Select explicit configuration, keytab or PKINIT identity, and FILE armor. Alias, enterprise-UPN,
selected-cache and ambient-credential combinations are refused. The standalone
path honors the explicitly selected Kerberos configuration, including configured
KDC names. Protect keytab and armor files with OS permissions; their ordinary
loaders do not impose the helper's snapshot/symlink restrictions. Local file I/O
remains subject to the filesystem; KDC work uses the bounded cancelable
connection lifecycle.

<a id="linux-pkinit"></a>
## PKINIT (Windows/Linux)

PKINIT authenticates a pinned canonical principal using an explicit PEM
certificate/private-key pair and pinned CA. Both standalone binaries perform
the AS exchange in Go, then use the ordinary TGS/RPCSEC_GSS path.

```text
nfs-viewer SERVER --sec krb5p --principal USER@REALM --spn nfs/SERVER --krb5-config /absolute/krb5.conf --pkinit-cert /absolute/client.crt --pkinit-key /absolute/client.key --pkinit-ca /absolute/ca.crt --pkinit-crl /absolute/ca.crl
```

<a id="linux-pkinit-supported-boundary"></a>
### Supported boundary

Certificate, key and CA paths are required and absolute. Unencrypted PKCS1,
PKCS8 and SEC1 PEM keys support RSA of at least 2048 bits or ECDSA of at least
256 bits. Private keys, prompts, PKCS12, PKCS11/smart cards and anonymous PKINIT
are not supplied by ambient providers. Select a canonical principal explicitly;
aliases, enterprise mapping and keytab/cache/password fallback are refused.

The implementation verifies certificate/key correspondence, validity, signature
usage, PKINIT client/KDC EKUs including chain restrictions, and exact Kerberos
SANs for the selected client and `krbtgt/REALM` KDC. TLS EKUs and DNS names do
not substitute for those identities. Signed CMS attributes bind the exact
content type and digest to one signer. RSA SHA1 is accepted for deployed MIT
KDC compatibility, together with RSA SHA256 and ECDSA SHA256.

A supplied CRL set is mandatory evidence for every chain issuer, for both client
and KDC. Missing/expired/invalid signatures, revoked certificates and unsupported
delta, scoped, indirect or unknown critical CRL extensions fail authentication.
Recognized CRL-number and authority-key-identifier extensions remain accepted. Omitting
`--pkinit-crl` leaves revocation status unchecked.

The KDC must support RFC 8070 freshness. A discovery request obtains the token
before certificate preauthentication. Each exchange uses fresh group-14 DH
parameters and constant-time private-exponent arithmetic; reused DH, alternate
groups and unrequested KDFs are refused. AS reply/session keys require AES17/18.
Nonce, ticket identity, flags, lifetime and exact request bindings are validated.
Every GSS replacement repeats the same selected certificate flow.

### Required FAST with PKINIT

Add `--require-fast --fast-armor FILE:/absolute/armor.ccache` to the certificate
command above. The combined profile uses the pure-Go implementation on both OSes;
`--as-helper` is refused for this combination. The armor must contain a valid
home-realm TGT, possibly for a different principal. Both the freshness request
and signed certificate request stay inside FAST. The client verifies the inner
preauthentication challenge, freshness, signed DH reply, FAST nonce/finished
identity and ticket checksum, then applies reply-key strengthening when supplied.
Missing armor, unarmored replies and trust/freshness failures never downgrade.

Windows/Linux acceptance covers real MIT KDC AS and TGS exchanges over TCP/UDP,
AES128/AES256, stripped/tampered replies, wrong/expired armor and certificate/CRL
refusals. Public Initiator tests complete mutual GSS with MIC and privacy. An
independent encrypted challenge fixture verifies missing freshness and incorrect
inner errors; this evidence does not add a new native NFS server certification.

### Optional Linux helper compatibility

An explicit absolute `--as-helper` selects the older Linux MIT integration for
either method. It is never selected as a fallback. Windows refuses an explicitly
requested helper; omit the flag for the standalone implementation. See the
[helper build and input contract](../internal/krbgss/native-helper/README.md).
The operator must trust the executable, native library and plugins. The adapter
uses a minimal configuration, private credential snapshots, sanitized environment,
opened-inode execution, an exact bounded success record and a five-second
cancelable subprocess deadline. This helper path requires numeric KDC endpoints,
disabled DNS discovery, UDP preference within 1..32700 and protected regular
credential files without symlinks (snapshots bounded to 4 MiB). The helper is not a sandbox.
