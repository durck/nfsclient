# Authentication and transport

[Quick start](../README.md) · [User guide](USAGE.md) · [Compatibility](COMPATIBILITY.md)

## Contents

- [AUTH_SYS](#auth_sys)
- [Kerberos connection examples](#kerberos-connection-examples)
- [Credential sources](#credential-sources)
- [Realm routing](#realm-routing)
- [FAST and PKINIT](#fast-and-pkinit)
- [RPC-over-TLS](#rpc-over-tls)
- [Version and transport selection](#version-and-transport-selection)

## AUTH_SYS

AUTH_SYS sends numeric UID, GID and supplementary groups supplied by the client.
Use `--uid`, `--gid` and `--groups` at startup, or shell `uid UID [GID [G1,G2]]`.
Server export restrictions, root squash and filesystem permissions still apply.

NFSv3 can adopt observed owner IDs with `auto-uid on`. For a fixed identity/root,
select `--auto-uid=false --auto-escape=false`. Identity changes require no held
locks. These options do not select a Kerberos principal or OS credential cache.

## Kerberos connection examples

Choose `--sec krb5` (authentication), `krb5i` (integrity), or `krb5p` (privacy).
The portable Go provider works on Windows and Linux with NFSv2/v3/v4 TCP and
v2/v3 UDP. Supply the exact user principal, NFS service SPN, configuration and
one credential source. Authentication failure never falls back to AUTH_SYS.

Examples assume `nfsclient` is on PATH; substitute your own server and files.
Use absolute Windows paths when running on Windows.

```sh
nfsclient nfs.example.test --export /data --nfs-version 4.1 \
  --sec krb5p --principal alice@EXAMPLE.TEST --spn nfs/nfs.example.test \
  --krb5-config /absolute/krb5.conf --keytab /absolute/alice.keytab \
  --auto-escape=false
```

For a FILE cache, replace `--keytab` with `--ccache FILE:/absolute/alice.ccache`.
For password authentication, replace it with `--password YOUR_PASSWORD`;
`--principal alice --domain EXAMPLE.TEST` qualifies a bare name. Password
arguments can be visible in shell history and process listings.

AD requires an exact NFS SPN, matching server keys, working KDC resolution,
synchronized clocks and server-side principal/group mappings. The client need
not join the domain. A successful TGT acquisition does not prove NFS access.
General forest/PAC/NAS interoperability is not implied.

For multi-host scans, use explicit endpoint service mappings described in
[network scanning](USAGE.md#network-scan). Scan exposes a subset of these profiles.

## Credential sources

| Source | Selection | Requirements |
| --- | --- | --- |
| Keytab | `--keytab ABSOLUTE_FILE` | Must contain the selected principal's usable keys |
| FILE | `--ccache FILE:ABSOLUTE_FILE` | FILE v3/v4, matching principal and valid home TGT |
| Password | `--password VALUE` | Explicit user/realm and configuration |
| Linux KCM | `--ccache KCM:NAME --kcm-socket ABSOLUTE_SOCKET` | Explicit named cache and trusted root/current-user daemon; no default-cache discovery |
| Linux KEYRING | `--ccache KEYRING:session:COLLECTION:CACHE` | Accessible current-user collection and subsidiary; `process` and `user` also supported |
| Linux persistent KEYRING | `--ccache KEYRING:persistent:UID:CACHE` | UID must equal the process's effective UID; kernel keys/keyctl access required |
| Windows LSA | `--ccache MSLSA:CURRENT` | Current-logon exportable AES home TGT; see limits below |
| Windows SSPI | `--krb5-provider sspi` | Current-logon Kerberos handles; explicit principal and SPN |
| Certificate | PKINIT options below | Explicit certificate/private key and KDC trust |

Cache selectors stay fixed for the connection. OS caches are read again when
GSS credentials need replacement; changed identity, expired credentials or an
inconsistent snapshot are refused. They are not written, repaired or replaced
by `kinit`. AUTH_SYS IDs cannot change which OS user owns the cache.

FILE TGTs eligible for renewal are renewed in memory while connected, including
during idle periods. This is subject to the KDC renewal lifetime; the source
file is not rewritten. Nonrenewable/expired TGTs and OS caches require external
refresh. A new process cannot inherit the previous process's in-memory renewal.

### Windows LSA and SSPI

LSA imports only a cache-resident home TGT for the selected current-logon
principal. Credential Guard or key-export restrictions may refuse this profile;
it does not bypass those restrictions. Positive native domain import remains
unverified.

SSPI uses OS Kerberos handles without exporting keys or selecting NTLM.
It supports ordinary TCP and v2/v3 UDP RPC with krb5/i/p. TLS channel binding,
callbacks and RPCSEC_GSS v3 are not supported by this provider. Do not combine
it with portable credential sources or AS routing options. Positive native
domain RPC remains unverified; deterministic tests are not a domain certification.

## Realm routing

Service SPNs and user principals remain explicit throughout routing.

- `--as-alias ALIAS@REALM` requires the selected canonical `--principal`,
  a matching explicit keytab and the same realm. The protected AS reply must
  name exactly that canonical identity.
- `--enterprise-upn USER@SUFFIX --as-start-realm MAP.REALM
  --as-referral-realms MAP.REALM,HOME.REALM` allows bounded AS routing while
  pinning `--principal NAME@HOME.REALM` and its keytab. Every approved realm
  needs explicit KDC endpoints; unlisted realms and cycles are refused.
- `[capaths]` in the selected krb5.conf restricts foreign service realms to
  routes under the client's home realm; an empty section permits only the home
  realm. Keep service-realm selection explicit in `[domain_realm]`. Without
  `[capaths]`, the client retains KDC-directed routing.
- File-based `include` and `includedir` require absolute paths outside relation
  blocks. Loading is bounded and rejects cycles, conflicting settings and
  executable modules. Credential refresh checks the original dependency
  snapshot; a policy change requires an explicitly selected fresh connection.

Alias and enterprise modes cannot be combined with selected caches, FAST or
PKINIT. Neither mode permits accepting a different principal from network data.
Use `nfsclient help auth` for the complete option syntax and allowed combinations.

## FAST and PKINIT

Both use the standalone Go implementation on Windows and Linux. Select an
explicit canonical principal, NFS SPN and krb5.conf; AES128/AES256 are supported.

Required FAST adds `--require-fast --fast-armor FILE:/absolute/armor.ccache`
to keytab or certificate authentication. Armor must contain a valid home-realm
TGT, possibly for a different principal. Refresh the armor externally before
expiry. Missing/invalid FAST never falls back to an unarmored exchange.

For certificate authentication:

```sh
nfsclient nfs.example.test --export /data --nfs-version 4.1 \
  --sec krb5p --principal alice@EXAMPLE.TEST --spn nfs/nfs.example.test \
  --krb5-config /absolute/krb5.conf \
  --pkinit-cert /absolute/alice.crt --pkinit-key /absolute/alice.key \
  --pkinit-ca /absolute/ca.crt --pkinit-crl /absolute/ca.crl
```

Alternatively use `--pkinit-pfx FILE --pkinit-pfx-password PASSWORD` instead
of the PEM certificate/key pair; keep the explicit KDC CA and other identity
settings. There is no ambient certificate discovery or smart-card/PKCS11 support.

The KDC must support RFC 8070 freshness. Certificate/key match, certificate
validity, PKINIT client/KDC purposes and exact Kerberos SANs are checked.
TLS identities do not substitute for PKINIT identities. With `--pkinit-crl`,
every chain issuer needs valid revocation evidence; without it revocation
status is unchecked. No password/keytab/cache fallback occurs.

FAST may be combined with PKINIT by supplying the same armor options.
An explicit Linux `--as-helper` is an optional older MIT integration for
individual FAST or PKINIT profiles, not a fallback and not supported for the
combined profile. See the [helper contract](../internal/krbgss/native-helper/README.md).

## RPC-over-TLS

`--tls` requires RFC 9289 AUTH_TLS/STARTTLS, TLS 1.3 and `sunrpc` ALPN on
each RPC connection, including rpcbind/MOUNT when used. Failed upgrades do
not fall back to plaintext. UDP/DTLS is unsupported.

```sh
nfsclient nfs.example.test --nfs-version 4.1 --export /data \
  --tls --tls-ca ca.pem --tls-server-name nfs.example.test
```

Use `--tls-cert` and `--tls-key` for a client certificate. The server chain
must satisfy the exact peer identity and an accepted server/RPC TLS purpose.
`--tls-insecure` explicitly disables certificate verification; encryption
alone then does not authenticate the peer.

Portable Kerberos binds its GSS context to the exact TLS connection while
retaining the selected krb5/i/p protection level. SSPI does not support this
combination. TLS on the NFS connection does not encrypt a separate iSCSI
storage connection.

## Version and transport selection

Automatic TCP negotiation tries 4.2, 4.1, 4.0, 3, 2; UDP tries 3, 2.
Only a valid protocol-version mismatch permits the next candidate.
Authentication, trust and transport failures stop negotiation.

NFSv4 uses port 2049 directly by default and does not need rpcbind/MOUNT.
For v2/v3, `--nfs-port` and `--mount-port` together bypass rpcbind.
`--portmap-port`, `--timeout`, `--dns-server` and `--dns-tcp` control
discovery and invocation-scoped resolution.

`--transport udp` is for v2/v3; `--udp-size` bounds payloads. IP fragmentation
and server/network limits still apply. Uncertain writes are not retried.
`--reserved-port` binds a source port in 900–1023 and may require privileges.

`--transport iwarp --nfs-version 4.2` selects the software RPC/RDMA profile;
explicit 4.0/4.1 also work. It needs an iWARP listener (default port 20049),
AUTH_SYS and inline RPC messages. Ordinary TCP listeners, RDMA chunks,
GSS/TLS, callbacks and pNFS are not supported by this profile.
It is not a hardware RDMA implementation.
