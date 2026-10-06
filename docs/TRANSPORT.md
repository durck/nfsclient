# Transport and RPC security

These are bounded implemented profiles. Server authorization, confirmed
state and explicit endpoint/credential approvals remain required.
Native interoperability scope is recorded in [compatibility](COMPATIBILITY.md);
default software checks do not certify arbitrary vendors.

## Contents

- [Automatic version selection](#automatic-version-selection)
- [RPC-over-TLS](#rpc-over-tls)
- [TLS-bound GSS](#tls-bound-gss)
- [Protected NFSv3 UDP](#protected-nfsv3-udp)
- [UDP network limits and reserved ports](#udp-network-limits-and-reserved-ports)
- [Software iWARP](#software-iwarp)
- [Negotiated NFSv4 session limits](#negotiated-nfsv4-session-limits)

## Automatic version selection

Explicit `--nfs-version auto` uses TCP 4.2, 4.1, 4.0, 3, 2 or UDP 3, 2
with AUTH_SYS or the selected `krb5`, `krb5i`, `krb5p` identity. Initial v4
probes use empty COMPOUND requests before creating client/session state.
Only a well-formed RPC program-version or NFS minor-version mismatch advances
to another version. Authentication, trust, transport and later initialization
failures stop. Failed candidates release credentials/connections; reconnect
uses the selected version and original security policy. No mutation is replayed
as part of negotiation. The omitted API version remains v3; pNFS and advanced
offload profiles still require their explicit versions.

## Negotiated NFSv4 session limits

NFSv4.1/4.2 retains the negotiated maximum request, response, cached-response
size and operation count. Limits cover the complete RPC message, including the
actual AUTH_SYS or GSS overhead. They are checked for every compound; protected
replies are also bounded before decoding. The client no longer requires a fixed
4096-byte request/response or 1024-byte reply cache from every server.

READ, WRITE, READDIR and LAYOUTGET payloads shrink to the available budget.
Commands that cannot fit their required compound are refused before sending it.
Mutations retain `cachethis=true`; reducing the cache limit does not silently
remove exactly-once protection. Variable-size results remain subject to the
server's negotiated response/cache enforcement. Session recovery preserves the
same limits and refuses an exact saved request if it no longer fits unchanged.

Independent wire tests cover legal small channels, GSS integrity/privacy
overhead, operation-count boundaries, oversized replies and local mutation
refusal without transmission. A server that cannot fit mandatory initialization
operations is explicitly unsupported; commands are not split into a different
transaction merely to pass negotiation.

## UDP network limits and reserved ports

Native Windows/Linux UNFS3 AUTH_SYS checks cover MTU 1500 and 900 with 512,
1024 and 4096-byte read limits. Packet observation confirms fragmented NFS UDP
replies; independent server hashes verify file content. At MTU 900, larger read
fixtures are seeded through TCP. A 2100-byte write with `--udp-size 4096` on that reduced-MTU path
does not reach the server in the recorded run: the client reports an uncertain
outcome and sends no retry; the independent server audit observes zero bytes.
The client does not silently shrink and
replay a mutation. Use `--udp-size 512` for that bounded small-MTU profile, or
TCP. This isolated result does not establish the cause of historical AD UDP
timeouts.

A container-only reply firewall additionally verifies three read attempts and
one write attempt. A fresh independent connection observes the unacknowledged
write. Library-level repeated reply sends are counted separately from incoming
client RPCs.

`--reserved-port` selects source ports 900–1023. Windows now recognizes the
Winsock address-in-use error and continues to the next candidate; other errors
still stop immediately. Native UDP collision fallback passes on Windows/Linux,
and Linux TCP binding passes. The Windows run verifies refusal when every TCP
candidate is occupied, without falling back to an ephemeral port; it does not
prove successful Windows TCP binding. NAT can rewrite a locally reserved port.
See [reproduction and fixture boundaries](../tests/README.md#local-storage-and-network-checks).

<a id="rpc-over-tls"></a>
## RPC-over-TLS

<a id="rpc-over-tls-rpc-over-tls"></a>
### RPC-over-TLS

`--tls` requires RFC 9289 AUTH_TLS/STARTTLS, TLS 1.3 and `sunrpc` ALPN on
every RPC connection. Credentials and ordinary RPC requests are sent only after
the upgrade. A refused upgrade, handshake failure or missing ALPN closes the
connection; there is no plaintext fallback. This applies to rpcbind and MOUNT
when used, so an NFSv3 server with TLS only on port 2049 is insufficient.
NFSv4 with an explicit export connects directly to its NFS endpoint.

```sh
nfs-viewer nfs.example.test --nfs-version 4.1 --export / --tls
nfs-viewer nfs.example.test --nfs-version 4.1 --export / --tls --tls-ca lab-ca.pem
nfs-viewer nfs.example.test --nfs-version 4.1 --export / --tls --tls-insecure
```

Certificate validation is enabled by default. RPC server DNS identifiers must
not contain wildcards. A complete chain must retain one common permitted purpose
(`serverAuth` or `id-kp-rpcTLSServer`) through leaf, intermediates and root, while
normal trust, signatures, name, validity and constraints are verified. Actual
verified chains are retained on the RPC connection; insecure mode reports the
certificate as unverified. `--tls-insecure` requires `--tls`
and disables certificate chain, validity period and hostname verification,
allowing self-signed, expired or name-mismatched certificates. Encryption remains
enabled, but the certificate no longer authenticates the server. To trust a lab
CA while retaining validation, use `--tls-ca`. `--tls-server-name` selects the
expected DNS name; `--tls-cert` and `--tls-key` supply a client certificate pair.
The `id` command reports TLS and whether certificate verification is enabled.

TLS works over TCP only. Kerberos security remains separately selected by
`--sec`: TLS does not change the GSS principal or server-side authorization.
Every TLS/GSS context now includes the connection's `tls-exporter` binding;
see [encoding, server requirements and independent MIT GSS checks](TRANSPORT.md#tls-bound-gss).
Reconnect retains the chosen TLS policy. Scripted peers cover encrypted RPC,
rejected/expired certificates, upgrade refusal and ALPN. Real Linux knfsd/ext4
now passes Windows/Linux NFSv4.0/4.1/4.2 with AUTH_SYS over TLS, trusted IP/DNS,
insecure self-signed mode, negative trust/plaintext checks and automatic recovery
after encrypted TCP cuts. Independent files, kernel TLS counters and restoration
pass. The stock Ubuntu tlshd lacks mandatory SunRPC ALPN; this real-server run
uses a separate pinned upstream daemon with a narrow fixture ALPN correction.
See [archived server evidence and reproduction recipes](DEVELOPMENT.md#historical-evidence).
Mutual TLS additionally passes both OSes/all minors in run `tls-20260924-24`, including missing/expired client certificate denial, reconnect and credential-copy cleanup. `--tls-insecure` does not bypass client certificate requirements.
No stock tlshd success, commercial NAS, or TLS-plus-GSS channel-binding
certification follows from these tests.

<a id="tls-bound-gss"></a>
## TLS-bound GSS

`--tls --sec krb5`, `krb5i` or `krb5p` now binds each GSS context to its exact
TLS connection. This includes explicit pNFS MDS/DS connections and intra-server
offload callbacks. The selected GSS protection level is retained; TLS does not
cause an authentication or integrity downgrade. Existing certificate, ALPN,
identity, timeout and no-replay rules still apply.

After the TLS 1.3 handshake with `sunrpc` ALPN, the client exports 32 bytes
using label `EXPORTER-Channel-Binding` and an empty context. The GSS application
binding is the `tls-exporter:` type prefix followed by those bytes. The
Kerberos authenticator contains the RFC 4121 binding hash, including omitted
network-address fields encoded as GSS_C_AF_NULLADDR. Every new GSS context,
including an ordinary context renewal, derives its binding from the live TLS
connection; it does not reuse another connection's exporter or a certificate
hash. Callback contexts remain pinned to their negotiated session as before.

The server must enforce the binding. The client sends it but cannot infer the
server's enforcement policy merely from a successful Kerberos exchange: a GSS
acceptor that was given no binding may ignore the initiator's binding under
RFC 4121. This feature does not certify an arbitrary server's configuration.
The local test acceptor explicitly rejects mismatched or absent bindings and
validates authenticator checksum type, size and flags before indexing fields.

<a id="protected-nfsv3-udp"></a>
## Protected NFSv3 UDP

The public client now accepts all three Kerberos services on NFSv3/UDP:
`krb5`, `krb5i` and `krb5p`, with explicit keytab or FILE credentials.

```sh
nfs-viewer nfs.example.test --nfs-version 3 --transport udp --sec krb5p \
  --krb5-config krb5.conf --principal alice@EXAMPLE.TEST \
  --keytab alice.keytab --spn nfs/nfs.example.test --export /data
```

Select `--sec krb5i` for integrity without privacy. The connection does not
silently lower security or switch transport when the server fails. Kerberos
auto-version selection remains NFSv3. Explicit NFSv2 now also supports all three
GSS modes over TCP/UDP; v4/UDP remains refused. Native kernel checks cover
Windows/Linux keytab and FILE credentials, NFSACLv2 and protected UDP failures.
NFS/MOUNT and KDC transports are separate settings.

<a id="protected-nfsv3-udp-bounded-transport-contract"></a>
### Bounded transport contract

- READ/WRITE payloads stay at or below 4096 bytes, including after FSINFO tuning.
  RPC/GSS framing adds overhead; this is not a path-MTU discovery implementation.
- `--udp-size 1024` lowers the data and requested directory-response limits.
  Values are 512..4096; zero keeps the existing 4096-byte default. The setting
  requires UDP and survives reconnect and server tuning. It does not bound GSS
  initialization, ACLs or every RPC reply and cannot guarantee unfragmented traffic.
- Every successful result is authenticated before exposing content. Integrity
  and privacy service numbers remain pinned throughout the connection.
- Read-only RPC retries use fresh XIDs and GSS sequence numbers. A late original
  reply is ignored; a signed response for the wrong sequence fails authentication.
- Mutation requests, including WRITE, CREATE, SETACL and RENAME, are never replayed.
  A lost mutation reply reports an unknown outcome and closes the failed session.
  Inspect remote state before retrying. GSS INIT/DESTROY is also single-send.
- Oversized datagrams are rejected. TCP is still appropriate where datagram
  fragmentation, packet loss, network middleboxes or ticket size prevents UDP use.
  Arbitrary WAN, physical-NIC/path-MTU and huge AD-ticket profiles are unverified.
- RPC-over-TLS remains TCP-only. This feature uses GSS, not TLS or DTLS.

These rules retain the existing [RPCSEC_GSS sequencing model](https://www.rfc-editor.org/rfc/rfc2203.html#section-5.3.3.1)
and the client's stricter no-mutation-replay policy.

<a id="protected-nfsv3-udp-independent-real-server-evidence"></a>
### Independent real-server evidence

The direct Windows Server 2025 → Microsoft AD/Linux knfsd lane passes all six
NFSv3 UDP GSS/credential profiles with `--udp-size 1024`, including full raw-ACL
replacement and verified-prefix resume. The 4096-byte diagnostic on this VM
network produced ambiguous mutation timeouts and remains a failed result;
the smaller setting does not certify every MTU or eliminate packet loss.
See [Windows runs and exact scope](../tests/README.md#native-fixtures).

Microsoft AD run `interop-20260924-08` passes **30** Linux knfsd/ext4 profiles,
including the four newly public UDP integrity/privacy keytab/FILE profiles.
Those four exercise domain group grants/denials, numeric identity, binary
transfers, complete raw POSIX ACL replacement, explicit reconnect and verified
half-file resume. The independent verifier checks all 30 files, 12 raw ACLs,
artifact hashes and restored domain/service state. The recursive and real
server-restart tests also remain green. See [the AD lane](../tests/README.md#native-fixtures).

<a id="protected-nfsv3-udp-packaged-ganesha-limitation-and-isolated-repair"></a>
### Packaged Ganesha limitation and isolated repair

The original Ubuntu Ganesha 4.3 / ntirpc `4.3-3.1build2` remains incompatible:
the baseline independently reproduces a signed NULL timeout and a privacy
GETATTR GARBAGE_ARGS error. Public client enablement does not fix that server.
Use a verified server build, or explicitly select TCP with the same GSS mode.

The named test image fixes only its private copy of ntirpc. It is not an upstream
release claim, automatic server patcher or recommendation to replace production
libraries. The source comes through authenticated Ubuntu apt metadata and a
pinned original-tarball SHA256. Actual process mappings confirm the rebuilt
library is loaded. The Go executables gain no native runtime dependency.

The [v4.3 XDR memory implementation](https://github.com/nfs-ganesha/ntirpc/blob/v4.3/src/xdr_mem.c)
returns an entire buffer instead of the requested subrange and rejects the first
DATA vector during header allocation. Once allocation works, it also needs to
marshal the MIC trailer length. The fixture repair bounds ranges/layouts, preserves
the requested DATA bytes, supports header/trailer reservation and writes the
length with alignment-safe copying. The original C regression has 12 failures;
the repair has zero. Real GSS tests were necessary to catch the missing trailer
length after the initial buffer fixes.

Reproduction, inputs and cleanup are in the
[fixture guide](../tests/README.md#fixture-catalog). Build/test logs and lab
reports remain under ignored `bin/`; credentials and packet contents are not
included in documentation.

<a id="software-iwarp"></a>
## Software iWARP

`--transport iwarp --nfs-version 4.2 --export /data` selects RPC-over-RDMA
using a pure-Go software iWARP endpoint. Explicit `4.0` and `4.1` also work.
The default NFS port is 20049; `--nfs-port` can override it. The server must
provide an iWARP RPC/RDMA listener. An ordinary NFS/TCP listener is not enough.

This path uses MPA v2 with enhanced depth negotiation and mandatory CRC32C,
DDP/RDMAP untagged SEND/RECEIVE, and RPC/RDMA version 1 inline messages.
It requires RFC 8797 private negotiation, peer inline buffers of at least
4096 bytes, no markers, peer-to-peer RTR or remote invalidation. It exposes
no registered memory and advertises no read/write/reply chunks. RPC messages
are limited to 4068 bytes after the 28-byte RDMA header. Data requests and
NFSv4 session sizes are reduced accordingly. One foreground RPC is in flight.

Requests that exceed the inline budget are refused before sending. Transport,
CRC, sequence or unsupported-frame errors close the connection; mutations
are never replayed. Existing explicit reconnect and held-lock refusal apply.
Large metadata responses can exceed this deliberately small inline profile
and fail. No automatic TCP fallback occurs.

Only AUTH_SYS is supported in this first profile. Explicit Kerberos, TLS, UDP
options and automatic NFS version selection are refused. CRC detects frame
corruption; it does not authenticate the server or encrypt data. For authenticated
or encrypted connections use the existing Kerberos/TCP or RPC-over-TLS profiles.

The implementation runs on Windows and Linux without CGO, OS RDMA drivers on
the client, or helper processes. It does **not** provide hardware offload,
zero-copy, RoCE, InfiniBand, pNFS layouts, tagged placement, callbacks or RDMA
read/write chunks. Software iWARP interoperability is a separate claim from
hardware RDMA compatibility or performance.

The real Linux kernel SIW/NFS listener passes all three minors from Windows
and Linux: six API and six release-CLI flows transfer 1 MiB + 17-byte files,
read under retained locks, reject reconnect with held locks, then reconnect
explicitly and verify bytes. The independent native oracle checks twelve
retained files, ownership/modes and fixture restoration. See the
[fixture](../tests/README.md#fixture-catalog).

Protocol references: [RPC/RDMA v1](https://www.rfc-editor.org/rfc/rfc8166.html),
[connection negotiation](https://www.rfc-editor.org/rfc/rfc8797.html),
[MPA](https://www.rfc-editor.org/rfc/rfc5044.html),
[enhanced MPA](https://www.rfc-editor.org/rfc/rfc6581.html).
