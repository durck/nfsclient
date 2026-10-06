# Local Kerberos client adaptation

Seven source files adapt client/message code from `github.com/jcmturner/gokrb5/v8`
v8.4.4, under Apache-2.0 (see LICENSE). Preserve that license on redistribution.
This internal package is not a new Kerberos implementation. Message parsing,
AS/TGS reply verification and cryptographic primitives still use gokrb5.

Local changes:

- Replace upstream network.go with caller-context-aware KDC discovery, dialing
  and I/O. Preserve TCP/UDP preference and response-too-big TCP fallback; stop
  endpoint/transport retries when the shared setup deadline or cancellation fires.
- Reserve an equal share of the remaining caller budget for each remaining KDC
  candidate; the last candidate can use the remainder within its five-second cap.
  Continue after transport failure or KDC_ERR_SVC_UNAVAILABLE only. Preserve
  authentication errors and preauth challenges for upstream AS/TGS processing.
  Deprioritize failed endpoints within this client, keyed by realm/transport/address;
  never remove candidates permanently or share history with a new GSS context.
- Retry a timed-out UDP AS/TGS request at most three times in total, reusing its
  bytes and source socket. Wait 1/2/4 seconds, clamped to the five-second endpoint
  ceiling and caller deadline; return non-timeout errors and received replies
  without retransmission. This never changes NFS/GSS RPC replay rules.
- Share per-connection DNS server/TCP selection with NFS address lookups. Route
  both KDC SRV discovery and KDC hostname resolution through `internal/resolve`;
  preserve explicit realm/KDC configuration and Kerberos's own transport choice.
- Read the complete four-byte TCP prefix; bound responses to 4 MiB before
  allocating and handle short writes/partial replies. Each endpoint has a
  five-second ceiling in addition to the overall caller deadline.
- Export the verified service-ticket cache endtime. The GSS adapter no longer
  estimates expiry using the requested/configured ticket lifetime.
- After upstream AS decryption/verification, require the exact selected client
  name/realm and a home-realm TGT; bind the clear ticket name/realm to the
  authenticated reply before session insertion. Reject empty ETYPE-INFO/INFO2
  lists with a diagnostic instead of indexing them.
- Reject AS WRONG_REALM client referrals, including after a preauth challenge,
  without contacting the suggested realm or changing credentials. Explicit
  canonical principal/realm configuration is required; protected AS name
  canonicalization is opt-in through a same-realm AS alias and pinned canonical
  keytab. Require RFC 6806 protection over the exact final request and strict
  reply identity/nonce/TGT/address/time checks; do not require FAST capability
  advertisement for that checksum. Explicit enterprise UPN routing preserves
  the original type-10 name through at most five allowlisted referrals with
  configured KDCs. Intermediate realms receive lookup data only; home-key preauth
  and protected canonical replies are restricted to the pinned home realm.
  TGS service referrals remain separate.
- After decrypting/verifying TGS replies, check the selected client realm and
  bind the ticket name/realm to the authenticated service identity. Require the requested
  SPN or a two-component, nonempty, non-self `krbtgt/NEXT-REALM` referral. Reject
  malformed names before indexing, cache insertion or referral I/O. Follow at
  most five referrals; do not accept service-principal alias substitutions.
- Rebuild each TGS authenticator with the selected client's original realm,
  including recursive referrals. Upstream uses the TGT issuer, which differs
  after an intermediate hop. The adapted messages/KDCReq.go PA builder retains
  the real ticket and request-body checksum, destination, options and nonce;
  encryption and marshaling still use upstream primitives. Emit exactly one
  PA-TGS-REQ while retaining any other preauthentication data.
- Remove the upstream background TGT-renewal timer. The NFS RPC layer can create
  a fresh client/context before the next RPC using the same explicit credentials;
  it never replays a failed operation. Closing a session leaves no renewal task.
- Omit password-change APIs, diagnostic keytab dumping and unrelated source
  files. Password constructors remain internal upstream plumbing. Explicit FILE
  cache login imports only a validated home-realm TGT and always requests a fresh
  service ticket; it does not trust cached service-ticket lifetime metadata.

The GSS AP_REQ builder uses an upstream client containing only the same
credentials to satisfy its parameter type. That builder performs no networking.
Never substitute the upstream network client on the active authentication path.

Tests use loopback peers, synthetic credentials and opt-in MIT/Ganesha fixtures:
four-second tickets, real UDP AS/TGS exchanges, dropped AS/TGS responses, genuine
response-too-big TCP fallback, DNS SRV and cancellation. The two-KDC fixture
verifies an independent MIT replica with a one-time database snapshot: primary
AS, replica TGS, TCP/UDP failover and unchanged authentication-denial behavior.
The separate direct-trust fixture verifies independent CLIENT.TEST/NFS.TEST
realms over TCP/UDP, home-realm keytab/FILE credentials and genuine cross-realm
TGT/service tickets. An independent Samba AD fixture covers single-realm
AES128/AES256 authentication, denials and actual context expiry; Microsoft AD,
ongoing replication, broader trust chains and cache/TGT renewal have separate
implementation and interoperability bounds. NFS-layer context replacement is
described in the [authentication guide](../../docs/AUTHENTICATION.md#client-trust-paths-authentication-and-refresh); this package does not
perform background credential renewal itself. The GSS FILE-cache owner now
uses `RenewCCacheTGT` for authenticated home-TGT renewal while its NFS connection
is alive, including idle periods; it cancels and joins renewal on close.
The original FILE input is never rewritten, and renewal never follows a referral
or exceeds the original renewal lifetime.

AS identity regressions use encrypted wire replies over TCP/UDP, including
malformed ticket names, mismatched ticket metadata, nonce/ciphertext changes,
empty preauth lists and referrals before/after preauth. Assert both unchanged
credential state and absence of traffic to the referred realm. The AS changes
also pass the independent Samba AD and direct MIT trust matrices on both OSes.

References: RFC 4120 sections 3.1.2, 3.1.5, 3.3.3, 5.4.2 and 7.2;
RFC 6806 sections 6/7/13 (name changes and unauthenticated AS referrals);
RFC 2743 context lifetime;
RFC 2203 context creation/destruction. The configuration's requested lifetime is
not evidence of the lifetime actually granted by the KDC.

The error-29-only KRB_ERROR failover policy follows MIT's
[`check_for_svc_unavailable`](https://github.com/krb5/krb5/blob/master/src/lib/krb5/os/sendto_kdc.c).

Without explicit policy, direct and intermediate trust use `[domain_realm]`
and existing `realmLogin`. The separate
three-database MIT fixture uses KDC-side capaths for CLIENT -> MID -> NFS, with
no direct first-to-last trust. Authenticators retain the original client realm;
the encrypted-wire regression checks that identity and the body checksum, while
the real route test requires both intermediate-issued and home-issued TGTs.
This does not validate arbitrary/AD trust routes.

The GSS adapter separately parses the same configuration text with
`ParseCAPaths` before credentials/login. `TrustPaths` opts into an immutable
per-client route policy: home realm plus explicitly listed foreign services.
`GetServiceTicket` validates the route before cache lookup and requests each
adjacent TGT using the previous reply. It does not reuse foreign sessions or
renew a service ticket through the legacy cache path. Exact requested TGTs are
accepted; a substituted referral is rejected before insertion or further I/O.
An external FILE cache still contributes only the validated home TGT. The strict
profile subset and limits are documented in the
[current client trust-path contract](../../docs/AUTHENTICATION.md#client-trust-paths).
The GSS adapter's bounded file loader expands include/includedir into one pinned
snapshot before both authentication and trust-path parsing. The raw text parser
still rejects unresolved includes and modules, even without a local capaths
section, because an ignored external profile could contain policy. Executable
modules remain unsupported. An explicitly empty configuration never falls back
to a system file. The optional internal default file path uses the same snapshot
loader and policy parser.

TCP/UDP encrypted-wire tests assert the requested chain, no reuse of a foreign
TGT from another route, valid service-cache reuse and zero traffic/session/cache
insertion for a rejected referral. Real three-realm policy tests also verify
denials and withheld mutations when replacement rereads a changed policy.

When updating gokrb5, review these adapted source files against upstream.
Module vulnerability scanners cannot automatically attribute a copied client
function to its original module version.

KDC deadline checks consult both `Context.Err()` and the declared deadline.
Socket deadlines can fire before the context timer publishes its error; elapsed
budgets must still return `context.DeadlineExceeded` and prevent additional KDC
discovery/failover. A delayed-notification context reproduces this race without
relying on scheduler timing. The per-endpoint timeout and shared parent budget
are unchanged, and cancellation remains `context.Canceled`.

Portable mandatory FAST and certificate PKINIT are implemented in `as_fast*`
and `as_pkinit*`. They validate pinned identities and authenticated AS evidence
before adding a TGT. Private DH arithmetic uses `filippo.io/bigmod`; public group
validation may use `math/big`. Keep the independent negative controls and native
MIT KDC interoperability checks when changing these authentication paths.
