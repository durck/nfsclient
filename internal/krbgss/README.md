# Local Kerberos GSS adapter

The original `.go` files and `LICENSE` are copied from
`github.com/bodgit/gssapi` v0.0.4 (BSD-3-Clause, Matt Dainty). Preserve the license
when distributing source or binaries. Most files retain upstream behavior;
`privacy.go` adds confidential RFC 4121 Wrap/Unwrap using gokrb5 AES crypto
profiles. It does not implement AES, key derivation or message authentication.

The local package is needed because upstream has no confidential Wrap API and
does not expose context keys. No reflection, unsafe access or module-cache
patch is used. Key material stays internal. Privacy initially accepts only
AES128/256 CTS HMAC-SHA1-96 and requires confidentiality context flags.

Primary references: RFC 4121 sections 2 and 4.2 (direction/key usages, subkey
priority, encrypted header copy, EC/RRC); RFC 2203 section 5.3.2.3 (RPC privacy
body). See the parent project's tests/kerberos for real MIT/Ganesha validation.
Unit tests use explicitly synthetic keys; never put realm keytabs here.

`acceptor.go` honors `WithKeytab` before system keytab discovery. The opt-in
pNFS MIT-ticket matrix exercises explicit acceptor keytabs on Windows/Linux;
the acceptor is used in protocol tests, not as an NFS server in the client.

`channel_binding.go` implements copied application bindings using the RFC 4121
authenticator hash and GSS_C_AF_NULLADDR address types. The initiator rebuilds
the authenticator with the upstream encryption API; no encryption algorithm is
implemented here. The strict local acceptor checks checksum framing, binding
and unsupported delegation before reading flags. The native MIT GSS oracle
independently accepts matching TLS exporter bindings and rejects mismatches.

`initiator.go` additionally uses the local `internal/krbclient` adaptation for
cancelable KDC calls, no background TGT renewal, failed-login cleanup and the
authenticated service-ticket endtime. The AP_REQ builder still delegates to
upstream spnego using a credential-only client adapter (no network calls).
Its DNS option passes connection-scoped server/TCP settings to the local client;
it does not rewrite the explicit service principal or global resolver settings.
It parses bounded client `[capaths]` from the same configuration text before
loading credentials or sending AS/TGS requests. Both an explicit config and
the internal default-file loader use this path; an explicitly empty config
fails instead of falling back to an ambient file. NFS context replacement
constructs a fresh initiator and rereads the selected policy.

`ccache.go` parses explicitly selected FILE format 3/4 caches with bounds before
credential use; it avoids the upstream unchecked-slice parser. Default principal
and TGT validity are checked, and no ambient cache or secret-file dump is used.
