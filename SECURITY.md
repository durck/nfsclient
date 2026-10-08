# Security policy

Security fixes target the current development branch. There are no separately
maintained release branches or guaranteed response times at present.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** option when private
reporting is enabled. If it is unavailable, ask the maintainer for a private
contact channel without disclosing the vulnerability in a public issue. Do not
post an exploit, credentials or private infrastructure details publicly.

Provide the affected revision, OS and server versions, protocol/security profile,
minimal reproduction, expected security boundary and observed impact. Use dummy
identities and disposable data. Never send real keytabs, ticket caches, private
keys or passwords. Share sensitive diagnostic material only through an agreed
private channel.

## Security boundaries

See [authentication](docs/AUTHENTICATION.md), [transport](docs/AUTHENTICATION.md#version-and-transport-selection) and
[compatibility](docs/COMPATIBILITY.md) for supported profiles and explicit limits.
AUTH_SYS does not authenticate a user cryptographically. `--tls-insecure` disables
certificate verification. Server authorization remains authoritative, and
advisory locks do not isolate other clients. The client refuses unsupported or
uncertain recovery; this does not imply a remote mutation was rolled back.
