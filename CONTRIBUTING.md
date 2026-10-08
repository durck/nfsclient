# Contributing

For bugs, include the client version or source revision, OS, server implementation,
NFS version, transport and authentication profile, exact command, expected result
and a minimal reproduction. Redact addresses and identities when private. Never
attach credentials, keytabs, ticket caches, private keys or unredacted packet
captures. Follow [SECURITY.md](SECURITY.md) for suspected vulnerabilities.

Discuss substantial new protocol profiles in an issue before implementation.
Keep changes focused, describe observable behavior and its limits, and update the
owning [guide](README.md#documentation-and-development) and [changelog](CHANGELOG.md). Use English for code,
comments, documentation and commit subjects. Keep discussion respectful and
focused on the work.

Run `gofmt` on changed Go files and the [local self-check](docs/DEVELOPMENT.md#local-self-check).
CI checks Windows and Linux, static analysis and known vulnerabilities. Add
regression coverage for confirmed bugs and meaningful protocol behavior; do not
enable external fixtures in default tests. Mark native interoperability claims
with the server and configuration actually tested. Include the commands and
results in your pull request, including any checks that could not run.

Do not commit `bin/`, credentials, local environment files, generated logs or VM
images. Contributions must be yours to submit under the project license; retain
upstream notices in adapted code.
