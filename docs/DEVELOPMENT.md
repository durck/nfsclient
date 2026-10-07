# Development, verification and retained evidence

## Local self-check

Run from the project root. Python 3, Go and a supported C compiler are required.
The container variant also requires Docker and a populated host module cache:
run `go mod download` before the first container check and after dependency
changes, because the container mounts that cache read-only.

```powershell
go mod download
python -B tests/selfcheck.py
python -B tests/selfcheck.py --linux-container
```

The native run performs Go vet/race, Python evidence-reader checks, a CGO-free
amd64 build/help check and affected release-process scenarios. Race tests need
CGO enabled and a supported C compiler; scope CGO=0 to release builds only.
On Windows, race-test packages run sequentially (`-p=1`): journal stress tests
perform thousands of durable flushes and can otherwise starve another package's
subprocess crash-boundary watchdog. All tests and race instrumentation remain
enabled; concurrency within each package is unchanged.
Linux Go checks use temporary `golang:1.26.8` Docker containers with `--rm`,
read-only source/module mounts and a reusable build cache. Inherited NFS_/KRB5_
fixture selectors are removed. No real NAS/domain/hardware fixture is enabled.
Logs and summaries are written to ignored `bin/verification/`.

## Continuous integration

GitHub Actions runs the native self-check on Windows and Linux, checks Go
formatting, runs staticcheck 2026.1 and scans reachable dependency vulnerabilities
with govulncheck. Actions are pinned to commit IDs; analysis tools are pinned to
versions and compiled with the project's selected Go toolchain.

To run the additional analysis locally:

```text
go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
staticcheck ./...
govulncheck ./...
```

Successful CI builds upload the platform binary, project license, third-party
notices and SHA256SUMS as development artifacts retained for 14 days. CI does
not create tags or GitHub Releases. Download instructions are in the
[README](../README.md#install). Published releases retain versioned archives
separately from the expiring CI artifacts.
Test event totals include parent tests and subtests. A skipped native fixture is
not evidence of interoperability. Review the generated summary and individual
logs; historical totals do not certify a changed source tree.

Separate opt-in MIT KDC checks cover FAST/PKINIT and OSD GSS/privacy/TLS matrices;
the KDC is native while NFS and OSD peers are scripted. Positive native SSPI
domain RPC, persistent kernel KEYRING and native OSD/storage vendor behavior
remain unverified. The [fixture catalog](../tests/README.md) lists opt-in families.

## Historical evidence

Build outputs, logs, local lab inputs and historical receipts belong under
ignored `bin/` or a separate local archive. They are not needed to build or run
the default self-check from a source checkout. Reproducing a historical native
run requires its original inputs; current support is described by
[compatibility](COMPATIBILITY.md), not by an archived binary or old test count.
Keep temporary Go reproducers as `.go.txt` or in underscore-prefixed directories:
Git ignore rules do not exclude `.go` files from `go test ./...` or `go vet ./...`.

Current executable names are `bin/nfsclient-windows-amd64.exe` and
`bin/nfsclient-linux-amd64`. Distributions must include the root `LICENSE` and
`bin/THIRD-PARTY-LICENSES.txt`; generate the latter with
`python -B tests/package_licenses.py` or the self-check.

Preview local artifact cleanup with `python -B tests/archive_artifacts.py`.
Use `--apply` only after clients/checks finish and after reviewing the selection.
The script moves entries to an external local archive; it does not free space.
Its fixed keep-list retains the AD fixture, current binaries, licenses,
verification directory and archive pointer. Every other top-level `bin/` entry
is selected, including newly added runtime inputs. Containment checks reject
reparse points, and an empty selection preserves the previous archive pointer.
Docker state is unaffected; default self-check containers remove themselves.

## Engineering notes

Keep independent wire oracles separate from client constants. Test legal peers
and malformed/forbidden controls; high test counts alone cannot establish
interoperability. Distinguish issued-but-unknown RPCs from local pre-issue refusal,
and recheck state immediately before publishing recovered state or file bytes.
Use protocol-specific packet counters for fragmentation evidence: global IP
counters can include the fixture's own control traffic. On Windows, Winsock
address-in-use is distinct from the generic `syscall.EADDRINUSE` constant.
An NSM notification receipt is not a barrier for delayed lockd cleanup. Likewise,
an unrelated successful SEQUENCE must never complete a pending OPEN/LOCK release
intent; durable resource transitions require their exact saved operation.
Durable slot confirmation, lock retirement and notification completion are
separate journal boundaries. Successful recovery polling must persist renewed
lease evidence from request start, and bounded journals must not exhaust storage
solely while waiting for a supported long operation. A crash fixture must retain open file ownership
through process termination; GC can otherwise release its lock early.
A checkpoint message is not a crash barrier while background lease renewal is
active: another SEQUENCE can mark the journal pending before the process exits.
Lease-renewal crash tests therefore verify durable confirmation in the actual
crash journal and stop at an observed cached WRITE boundary. A separate pending
renewal case checks that unresolved state remains quarantined.
Restore ownership before final mode/ACL, because chown may clear special bits.

Credential deep copies must retain fields deliberately omitted from JSON:
gokrb5 encryption keys use `json:"-"`. Renewal copies and fingerprints therefore
handle key bytes explicitly, without writing or logging them. Validate renewed
ticket flags, current validity and session-key lengths before replacing a live
credential. Cancel connection-owned KDC work before waiting on an RPC mutex
that foreground credential replacement may hold.
For negotiated NFSv4 channels, use the complete RPC/compound budget once;
subtracting a legacy WRITE-payload allowance again can reject legal metadata.
Operation-specific error results still carry XDR bodies: SETATTR returns attrsset
on failure and LOCKT DENIED returns a conflict owner/range. Consume and validate
these before checking trailing bytes; a valid refusal must not poison the session.

Always read/write documentation with explicit UTF-8 and inspect visible text:
valid Unicode can already contain mojibake. Generated Unix scripts also need
explicit LF newlines. Foreground APIs stay serial even when internal pNFS work
is parallel; callbacks must not redefine the transfer's pinned identity.

## Documentation maintenance

Update the owning topical guide and compatibility row when behavior changes.
Keep README short. PLAN owns client implementation scope; this file owns verification
and artifact handling. Fixture procedures have one catalog. Record runtime logs,
review reports and chronological evidence in ignored artifacts, rather than
adding a Markdown file per stage. Add a guide only for a distinct user-facing
topic that cannot fit an existing guide; use contents for long references.
