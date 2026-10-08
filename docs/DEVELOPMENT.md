# Development, verification and retained evidence

## Build from source

Go 1.26 is required; `go.mod` selects patched Go 1.26.8 automatically.

Clone the repository and run the build commands from its directory:

```sh
git clone https://github.com/durck/nfsclient.git
cd nfsclient
```

```powershell
$previousCGOEnabled = $env:CGO_ENABLED
try {
  $env:CGO_ENABLED = "0"
  go build -trimpath -o bin/nfsclient-windows-amd64.exe .
} finally {
  $env:CGO_ENABLED = $previousCGOEnabled
}
.\bin\nfsclient-windows-amd64.exe nfs.example.test --export /data
```

```sh
CGO_ENABLED=0 go build -trimpath -o bin/nfsclient-linux-amd64 .
./bin/nfsclient-linux-amd64 nfs.example.test --export /data
```

Launching without arguments displays help. By default, AUTH_SYS/TCP probes
4.2, 4.1, 4.0, 3 and 2. Select `--nfs-version` explicitly to require a version.
NFSv4 uses the server's pseudo-root; v2/v3 use export discovery/MOUNT.

Before redistributing binaries, run `python -B tests/package_licenses.py` and
include the root `LICENSE` and generated `bin/THIRD-PARTY-LICENSES.txt`. It includes all modules
linked into either platform, the Go runtime and local GSS/Kerberos adaptations.
The self-check generates this file automatically.

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

## Development downloads

Development builds are also available from successful runs in
[GitHub Actions → CI](https://github.com/durck/nfsclient/actions/workflows/ci.yml).
Under **Artifacts**, select `nfsclient-Windows-amd64` or `nfsclient-Linux-amd64`;
`checks-*` contains verification logs. CI artifacts expire after 14 days.

## Continuous integration

GitHub Actions runs the native self-check on Windows and Linux, checks Go
formatting, runs staticcheck 2026.1 and scans reachable dependency vulnerabilities
with govulncheck. Actions are pinned to commit IDs; analysis tools are pinned to
versions and compiled with the project's selected Go toolchain.

To run the additional analysis locally:

```sh
go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
staticcheck ./...
govulncheck ./...
```

Successful CI builds upload the platform binary, project license, third-party
notices and SHA256SUMS as development artifacts retained for 14 days. CI does
not create tags or GitHub Releases. See [development downloads](#development-downloads) for artifact names
and the [README](../README.md#install) for release downloads. Published releases retain direct executables and
versioned archives separately from the expiring CI artifacts.

To publish a release, update the changelog and README download links, run the
local checks, and push the release commit and its version tag. Require successful
Windows/Linux CI for that exact commit. Download its `nfsclient-Windows-amd64`
and `nfsclient-Linux-amd64` artifacts and verify the included `SHA256SUMS` files.
Package those unchanged binaries and notices into versioned ZIP/tar.gz archives;
preserve the Linux executable mode. Also publish both executables directly with
separate license files, and generate release checksums covering the direct
executables, archives and license files. Verify every asset, publish them with
release notes identifying the source commit and CI run, then verify the published
tag and downloadable assets.

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

## Documentation maintenance

Update the owning topical guide and compatibility row when behavior changes.
Keep README short; it links to five task-oriented guides. This file owns
verification and artifact handling. Completed plans belong in Git history.
Fixture procedures have one catalog. Record runtime logs,
review reports and chronological evidence in ignored artifacts, rather than
adding a Markdown file per stage. Add a guide only for a distinct user-facing
topic that cannot fit an existing guide; use contents for long references.
