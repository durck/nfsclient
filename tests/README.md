# Test fixtures

Default regression checks are [documented here](../docs/DEVELOPMENT.md#local-self-check).
All service fixtures below are opt-in. Use explicit test-owned endpoints,
credentials and fresh output directories. Missing prerequisites cause skips;
passing default suites does not imply native interoperability.

## Fixture catalog

| Source directory | Profile / entry point |
| --- | --- |
| `ganesha/` | Isolated NFS-Ganesha; build its Dockerfile |
| `unfs/` | Independent UNFS3 TCP/UDP compatibility |
| `network/` | Native Windows/Linux reserved ports, NFS UDP fragmentation/MTU and isolated reply firewall; `run.py --target both` |
| `storage/` | Disposable kernel/QEMU ext4/XFS/Btrfs exports and Linux FAT32/exFAT publication; `TestNativeStorageRoots`, `TestNativeLocalPublication` |
| `nfsv2/` and `nfsv2/replacement/` | Bounded v2 ordinary operations and NFSACLv2 replacement |
| `nfsv2/gss/` | Stock-kernel NFSv2 GSS TCP/UDP, keytab/FILE and protected UDP fault controls; `TestV2GSSNative*` |
| `kerberos/` | MIT tickets/Ganesha; `TestKerberos*`, explicit `NFS_VIEWER_KRB5_*` inputs |
| `kcm-native/` | Real SSSD KCM/MIT/Ganesha selection and expiry lifecycle; `run.py --repository PATH --output PATH` |
| `kerberos/udp-repair/` | Separately named ntirpc protected-UDP repair image; stock failures stay separate |
| `kerberos-pkinit/` and `nfsv2/gss/` | MIT KDC/kernel fixtures for pure-Go FAST/PKINIT (`TestPureGoASNativeWire`, `TestPureGoASNativeInterop`, explicit `NFS_VIEWER_PUREGO_AS_*` inputs) and optional helper compatibility |
| `samba-ad/` | Samba AD static-principal mapping; does not certify Microsoft AD/PAC |
| `vfs/` | POSIX-backed authorization and separately built ACL-enabled server |
| `microsoft-ad/` | Existing protected Microsoft DC/domain guest; guarded scripts and recorded native runs |
| `tls/` | Kernel RPC-over-TLS with separately authenticated ALPN fixture daemon |
| `rdma/` | Software iWARP, AUTH_SYS inline profile |
| `pnfs/` | Gluster FILE layouts and DS approval mappings |
| `pnfs/lizardfs/` | Real multi-DS placement/concurrency and independent native oracle |
| `pnfs/lizardfs-protected/` | Native Windows/Linux krb5i/p MDS access and protected-backchannel refusal on the retained Ganesha 4.3 image; `run.py --output PATH`; no DS I/O certification |
| `pnfs/freebsd/` | Stock FreeBSD FILE/Flex, natural recalls, writes/publication |
| `nlm/freebsd/` and `nlm/reclaim/` | NLM TEST/locks and bounded Linux server-restart reclaim |
| `offload/` and `copy-from/` | Intra/inter-server v4.2 offload and byte/wire evidence |
| `reclaim-resume/` | Protected read recovery after a real server restart |

The opt-in Windows `TestSSPINativeCurrentLogonRPC` uses the real current-logon
SSPI provider for read-only Mount/GetAttr under krb5/i/p. Set
`NFS_VIEWER_SSPI=1` and explicitly provide `NFS_VIEWER_SSPI_HOST`, `_PRINCIPAL`,
`_SPN`, `_EXPORT` and `_VERSION` (each suffix uses the full `NFS_VIEWER_SSPI`
prefix). Optional `_TRANSPORT`, `_NFS_PORT`, `_MOUNT_PORT` and `_PORTMAP_PORT`
select transport/service endpoints. Run `go test ./internal/nfs -run
^TestSSPINativeCurrentLogonRPC$ -count=1` from a Windows logon with suitable
Kerberos credentials and an authorized export. No keytab/cache substitution is
performed. This positive native test is not part of the default checkpoint;
native-call refusal/ABI tests and portable encrypted RPC tests are separate evidence.

## Docker build prerequisites

Run these commands from the project root. They build disposable images;
they do not start services. The root `.dockerignore` excludes `bin/` and
generated caches from root-context builds while retaining the fixture sources.

```sh
docker build -t nfs-viewer-ganesha-test tests/ganesha
docker build -t nfs-viewer-kerberos-test tests/kerberos
docker build -t nfs-viewer-vfs-test -f tests/vfs/Dockerfile .
docker build --target build -t nfs-viewer-vfs-acl-build -f tests/vfs/Dockerfile.acl .
docker build -t nfs-viewer-kerberos-udp-repaired tests/kerberos/udp-repair
```

## Local storage and network checks

For native network checks, first build the `unfs/` image, then
`docker build --build-context packages=. -f tests/network/Dockerfile -t nfs-viewer-network-test .`.
Offline builds use an authenticated Ubuntu repository from
`kcm-native/prepare-repository.py` as the `packages` context and
`--build-arg OFFLINE_REPOSITORY=1`. Run
`python -B tests/network/run.py --target both` on Windows. The runner creates
and removes its server and Linux test-client containers; only the server has
`NET_ADMIN` in its own namespace. It changes no host
MTU/firewall. Default loopback ports 19449/19448/19477 are configurable.
`--windows-tcp-exhausted` is only for an independently confirmed occupied TCP
900–1023 range; it verifies refusal, not successful TCP binding. MTU 900 reads
above 512 bytes use TCP-seeded files and count NFS UDP fragments on the server
interface. The separate reduced-MTU write case verifies bounded non-replay and
records actual server bytes even when the path drops the datagram.

Storage uses guest-owned raw images, never host block devices. Its Dockerfile
requires the existing kernel fixture base and a signed Debian `packages` build
context prepared by `storage/prepare-repository.py` and the package downloader
in `nfsv2/replacement/`. The opt-in session tests select explicit
`NFS_VIEWER_STORAGE_HOST`, `NFS_VIEWER_STORAGE_PORT` and
`NFS_VIEWER_STORAGE_MOUNT_PORT`; only the guest sets
`NFS_VIEWER_STORAGE_LOCAL_DIR` to its freshly formatted destination mounts.
`storage/verify-native.py EVIDENCE_DIR` checks the independent guest file hashes.
The inherited kernel fixture includes the earlier NFSv2 compatibility module;
this is native kernel/filesystem evidence, not certification of a pristine
distribution module.

## Disposable Ganesha smoke check

After building `nfs-viewer-ganesha-test` above, launch its in-memory export:

```sh
docker run -d --rm --name nfs-viewer-ganesha-fixture -p 127.0.0.1:12049:2049/tcp -p 127.0.0.1:12048:20048/tcp -p 127.0.0.1:12049:2049/udp -p 127.0.0.1:12048:20048/udp nfs-viewer-ganesha-test
```

Wait seven seconds for its six-second grace period. Use unused ports and a
unique container name; adjust both TCP and UDP selectors if changing ports.
No privileged container or host export is needed. Restarting loses its data;
keep files below the MEM backend's approximately 1 MiB per-inode buffer.

PowerShell, from the project root (restores the previous selectors):

```powershell
$fixtureVars = @('NFS_VIEWER_TEST_PORT', 'NFS_VIEWER_TEST_MOUNT_PORT', 'NFS_VIEWER_TEST_UDP_PORT', 'NFS_VIEWER_TEST_UDP_MOUNT_PORT')
$savedFixtureEnv = @{}
foreach ($name in $fixtureVars) { $savedFixtureEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
  $env:NFS_VIEWER_TEST_PORT = '12049'
  $env:NFS_VIEWER_TEST_MOUNT_PORT = '12048'
  $env:NFS_VIEWER_TEST_UDP_PORT = '12049'
  $env:NFS_VIEWER_TEST_UDP_MOUNT_PORT = '12048'
  go test -race -count=1 ./internal/cli -run '^TestGaneshaVersions$'
  if ($LASTEXITCODE -ne 0) { throw 'Ganesha smoke check failed' }
} finally {
  foreach ($name in $fixtureVars) { [Environment]::SetEnvironmentVariable($name, $savedFixtureEnv[$name], 'Process') }
  docker stop nfs-viewer-ganesha-fixture
}
```

Linux, from the project root:

```sh
(trap 'docker stop nfs-viewer-ganesha-fixture' EXIT
NFS_VIEWER_TEST_PORT=12049 NFS_VIEWER_TEST_MOUNT_PORT=12048 NFS_VIEWER_TEST_UDP_PORT=12049 NFS_VIEWER_TEST_UDP_MOUNT_PORT=12048 go test -race -count=1 ./internal/cli -run '^TestGaneshaVersions$')
```

This checks v4.0/4.1/4.2, v3, automatic selection and v3/UDP. Omitting selectors
skips the external fixture. The MEM backend exposes no ACL, so overwrite checks
require safe refusal and unchanged original bytes; positive policy-preserving
replacement needs an ACL-capable fixture. `NFS_VIEWER_TEST_IDLE=1` optionally adds an eight-second
wait per v4 case to exercise the six-second lease. The normal self-check removes
fixture selectors, so use the direct `go test` command for this opt-in smoke run.

## Recording the README demo

Build the Windows client using the root README, then start a **fresh** disposable
Ganesha fixture as above and wait for its grace period. The optional recorder
requires Python with `pywinpty` (verified with 2.0.15) and `pyte` (0.8.2), and uses
a native Windows PTY with a UTF-8 console. It seeds example files, types into the interactive
client, captures unchanged terminal output with observed timestamps, and checks
the downloaded bytes. It refuses an existing `--work-dir` directory.
The extended scenario runs 34 commands in a 110-column, 32-row terminal:
help/remote working directory, navigation and Tab completion, text/hex previews, corporate/cloud
path hints, upload/download, links, permissions, moves and cleanup. Section
boundaries use the client's real Ctrl+L clear-screen handling. Seed files are
explicitly synthetic examples on a disposable server; captured UI is real.
The opening holds the connected prompt for 1.8 seconds and uses compact
`help ls` to avoid a scrolling help dump. Each typed character must appear on
the current terminal cursor row before the next key is sent, then remains
visible for at least 80 ms. Reading pauses after commands are capped at 1.5
seconds. Tab still inserts its real completion suffix.
Use a fresh neutral `--work-dir` outside the personal Windows profile. The demo
omits `id` and `lls`, which expose the absolute local directory. The recorder
rejects all absolute Windows drive/UNC paths and personal profile/username/hostname
matches before saving public media input; it does not redact recorded output.
The recording published with the README uses the v0.2.0 release binary.

```powershell
python -B tests/record_demo.py --binary bin/nfsclient-windows-amd64.exe --port 12049 --output bin/verification/readme-recording --work-dir C:/nfsclient-demo/files
python -B tests/prepare_demo_render.py bin/verification/readme-recording/demo.cast bin/verification/readme-recording/render.cast
agg --font-family Consolas --font-size 16 --theme asciinema --speed 1 --idle-time-limit 60 --last-frame-duration 0.1 bin/verification/readme-recording/render.cast bin/verification/readme-recording/demo.gif
ffmpeg -i bin/verification/readme-recording/demo.gif -vf "fps=30,pad=ceil(iw/2)*2:ceil(ih/2)*2" -c:v libx264 -pix_fmt yuv420p -crf 20 -movflags +faststart bin/verification/readme-recording/demo.mp4
```

Use [agg](https://github.com/asciinema/agg) 1.9.0 to render the captured stream.
The MP4 uses a constant 30 fps for predictable player timing, pads odd pixel
dimensions for H.264 compatibility, and preserves playback duration.
The render-only cast coalesces erase-only ConPTY events with a redraw
arriving within 150 ms, avoiding transient blank prompt frames. It preserves
every output byte and retains longer intentional pauses. The published
`demo.cast` remains the original stream with observed timestamps.
Run `python -B tests/test_prepare_demo_render.py` and
`python -B tests/test_record_demo.py` to check render and privacy boundaries.
Inspect representative frames before copying `demo.cast`, `demo.gif`, and `demo.mp4` to
`docs/assets/`; update the README duration/chapter offsets from actual evidence. Keep recorder
evidence in ignored `bin/verification/`, and stop the disposable server afterward.
Review `typed_inputs` in `evidence.json` for observed chapter start times and
`terminal-output.txt` for errors, link targets and final directory contents.
`visible_prefix_checks` records observed per-character screen states; verify
these states also survive the render-only event coalescing before publication.
Keep raw evidence private and remove only the freshly created demo work directory
after confirming its resolved path is the intended neutral fixture directory.
On every container restart, check the mapped port again if Docker assigned it.

## Other fixture prerequisites

Check each Dockerfile's base image before building. Keep server-specific repairs
in separately named fixture images; do not replace host libraries/services.
Publish test listeners on loopback or the explicitly selected private network.
For the single-Ganesha Windows Gluster example, MDS port `12049` and approved
DS target `127.0.0.1:12049` refer to the same published endpoint; the advertised
container endpoint remains its actual `IP:2049`. Never infer DS approvals.

`NFS_VIEWER_TEST_BINARY` selects an explicit standalone release for eligible
CLI tests. Credential fixture selectors use absolute private paths. Obtain
current credentials for the selected profile/enctype; never print keys/cache
contents or inherit unrelated selector variables accidentally. Real-server
runners/verifiers under the listed directories own their exact options and
evidence contracts. Use their `--help` where provided; inspect guards before
running a native procedure.

## Native fixtures

The retained AD lab has already been joined and its separate interop accounts
provisioned. Do not rerun installation, promotion, account creation or domain
join, reset keys, bypass domain-owned guest guards or stop the active VM for
cleanup. Machine Kerberos, domain identities, ordinary-user NFS and Windows
client checkpoints are distinct evidence stages. Recorded AD/knfsd results
do not certify arbitrary NAS/forest/PAC or positive native LSA import.

FreeBSD pnfs11 natural-recall refusals remain historical; later pnfs12/pnfs13
verify repeated DS sessions and complete publication within their profiles.
Later write/Flex results have separate bounds. Failed stock Ganesha/ntirpc/tlshd
runs remain failed baselines even when isolated repair fixtures pass.

## Detailed recipes and historical inputs

The complete former fixture READMEs, provisioning stages, hashes and native
reproduction recipes are retained in the pre-consolidation documentation
archive, with their original `tests/...` paths. Locate it through
[historical evidence](../docs/DEVELOPMENT.md#historical-evidence) and the
consolidation receipt. They describe specific authorized disposable/native
checkpoints, not an instruction to reprovision the retained AD guests.
Restore authenticated build contexts or selected archived evidence before old
recipes that need them. A TLS `bin/tls-build` context is not generated by Docker;
pnfs10 verifiers require the directory containing their complete input set.
New runs must verify current state and use fresh output paths.
