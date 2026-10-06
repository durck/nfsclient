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
