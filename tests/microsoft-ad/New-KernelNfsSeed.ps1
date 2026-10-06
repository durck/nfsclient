[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$TestSHA256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$BinarySHA256,
    [switch]$Kerberos,
    [switch]$GssProxy,
    [switch]$Nfs3Gss,
    [switch]$Nfs3ACLRead,
    [switch]$Nfs3ACLSet,
    [switch]$AuthSysOnGssGuest,
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$Nfs3UdpDiagnosticSHA256,
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$LargeTokenHelperSHA256,
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')][string]$RunId = ('kernel-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')),
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
if ($Nfs3Gss) { $GssProxy = $true }
if ($GssProxy) { $Kerberos = $true }
if ($AuthSysOnGssGuest -and ($Kerberos -or $LargeTokenHelperSHA256 -or $Nfs3UdpDiagnosticSHA256)) { throw 'AuthSysOnGssGuest cannot select Kerberos, large-token or UDP diagnostic profiles.' }
if ($Nfs3Gss -and $LargeTokenHelperSHA256) { throw 'Nfs3Gss is a separate supported-profile matrix; it cannot include the v4 large-token suite.' }
if ($Nfs3UdpDiagnosticSHA256 -and !$Nfs3Gss) { throw 'The protected-UDP diagnostic requires the explicit Nfs3Gss profile.' }
if ($LargeTokenHelperSHA256 -and !$GssProxy) { throw 'Large-token fixture requires the explicit GssProxy profile.' }
if ($Nfs3ACLRead -and ((!$AuthSysOnGssGuest -and !$Nfs3Gss) -or $LargeTokenHelperSHA256 -or $Nfs3UdpDiagnosticSHA256)) { throw 'Nfs3ACLRead requires an AUTH_SYS adapter or Nfs3Gss profile without large-token/UDP diagnostics.' }
if ($Nfs3ACLSet -and ((!$AuthSysOnGssGuest -and !$Nfs3Gss) -or $Nfs3ACLRead -or $LargeTokenHelperSHA256 -or $Nfs3UdpDiagnosticSHA256)) { throw 'Nfs3ACLSet requires an AUTH_SYS adapter or Nfs3Gss profile without ACL-read/large-token/UDP diagnostics.' }
if ($Kerberos -and !$PSBoundParameters.ContainsKey('RunId')) { $RunId = 'kernel-gss-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') }
if ($Kerberos -and $RunId -notmatch '^kernel-gss-[a-z0-9-]{1,48}$') { throw 'Kerberos RunId must start with kernel-gss- and have a bounded unique suffix.' }
if ($AuthSysOnGssGuest -and $RunId -notmatch '^kernel-(?!gss-)[a-z0-9-]{1,48}$') { throw 'AUTH_SYS adapter RunId must use a bounded kernel- suffix outside the kernel-gss- namespace.' }
$runs = Join-Path $runtime 'kernel-runs'
$run = Join-Path $runs $RunId
foreach ($path in @($runs,$run)) { Assert-LabRegularPath $path }
if (Test-Path -LiteralPath $run) { throw 'A kernel run directory already exists; never replace its media or evidence.' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$testDirectory = if ($Kerberos) { 'bin/kernel-gss-check' } else { 'bin/kernel-check' }
$test = Join-Path (Join-Path $repo $testDirectory) 'cli.test'
$binary = Join-Path $repo 'bin/nfs-viewer-linux-amd64'
foreach ($path in @((Join-Path $repo $testDirectory),$test,$binary)) { Assert-LabRegularPath $path }
if ((Get-FileHash -LiteralPath $test).Hash -ne $TestSHA256 -or (Get-FileHash -LiteralPath $binary).Hash -ne $BinarySHA256) { throw 'Artifacts do not match the parent-reviewed build hashes.' }
$packageProfile = if ($GssProxy) { 'kernel-gssproxy' } elseif ($Kerberos) { 'kernel-gss' } else { 'posix-acl' }
$bundleName = if ($GssProxy) { 'linux-gssproxy-packages' } elseif ($Kerberos) { 'linux-gss-packages' } else { 'linux-acl-packages' }
$seedBundleName = if ($Kerberos) { 'gss-bundle' } else { 'acl-bundle' }
$aclBundle=Join-Path $runtime $bundleName
Assert-LabRegularPath $aclBundle
if (!(Test-Path -LiteralPath (Join-Path $aclBundle 'verified.json'))) { throw 'Prepare the authenticated posix-acl package bundle before the kernel ACL run.' }
foreach ($path in @(Get-ChildItem -LiteralPath $aclBundle -Recurse -Force)) { Assert-LabRegularPath $path.FullName }
& docker run --rm --network none --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$aclBundle,target=/bundle,readonly" nfs-viewer-msad-package-tools python3 /scripts/verify-linux-bundle.py check /bundle --profile $packageProfile
if ($LASTEXITCODE) { throw 'ACL bundle authentication failed before ISO creation.' }
$seed = Join-Path $run 'seed'
New-Item -ItemType Directory -Path $seed -Force | Out-Null
Copy-Item -LiteralPath $test -Destination (Join-Path $seed 'cli.test')
Copy-Item -LiteralPath $binary -Destination (Join-Path $seed 'nfs-viewer-linux-amd64')
$seedBundle=Join-Path $seed $seedBundleName
New-Item -ItemType Directory -Path $seedBundle | Out-Null
foreach ($leaf in @('debs','provenance','provenance.json','Packages','verified.json')) { Copy-Item -LiteralPath (Join-Path $aclBundle $leaf) -Destination (Join-Path $seedBundle $leaf) -Recurse }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'verify-linux-bundle.py') -Destination (Join-Path $seed 'verify-linux-bundle.py')
if ((Get-FileHash -LiteralPath (Join-Path $seed 'cli.test')).Hash -ne $TestSHA256 -or (Get-FileHash -LiteralPath (Join-Path $seed 'nfs-viewer-linux-amd64')).Hash -ne $BinarySHA256) { throw 'Artifact changed during snapshot copy.' }
$hashes = @{ 'cli.test'=$TestSHA256.ToUpperInvariant(); 'nfs-viewer-linux-amd64'=$BinarySHA256.ToUpperInvariant() }
if ($LargeTokenHelperSHA256) {
    $helperDirectory = Join-Path $repo 'bin/kernel-large-tgt-smoke'
    $helper = Join-Path $helperDirectory 'gss-large-tgt'
    foreach ($path in @($helperDirectory,$helper)) { Assert-LabRegularPath $path }
    if ((Get-FileHash -LiteralPath $helper).Hash -ne $LargeTokenHelperSHA256) { throw 'Large-token helper differs from reviewed artifact.' }
    Copy-Item -LiteralPath $helper -Destination (Join-Path $seed 'gss-large-tgt')
    if ((Get-FileHash -LiteralPath (Join-Path $seed 'gss-large-tgt')).Hash -ne $LargeTokenHelperSHA256) { throw 'Large-token helper changed during snapshot copy.' }
    $hashes['gss-large-tgt'] = $LargeTokenHelperSHA256.ToUpperInvariant()
}
if ($Nfs3UdpDiagnosticSHA256) {
    $diagnostic = Join-Path (Join-Path $repo $testDirectory) 'nfs.test'
    Assert-LabRegularPath $diagnostic
    if ((Get-FileHash -LiteralPath $diagnostic).Hash -ne $Nfs3UdpDiagnosticSHA256) { throw 'Protected-UDP diagnostic differs from the reviewed artifact.' }
    Copy-Item -LiteralPath $diagnostic -Destination (Join-Path $seed 'nfs.test')
    if ((Get-FileHash -LiteralPath (Join-Path $seed 'nfs.test')).Hash -ne $Nfs3UdpDiagnosticSHA256) { throw 'Protected-UDP diagnostic changed during snapshot copy.' }
    $hashes['nfs.test'] = $Nfs3UdpDiagnosticSHA256.ToUpperInvariant()
}
$useGssRunner = $Kerberos -or $AuthSysOnGssGuest
$runnerName = if ($useGssRunner) { 'run-kernel-gss.py' } else { 'run-kernel-nfs.py' }
$runner = Join-Path $PSScriptRoot $runnerName
$scope = if ($Nfs3Gss) { 'Linux guest loopback, kernel NFSv3 MIT GSS supported profiles, no Microsoft AD' } elseif ($Kerberos) { 'Linux guest loopback, kernel NFS MIT GSS, no Microsoft AD' } else { 'Linux guest loopback, kernel NFS AUTH_SYS, no Microsoft AD' }
$metadata = @{ RunId=$RunId; Hashes=$hashes; RunnerSHA256=(Get-FileHash -LiteralPath $runner).Hash; CreatedUtc=[DateTime]::UtcNow.ToString('o'); Scope=$scope; }
$metadata.NFS3ACLRead = [bool]$Nfs3ACLRead
$metadata.NFS3ACLSet = [bool]$Nfs3ACLSet
if ($Nfs3ACLRead) { $metadata.Scope = 'Linux guest loopback, kernel NFSv3 NFSACL GETACL client checks, no SETACL/replacement or Microsoft AD' }
if ($Nfs3ACLSet) { $metadata.Scope = 'Linux guest loopback, kernel NFSv3 NFSACL SETACL/readback API checks on test-created objects, no replacement/CLI setter or Microsoft AD' }
$libraryYaml = ''
if ($useGssRunner) {
    $metadata.Security = if ($AuthSysOnGssGuest) { 'kernel-auth-sys' } else { 'kernel-gss' }
    $metadata.AuthSysOnGssGuest = [bool]$AuthSysOnGssGuest
    $metadata.GSSAcceptor = if ($AuthSysOnGssGuest) { 'none' } elseif ($GssProxy) { 'gssproxy' } else { 'svc-gssd' }
    $metadata.SupplementaryGroups = [bool]$GssProxy
    $metadata.LargeToken = [bool]$LargeTokenHelperSHA256
    $metadata.NFS3GSS = [bool]$Nfs3Gss
    $metadata.NFS3UDPDiagnostic = [bool]$Nfs3UdpDiagnosticSHA256
    $baseRunner = Join-Path $PSScriptRoot 'run-kernel-nfs.py'
    $metadata.BaseRunnerSHA256 = (Get-FileHash -LiteralPath $baseRunner).Hash
    $library = (Get-Content -LiteralPath $baseRunner -Raw).Replace("`r`n","`n").TrimEnd("`n")
    $libraryIndented = ($library.Split("`n") | ForEach-Object { '      '+$_ }) -join "`n"
    $libraryYaml = @"
  - path: /usr/local/sbin/run-kernel-nfs.py
    owner: root:root
    permissions: '0600'
    content: |
$libraryIndented
"@
}
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $seed 'run.json') -Encoding utf8NoBOM
$utf8 = [Text.UTF8Encoding]::new($false)
$script = (Get-Content -LiteralPath $runner -Raw).Replace("`r`n","`n").TrimEnd("`n")
$indented = ($script.Split("`n") | ForEach-Object { '      '+$_ }) -join "`n"
$runnerArguments = if ($AuthSysOnGssGuest) { ', --auth-sys' } else { '' }
$user = @"
#cloud-config
hostname: nfs
fqdn: nfs.msad.nfs.test
manage_etc_hosts: true
preserve_hostname: false
disable_root: true
ssh_pwauth: false
ssh_deletekeys: false
ssh:
  emit_keys_to_console: false
users: []
package_update: false
package_upgrade: false
write_files:
  - path: /usr/local/sbin/nfs-lab-kernel-check
    owner: root:root
    permissions: '0700'
    content: |
$indented
$libraryYaml
runcmd:
  - [python3, /usr/local/sbin/nfs-lab-kernel-check$runnerArguments]
final_message: 'Kernel NFS fixture ended; inspect evidence and cleanup result. No AD interoperability claim.'
power_state:
  mode: poweroff
  delay: now
  timeout: 1200
  condition: true
"@
[IO.File]::WriteAllText((Join-Path $seed 'user-data'),$user.Replace("`r`n","`n")+"`n",$utf8)
[IO.File]::WriteAllText((Join-Path $seed 'meta-data'),"instance-id: nfs-viewer-$RunId`nlocal-hostname: nfs`n",$utf8)
$network = Join-Path $runtime 'linux-seed/network-config'
Assert-LabRegularPath (Join-Path $runtime 'linux-seed')
Assert-LabRegularPath $network
Copy-Item -LiteralPath $network -Destination (Join-Path $seed 'network-config')
& docker run --rm --network none --mount "type=bind,source=$seed,target=/seed,readonly" nfs-viewer-msad-package-tools cloud-init schema -c /seed/user-data
if ($LASTEXITCODE) { throw 'Kernel seed cloud-init schema failed.' }
& docker run --rm --network none --mount "type=bind,source=$run,target=/run-output" nfs-viewer-msad-package-tools genisoimage -quiet -output /run-output/kernel.iso -volid cidata -joliet -rock /run-output/seed
if ($LASTEXITCODE) { throw 'Kernel fixture ISO generation failed.' }
$metadata.ISO = Join-Path $run 'kernel.iso'
$metadata.ISOSHA256 = (Get-FileHash -LiteralPath $metadata.ISO).Hash
$metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $run 'metadata.json') -Encoding utf8NoBOM
Write-Output ($metadata | ConvertTo-Json -Depth 4)
