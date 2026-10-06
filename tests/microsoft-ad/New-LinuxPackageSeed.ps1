[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$bundle = Join-Path $runtime 'linux-packages'
$seed = Join-Path $runtime 'linux-package-seed'
$media = Join-Path $runtime 'linux-media'
foreach ($path in @($bundle,$seed,$media)) { Assert-LabRegularPath $path }
if (!(Test-Path -LiteralPath (Join-Path $bundle 'verified.json'))) { throw 'Authenticate the complete package bundle first.' }
$iso = Join-Path $media 'packages.iso'
Assert-LabRegularPath $iso
if (Test-Path -LiteralPath $iso) { throw 'Package ISO exists; refusing to replace existing installation media.' }
foreach ($item in @(Get-ChildItem -LiteralPath $bundle -Recurse -Force)) { Assert-LabRegularPath $item.FullName }
& docker run --rm --network none --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$bundle,target=/bundle,readonly" nfs-viewer-msad-package-tools python3 /scripts/verify-linux-bundle.py check /bundle
if ($LASTEXITCODE -ne 0) { throw 'Offline bundle reauthentication failed.' }
New-Item -ItemType Directory -Path $seed -Force | Out-Null
foreach ($leaf in @('user-data','meta-data','network-config')) { Assert-LabRegularPath (Join-Path $seed $leaf) }
$utf8 = [Text.UTF8Encoding]::new($false)
$install = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-linux-packages.py') -Raw).Replace("`r`n","`n").TrimEnd("`n")
$indented = ($install.Split("`n") | ForEach-Object { '      ' + $_ }) -join "`n"
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
package_reboot_if_required: false
write_files:
  - path: /usr/local/sbin/nfs-lab-install-packages
    owner: root:root
    permissions: '0700'
    content: |
$indented
runcmd:
  - [python3, /usr/local/sbin/nfs-lab-install-packages]
final_message: 'Offline package stage finished; inspect NFS_LAB_PACKAGES markers. AD/NFS interoperability remains unverified.'
power_state:
  mode: poweroff
  delay: now
  timeout: 900
  condition: true
"@
[IO.File]::WriteAllText((Join-Path $seed 'user-data'),$user.Replace("`r`n","`n")+"`n",$utf8)
$meta = Join-Path $seed 'meta-data'
if (!(Test-Path -LiteralPath $meta)) { [IO.File]::WriteAllText($meta,"instance-id: nfs-viewer-msad-packages-$([Guid]::NewGuid().ToString('N'))`nlocal-hostname: nfs`n",$utf8) }
$network = Join-Path $runtime 'linux-seed/network-config'
Assert-LabRegularPath (Join-Path $runtime 'linux-seed')
Assert-LabRegularPath $network
Copy-Item -LiteralPath $network -Destination (Join-Path $seed 'network-config')
& docker run --rm --network none --mount "type=bind,source=$seed,target=/seed,readonly" nfs-viewer-msad-package-tools cloud-init schema -c /seed/user-data
if ($LASTEXITCODE -ne 0) { throw 'Package seed schema check failed.' }
& docker run --rm --network none --mount "type=bind,source=$seed,target=/seed,readonly" --mount "type=bind,source=$bundle,target=/bundle,readonly" --mount "type=bind,source=$PSScriptRoot,target=/scripts,readonly" --mount "type=bind,source=$media,target=/output" nfs-viewer-msad-package-tools `
    genisoimage -quiet -output /output/packages.iso -volid cidata -joliet -rock -graft-points user-data=/seed/user-data meta-data=/seed/meta-data network-config=/seed/network-config bundle=/bundle verify-linux-bundle.py=/scripts/verify-linux-bundle.py
if ($LASTEXITCODE -ne 0) { throw 'Package ISO generation failed.' }
@{ ISO=$iso; SHA256=(Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash; CreatedUtc=[DateTime]::UtcNow.ToString('o'); InstallerSHA256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'install-linux-packages.py')).Hash; Purpose='Offline packages only, services inactive, no AD join'; } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $media 'packages.metadata.json') -Encoding utf8
Write-Output 'Authenticated package ISO and validated NoCloud installer ready; no VM changes made.'
