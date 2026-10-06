# Build a credential-free management boot for the existing Linux guest; never starts it.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^management-[0-9]{8}-[0-9]{2}$')][string]$RunId,
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$vmx = Join-Path $runtime 'nfs/nfs.vmx'
Assert-LabRegularPath $vmx
$manifest = Get-Content -LiteralPath (Join-Path $runtime 'lab.json') -Raw | ConvertFrom-Json
$entry = @($manifest.Machines | Where-Object Name -eq nfs)
if ($entry.Count -ne 1 -or $entry[0].Vmx -ine $vmx) { throw 'Unexpected Linux VM identity.' }
$config = Get-Content -LiteralPath $vmx -Raw
$macs = [regex]::Matches($config,'(?m)^ethernet0.generatedAddress = "([0-9a-f:]{17})"\s*$')
if ($macs.Count -ne 1) { throw 'Missing exact Linux NIC identity.' }
$runs = Join-Path $runtime 'management-runs'
Assert-LabRegularPath $runs
New-Item -ItemType Directory -Path $runs -Force | Out-Null
$run = Join-Path $runs $RunId
Assert-LabRegularPath $run
if (Test-Path -LiteralPath $run) { throw 'Management run already exists; inspect and resume it.' }
$seed = Join-Path $run 'seed'
New-Item -ItemType Directory -Path $seed | Out-Null
$scriptPath = Join-Path $PSScriptRoot 'linux-management-evidence.py'
$script = (Get-Content -LiteralPath $scriptPath -Raw).Replace("`r`n","`n").TrimEnd()
$indented = ($script -split "`n" | ForEach-Object { '      ' + $_ }) -join "`n"
$userData = @"
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
  - path: /usr/local/sbin/nfs-lab-management-evidence
    owner: root:root
    permissions: '0700'
    content: |
$indented
runcmd:
  - [/usr/local/sbin/nfs-lab-management-evidence]
final_message: 'Private management boot complete; no AD join or NFS test has run.'
"@
$network = @"
version: 2
ethernets:
  lab:
    match:
      macaddress: '$($macs[0].Groups[1].Value)'
    set-name: lab0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    link-local: []
    addresses: [192.0.2.20/24]
    nameservers:
      addresses: [192.0.2.10]
      search: [msad.nfs.test]
    optional: true
"@
$utf8 = [Text.UTF8Encoding]::new($false)
foreach ($item in @{ 'user-data'=$userData; 'network-config'=$network; 'meta-data'="instance-id: nfs-viewer-msad-$RunId`nlocal-hostname: nfs" }.GetEnumerator()) {
    [IO.File]::WriteAllText((Join-Path $seed $item.Key),$item.Value.Replace("`r`n","`n")+"`n",$utf8)
}
& docker run --rm --network none --mount "type=bind,source=$seed,target=/seed,readonly" nfs-viewer-msad-linux-tools cloud-init schema -c /seed/user-data
if ($LASTEXITCODE) { throw 'Management seed schema validation failed.' }
& docker run --rm --network none --mount "type=bind,source=$seed,target=/seed,readonly" --mount "type=bind,source=$run,target=/out" nfs-viewer-msad-linux-tools genisoimage -quiet -o /out/management.iso -volid cidata -joliet -rock /seed/user-data /seed/meta-data /seed/network-config
if ($LASTEXITCODE) { throw 'Management seed build failed.' }
[ordered]@{RunId=$RunId;CreatedUtc=[DateTime]::UtcNow.ToString('o');Scope='Credential-free private management boot; retains SSH host/user keys; no fixture, join or poweroff';ISO=(Join-Path $run 'management.iso');SHA256=(Get-FileHash (Join-Path $run 'management.iso')).Hash;ScriptSHA256=(Get-FileHash $scriptPath).Hash} | ConvertTo-Json | Set-Content (Join-Path $run 'metadata.json') -Encoding utf8
Write-Output "Built validated management seed: $run"
