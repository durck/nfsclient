[CmdletBinding()]
param([string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../bin/microsoft-ad-lab'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'LabPaths.ps1')
$runtime = Get-LabRuntimeRoot $RuntimeRoot
$media = Join-Path $runtime 'linux-media'
Assert-LabRegularPath $media
$iso = Join-Path $media 'seed.iso'
if (Test-Path -LiteralPath $iso) { throw 'Seed ISO already exists; refusing to replace an attached datasource.' }
$manifest = Get-Content -LiteralPath (Join-Path $runtime 'lab.json') -Raw | ConvertFrom-Json
$vmx = Join-Path $runtime 'nfs/nfs.vmx'
Assert-LabRegularPath (Join-Path $runtime 'nfs')
Assert-LabRegularPath $vmx
$entry = @($manifest.Machines | Where-Object Name -eq 'nfs')
if ($entry.Count -ne 1 -or ![string]::Equals($entry[0].Vmx,$vmx,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected Linux VM path.' }
$macMatches = [regex]::Matches((Get-Content -LiteralPath $vmx -Raw),'(?m)^ethernet0.generatedAddress = "([0-9a-fA-F:]{17})"\s*$')
if ($macMatches.Count -ne 1) { throw 'The existing NFS VM must have its assigned MAC from the firmware preparation stage.' }
$mac = $macMatches[0].Groups[1].Value.ToLowerInvariant()
$seed = Join-Path $runtime 'linux-seed'
$private = Join-Path $runtime 'private'
foreach ($path in @($seed,$private)) { Assert-LabRegularPath $path; New-Item -ItemType Directory -Path $path -Force | Out-Null }
foreach ($leaf in @('user-data','meta-data','network-config')) { Assert-LabRegularPath (Join-Path $seed $leaf) }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-18'),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $private -AclObject $acl
$key = Join-Path $private 'linux-lab-ed25519'
Assert-LabRegularPath $key
Assert-LabRegularPath ($key + '.pub')
if (!(Test-Path -LiteralPath $key)) {
    & ssh-keygen.exe -q -t ed25519 -N '' -C 'nfs-viewer-disposable-lab' -f $key
    if ($LASTEXITCODE -ne 0) { throw 'Could not generate the dedicated lab key.' }
}
# Windows ssh-keygen installs its own explicit ACL, including Administrators.
# Apply the lab's narrower policy to the actual private file after generation.
& icacls.exe $key /inheritance:r /grant:r ('*'+$sid.Value+':(F)') '*S-1-5-18:(F)' /remove:g '*S-1-5-32-544' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the private key file ACL.' }
$keyAcl = Get-Acl -LiteralPath $key
$allowedIdentities = @($sid.Value,'S-1-5-18')
if (!$keyAcl.AreAccessRulesProtected -or @($keyAcl.Access | Where-Object {
    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowedIdentities
}).Count) { throw 'Private key file has unexpected access rules.' }
$publicKey = (Get-Content -LiteralPath ($key+'.pub') -Raw).Trim()
if ($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+ nfs-viewer-disposable-lab$') { throw 'Unexpected lab public key.' }
$utf8 = [Text.UTF8Encoding]::new($false)
$userData = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'linux-user-data.yaml') -Raw).Replace('__LAB_SSH_PUBLIC_KEY__',$publicKey)
$metaPath = Join-Path $seed 'meta-data'
if (!(Test-Path -LiteralPath $metaPath)) {
    [IO.File]::WriteAllText($metaPath,"instance-id: nfs-viewer-msad-$([Guid]::NewGuid().ToString('N'))`nlocal-hostname: nfs`n",$utf8)
}
[IO.File]::WriteAllText((Join-Path $seed 'user-data'),$userData.Replace("`r`n","`n"),$utf8)
$network = @"
version: 2
ethernets:
  lab:
    match:
      macaddress: '$mac'
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
[IO.File]::WriteAllText((Join-Path $seed 'network-config'),$network.Replace("`r`n","`n")+"`n",$utf8)
& docker run --rm --network none --mount "type=bind,source=$seed,target=/seed,readonly" nfs-viewer-msad-linux-tools cloud-init schema -c /seed/user-data
if ($LASTEXITCODE -ne 0) { throw 'Cloud-init user-data schema validation failed.' }
New-Item -ItemType Directory -Path $media -Force | Out-Null
& docker run --rm --network none --mount "type=bind,source=$seed,target=/seed,readonly" --mount "type=bind,source=$media,target=/output" nfs-viewer-msad-linux-tools `
    genisoimage -quiet -output /output/seed.iso -volid cidata -joliet -rock /seed/user-data /seed/meta-data /seed/network-config
if ($LASTEXITCODE -ne 0) { throw 'NoCloud seed ISO generation failed.' }
@{ SeedISO=$iso; SHA256=(Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash; Address='192.0.2.20/24'; DefaultGateway=$null; Credential='Dedicated local owner-restricted SSH key; password login disabled'; GeneratedUtc=[DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $media 'seed.metadata.json') -Encoding utf8
Write-Output 'Validated offline NoCloud seed ISO created. It configures static private networking and powers off after bootstrap evidence.'
