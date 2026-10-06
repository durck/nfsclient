# Run only on the dedicated DC after the guarded Linux join/configuration.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -ne 'NFSADDC1' -or (Get-CimInstance Win32_ComputerSystem).Manufacturer -ne 'VMware, Inc.' -or
    (Get-CimInstance Win32_OperatingSystem).ProductType -ne 2) { throw 'Expected the dedicated VMware DC.' }
Import-Module ActiveDirectory
if ((Get-ADDomain).DNSRoot -ne 'msad.nfs.test') { throw 'Unexpected lab domain.' }
$root = 'C:\NfsLab\linux-bridge'
$wrapper = Join-Path $root 'Invoke-LinuxDomain.ps1'
$reportPath = Join-Path $root 'identity-membership.json'
foreach ($name in @('identity-membership.json','identity-before.json','identity-added.json','identity-restored.json')) {
    if (Test-Path -LiteralPath (Join-Path $root $name)) { throw ('Existing evidence; do not overwrite: ' + $name) }
}
$ou = 'OU=NfsViewerLab,DC=msad,DC=nfs,DC=test'
$machine = Get-ADComputer -Identity NFS -Properties ServicePrincipalName,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes'
if ($machine.DistinguishedName -ne ('CN=NFS,' + $ou) -or $machine.DNSHostName -ne 'nfs.msad.nfs.test') {
    throw 'Unexpected machine identity/OU.'
}
$expectedSpn = @('HOST/nfs','HOST/nfs.msad.nfs.test','RestrictedKrbHost/nfs','RestrictedKrbHost/nfs.msad.nfs.test')
if (@(Compare-Object $expectedSpn @($machine.ServicePrincipalName)).Count) { throw 'Unexpected machine SPNs.' }
$service = Get-ADUser svc-nfs -Properties ServicePrincipalName,'msDS-KeyVersionNumber'
if (@($service.ServicePrincipalName).Count -ne 1 -or $service.ServicePrincipalName[0] -ne 'nfs/nfs.msad.nfs.test' -or
    $service.'msDS-KeyVersionNumber' -ne 2) { throw 'NFS service identity changed during machine join.' }
$readers = Get-ADGroup nfsreaders -Properties gidNumber
if ($readers.DistinguishedName -ne ('CN=nfsreaders,' + $ou) -or $readers.gidNumber -ne 24003) { throw 'Unexpected readers group.' }
$users = @{}
foreach ($entry in @(@{Name='alice';UID=24001},@{Name='bob';UID=24002},@{Name='svc-nfs';UID=24004})) {
    $user = Get-ADUser $entry.Name -Properties uidNumber,gidNumber,primaryGroupID,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes'
    if ($user.DistinguishedName -ne ('CN=' + $entry.Name + ',' + $ou) -or $user.uidNumber -ne $entry.UID -or
        $user.gidNumber -ne 24000 -or $user.primaryGroupID -ne 513 -or $user.'msDS-KeyVersionNumber' -ne 2 -or
        $user.'msDS-SupportedEncryptionTypes' -ne 24) { throw 'Unexpected test user attributes.' }
    $users[$entry.Name] = $user | Select-Object SamAccountName,DistinguishedName,uidNumber,gidNumber,primaryGroupID,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes'
}
$initialMembers = @(Get-ADGroupMember -Identity $readers | Select-Object -ExpandProperty SamAccountName)
if ($initialMembers.Count -ne 1 -or $initialMembers[0] -ne 'alice') { throw 'Readers must initially contain Alice only.' }
& $wrapper -Action verify -EvidenceName identity-before
$report = [ordered]@{
    StartedUtc = [DateTime]::UtcNow.ToString('o')
    Passed = $false
    Users = $users
    Machine = $machine | Select-Object Name,DNSHostName,DistinguishedName,ServicePrincipalName,'msDS-KeyVersionNumber','msDS-SupportedEncryptionTypes'
    NfsService = $service | Select-Object SamAccountName,ServicePrincipalName,'msDS-KeyVersionNumber'
    ReadersBefore = $initialMembers
    ReadersAdded = @()
    ReadersRestored = @()
    AdditionVerified = $false
    RestorationVerified = $false
    MicrosoftADNFSValidated = $false
}
try {
    # Initial absence was proven above. Even a partially failed addition must
    # be followed by restoring this lab user's original membership.
    Add-ADGroupMember -Identity $readers -Members bob
    $report.ReadersAdded = @(Get-ADGroupMember -Identity $readers | Select-Object -ExpandProperty SamAccountName)
    if (@(Compare-Object @('alice','bob') $report.ReadersAdded).Count) { throw 'AD did not retain expected added membership.' }
    & $wrapper -Action verify-bob-reader -EvidenceName identity-added
    $report.AdditionVerified = $true
} finally {
    try {
        $members = @(Get-ADGroupMember -Identity $readers | Select-Object -ExpandProperty SamAccountName)
        if ($members -contains 'bob') { Remove-ADGroupMember -Identity $readers -Members bob -Confirm:$false }
        $report.ReadersRestored = @(Get-ADGroupMember -Identity $readers | Select-Object -ExpandProperty SamAccountName)
        if (@(Compare-Object $initialMembers $report.ReadersRestored).Count) { throw 'AD membership restoration did not match initial state.' }
        & $wrapper -Action verify -EvidenceName identity-restored
        $report.RestorationVerified = $true
        $report.Passed = $report.AdditionVerified -and $report.RestorationVerified
    } finally {
        $report.CompletedUtc = [DateTime]::UtcNow.ToString('o')
        $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    }
}
if (!$report.Passed) { throw 'Domain identity/group-change validation did not pass.' }
Write-Output 'Real Microsoft AD RFC2307 identities and group add/remove propagation verified; NFS remains separate.'
