# Run only inside the promoted disposable DC. Passwords are SecureString inputs.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][Security.SecureString]$AlicePassword,
    [Parameter(Mandatory)][Security.SecureString]$BobPassword,
    [Parameter(Mandatory)][Security.SecureString]$NfsPassword
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
if ($env:COMPUTERNAME -ne 'NFSADDC1' -or $computer.Manufacturer -ne 'VMware, Inc.' -or $os.ProductType -ne 2) {
    throw 'Expected the dedicated VMware domain controller NFSADDC1.'
}
Import-Module ActiveDirectory
$domain = Get-ADDomain
if ($domain.DNSRoot -ne 'msad.nfs.test' -or $domain.NetBIOSName -ne 'NFSMSAD') { throw 'Unexpected domain; refusing account changes.' }
$base = 'DC=msad,DC=nfs,DC=test'
$ou = 'OU=NfsViewerLab,' + $base
if (Get-ADOrganizationalUnit -Filter 'Name -eq "NfsViewerLab"') { throw 'Lab OU already exists; refusing to reset identities or keys.' }
New-ADOrganizationalUnit -Name NfsViewerLab -Path $base -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name nfsusers -SamAccountName nfsusers -GroupScope Global -GroupCategory Security -Path $ou -OtherAttributes @{ gidNumber = 24000 }
New-ADGroup -Name nfsreaders -SamAccountName nfsreaders -GroupScope Global -GroupCategory Security -Path $ou -OtherAttributes @{ gidNumber = 24003 }
foreach ($entry in @(
    @{ Name = 'alice'; Password = $AlicePassword; ID = 24001 },
    @{ Name = 'bob'; Password = $BobPassword; ID = 24002 },
    @{ Name = 'svc-nfs'; Password = $NfsPassword; ID = 24004 }
)) {
    New-ADUser -Name $entry.Name -SamAccountName $entry.Name -UserPrincipalName ($entry.Name + '@MSAD.NFS.TEST') -Path $ou `
        -AccountPassword $entry.Password -Enabled $true -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 `
        -OtherAttributes @{ uidNumber = $entry.ID; gidNumber = 24000; unixHomeDirectory = ('/home/' + $entry.Name); loginShell = '/usr/sbin/nologin' }
}
Add-ADGroupMember -Identity nfsusers -Members alice,bob,svc-nfs
Add-ADGroupMember -Identity nfsreaders -Members alice
& setspn.exe -S nfs/nfs.msad.nfs.test NFSMSAD\svc-nfs
if ($LASTEXITCODE -ne 0) { throw 'NFS SPN registration failed.' }
Add-DnsServerResourceRecordA -ZoneName 'msad.nfs.test' -Name nfs -IPv4Address '192.0.2.20'
Write-Output 'Dedicated AD users, nfsreaders membership and NFS SPN created. Service keys and Linux join remain separate steps.'
