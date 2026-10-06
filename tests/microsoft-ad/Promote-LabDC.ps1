# Run INSIDE the dedicated Windows Server VM after installation/license acceptance.
# First rename only that guest to NFSADDC1 and reboot it.
[CmdletBinding()]
param([Parameter(Mandatory)][Security.SecureString]$DsrmPassword)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
if ($env:COMPUTERNAME -ne 'NFSADDC1' -or $computer.Manufacturer -ne 'VMware, Inc.' -or $os.ProductType -eq 1) {
    throw 'This script only runs in the dedicated VMware Windows Server guest named NFSADDC1.'
}
if ($computer.PartOfDomain) { throw 'Refusing to modify a computer already joined to a domain.' }
$nics = @(Get-NetAdapter | Where-Object Status -eq 'Up')
if ($nics.Count -ne 1) { throw 'Expected exactly one connected lab NIC.' }
if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count) {
    throw 'Default gateway present. Verify the private LAN segment before promotion.'
}
if (@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue).Count) {
    throw 'IPv6 default gateway present. Verify the private LAN segment before promotion.'
}
$nic = $nics[0]
Set-NetIPInterface -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled
$existing = @(Get-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq '192.0.2.10' -and $_.PrefixLength -eq 24 })
if (!$existing.Count) { New-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -IPAddress '192.0.2.10' -PrefixLength 24 | Out-Null }
Set-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses '192.0.2.10'
$role = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
if (!$role.Success) { throw 'AD DS role installation failed.' }
Import-Module ADDSDeployment
$params = @{
    DomainName = 'msad.nfs.test'
    DomainNetbiosName = 'NFSMSAD'
    InstallDns = $true
    CreateDnsDelegation = $false
    SafeModeAdministratorPassword = $DsrmPassword
}
Test-ADDSForestInstallation @params -ErrorAction Stop
Install-ADDSForest @params -Force
