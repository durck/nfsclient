# Run inside the dedicated DC. Collect read-only deployment evidence, not NFS certification.
[CmdletBinding()]
param([string]$OutputPath = 'C:\NfsLab\dc-evidence.json')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
if ($env:COMPUTERNAME -ne 'NFSADDC1' -or $computer.Manufacturer -ne 'VMware, Inc.' -or $os.ProductType -ne 2) {
    throw 'Expected the dedicated VMware domain controller NFSADDC1.'
}
Import-Module ActiveDirectory
$domain = Get-ADDomain
$forest = Get-ADForest
if ($domain.DNSRoot -ne 'msad.nfs.test' -or $domain.NetBIOSName -ne 'NFSMSAD' -or $forest.RootDomain -ne 'msad.nfs.test') {
    throw 'Unexpected disposable AD domain/forest.'
}
$dc = Get-ADDomainController -Identity NFSADDC1
$services = @(Get-Service NTDS,DNS,Kdc,Netlogon,ADWS,DFSR | Select-Object Name,@{n='Status';e={$_.Status.ToString()}})
$shares = @(Get-SmbShare -Name SYSVOL,NETLOGON | Select-Object Name,Path)
$adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name,MacAddress,InterfaceIndex)
$routes = @(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Select-Object DestinationPrefix,NextHop)
$addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '192.0.2.10' | Select-Object IPAddress,PrefixLength,InterfaceIndex)
$srv = @{}
foreach ($name in @('_ldap._tcp.dc._msdcs.msad.nfs.test','_kerberos._tcp.msad.nfs.test')) {
    $srv[$name] = @(Resolve-DnsName -Name $name -Type SRV -Server 192.0.2.10 -DnsOnly | Where-Object Type -eq SRV |
        Select-Object Name,NameTarget,Port,Priority,Weight)
    if (!$srv[$name].Count -or @($srv[$name] | Where-Object { $_.NameTarget.TrimEnd('.') -ine 'nfsaddc1.msad.nfs.test' }).Count) {
        throw "Unexpected domain service locator: $name"
    }
}
$diag = @(& dcdiag.exe /test:Advertising /test:Services /test:SysVolCheck /test:NetLogons)
$diagExit = $LASTEXITCODE
$passed = $services.Count -eq 6 -and !@($services | Where-Object Status -ne Running).Count -and
    $shares.Count -eq 2 -and $adapters.Count -eq 1 -and $routes.Count -eq 0 -and
    $addresses.Count -eq 1 -and $addresses[0].PrefixLength -eq 24 -and
    $dc.IsGlobalCatalog -and $dc.Enabled -and $diagExit -eq 0
$evidence = [ordered]@{
    CheckedUtc = [DateTime]::UtcNow.ToString('o')
    Passed = $passed
    ComputerName = $env:COMPUTERNAME
    OS = $os | Select-Object Caption,Version,BuildNumber,ProductType
    TimeZone = (Get-TimeZone).Id
    Domain = $domain | Select-Object DNSRoot,NetBIOSName,@{n='Mode';e={$_.DomainMode.ToString()}},PDCEmulator
    Forest = $forest | Select-Object RootDomain,@{n='Mode';e={$_.ForestMode.ToString()}},Domains
    DC = $dc | Select-Object HostName,IPv4Address,IsGlobalCatalog,Enabled,Site
    Services = $services
    Shares = $shares
    Adapters = $adapters
    Addresses = $addresses
    DefaultRoutes = $routes
    LocatorRecords = $srv
    DcdiagExit = $diagExit
    Dcdiag = $diag
    MicrosoftADNFSValidated = $false
}
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
if (!$passed) { throw 'DC deployment checks failed; inspect the saved evidence.' }
Write-Output 'Disposable Microsoft DC deployment checks passed; NFS/domain integration is not yet validated.'
