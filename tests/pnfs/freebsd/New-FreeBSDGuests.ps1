[CmdletBinding()]
param(
    [string]$RuntimeRoot = (Join-Path $PSScriptRoot '../../../bin/pnfs11-freebsd'),
    [string]$VmwareRoot = 'C:/Program Files (x86)/VMware/VMware Workstation',
    [ValidateSet('mds','ds')][string[]]$Roles = @('mds','ds'),
    [string]$MediaRoot = '',
    [ValidatePattern('^[a-z][a-z0-9-]{0,24}$')][string]$Name = 'pnfs11'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$runtime = (Resolve-Path -LiteralPath $RuntimeRoot).Path
if ($Roles.Count -eq 0 -or @($Roles | Select-Object -Unique).Count -ne $Roles.Count) { throw 'Select unique guest roles.' }
if (!$MediaRoot) { $MediaRoot = Join-Path $runtime 'media' }
$media = (Resolve-Path -LiteralPath $MediaRoot).Path
$diskTemplate = Join-Path $media 'freebsd-template.vmdk'
if (!(Test-Path -LiteralPath $diskTemplate)) { throw 'Prepare the verified FreeBSD disk template first.' }
$proof = Get-Content -LiteralPath (Join-Path $media 'verified.json') -Raw | ConvertFrom-Json
if (!$proof.verified -or $proof.version -ne '14.4-RELEASE') { throw 'Expected verified official FreeBSD 14.4 image.' }
$conversion = Get-Content -LiteralPath (Join-Path $media 'conversion.json') -Raw | ConvertFrom-Json
if ($conversion.compressed_sha256 -ne $proof.sha256 -or
    (Get-FileHash -LiteralPath $diskTemplate -Algorithm SHA256).Hash.ToLowerInvariant() -ne $conversion.template_sha256) {
    throw 'Disk template does not match the retained conversion evidence.'
}
$manifestPath = Join-Path $runtime 'guests.json'
if (Test-Path -LiteralPath $manifestPath) { throw 'Guests already prepared; do not replace their disks or seeds.' }
$private = Join-Path $runtime 'private'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
if (!(Test-Path -LiteralPath $private)) {
New-Item -ItemType Directory -Path $private | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-18'),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath $private -AclObject $acl
}
$privateACL = Get-Acl -LiteralPath $private
if (!$privateACL.AreAccessRulesProtected) { throw 'Private lab directory must not inherit access.' }
foreach ($rule in $privateACL.Access) {
    $ruleSID = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($rule.AccessControlType -eq 'Allow' -and $ruleSID -notin @($sid.Value,'S-1-5-18')) {
        throw 'Unexpected access to private lab directory.'
    }
}
$key = Join-Path $private 'identity'
if (!(Test-Path -LiteralPath $key)) {
    & ssh-keygen.exe -q -t ed25519 -N '' -C 'nfs-viewer-pnfs11' -f $key
    if ($LASTEXITCODE -ne 0) { throw 'Lab key generation failed.' }
}
& icacls.exe $key /inheritance:r /grant:r ('*'+$sid.Value+':(F)') '*S-1-5-18:(F)' /remove:g '*S-1-5-32-544' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Lab key ACL restriction failed.' }
$public = (Get-Content -LiteralPath ($key+'.pub') -Raw).Trim()
if ($public -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+ nfs-viewer-pnfs11$') { throw 'Unexpected lab public key.' }
$utf8 = [Text.UTF8Encoding]::new($false)
$machines = @()
foreach ($role in $Roles) {
    $machineDir = Join-Path $runtime $role
    if (Test-Path -LiteralPath $machineDir) { throw "Refusing existing guest directory: $machineDir" }
    New-Item -ItemType Directory -Path $machineDir | Out-Null
    $disk = Join-Path $machineDir 'system.vmdk'
    & (Join-Path $VmwareRoot 'vmware-vdiskmanager.exe') -r $diskTemplate -t 0 $disk
    if ($LASTEXITCODE -ne 0) { throw "Guest disk creation failed: $role" }
    $seed = Join-Path $machineDir 'seed'
    New-Item -ItemType Directory -Path $seed | Out-Null
    $userData = @'
#!/bin/sh
set -eu
sysrc hostname=__NAME__-__ROLE__
sysrc sshd_enable=YES
install -d -m 700 /root/.ssh
printf '%s\n' '__PUBLIC_KEY__' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
# No existing active directives are expected in this fresh distribution image.
sed -i '' -e '/^PermitRootLogin /d' -e '/^PasswordAuthentication /d' -e '/^KbdInteractiveAuthentication /d' /etc/ssh/sshd_config
printf '\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' >> /etc/ssh/sshd_config
ssh-keygen -A
service sshd restart
mkdir -p /var/db/pnfs11-bootstrap
uname -a > /var/db/pnfs11-bootstrap/uname.txt
sha256 /boot/kernel/kernel > /var/db/pnfs11-bootstrap/kernel.sha256
printf 'PNFS11_ROLE=__ROLE__\n' > /dev/ttyu0
ifconfig em0 inet | sed -n 's/^[[:space:]]*inet \([^ ]*\).*/PNFS11_IPV4=\1/p' > /dev/ttyu0
printf 'PNFS11_HOSTKEY=' > /dev/ttyu0
cat /etc/ssh/ssh_host_ed25519_key.pub > /dev/ttyu0
touch /var/db/pnfs11-bootstrap/ready
printf 'PNFS11_BOOTSTRAP_READY\n' > /dev/ttyu0
'@
    $userData = $userData.Replace('__ROLE__',$role).Replace('__NAME__',$Name).Replace('__PUBLIC_KEY__',$public)
    # nuageinit writes non-deferred files before NETWORKING. Disable the image's
    # optional first-boot updater before it can change the pinned distribution.
    $bootstrap = (($userData.Replace("`r`n","`n").Split("`n") | ForEach-Object { '      '+$_ }) -join "`n")
    $userData = @"
#cloud-config
hostname: $Name-$role
ssh_pwauth: false
write_files:
  - path: /etc/rc.conf.d/firstboot_freebsd_update
    permissions: '0600'
    content: |
      firstboot_freebsd_update_enable="NO"
  - path: /var/cache/nuageinit/pnfs11-bootstrap.sh
    permissions: '0700'
    content: |
$bootstrap
runcmd:
  - /bin/sh /var/cache/nuageinit/pnfs11-bootstrap.sh
"@
    [IO.File]::WriteAllText((Join-Path $seed 'user-data'),$userData.Replace("`r`n","`n")+"`n",$utf8)
    [IO.File]::WriteAllText((Join-Path $seed 'meta-data'),"instance-id: $Name-$role-$([Guid]::NewGuid().ToString('N'))`nlocal-hostname: $Name-$role`n",$utf8)
    $iso = Join-Path $machineDir 'seed.iso'
    & (Join-Path $VmwareRoot 'mkisofs.exe') -quiet -output $iso -volid cidata -joliet -rock $seed.Replace('\','/')
    if ($LASTEXITCODE -ne 0) { throw "Seed ISO creation failed: $role" }
    $vmx = Join-Path $machineDir ($role+'.vmx')
    $serial = Join-Path $machineDir 'serial.log'
    $config = @"
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "21"
displayName = "NFS viewer $Name FreeBSD $role"
guestOS = "freebsd14-64"
firmware = "efi"
uefi.secureBoot.enabled = "FALSE"
memsize = "2048"
numvcpus = "2"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "system.vmdk"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "$($iso.Replace('\','/'))"
sata0:0.startConnected = "TRUE"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000"
ethernet0.addressType = "generated"
ethernet0.startConnected = "TRUE"
serial0.present = "TRUE"
serial0.fileType = "file"
serial0.fileName = "$($serial.Replace('\','/'))"
serial0.startConnected = "TRUE"
serial0.yieldOnMsrRead = "TRUE"
floppy0.present = "FALSE"
usb.present = "FALSE"
sound.present = "FALSE"
sharedFolder.maxNum = "0"
isolation.tools.hgfs.disable = "TRUE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
RemoteDisplay.vnc.enabled = "FALSE"
vmci0.present = "FALSE"
tools.syncTime = "FALSE"
mks.enable3d = "FALSE"
rtc.diffFromUTC = "0"
uuid.action = "create"
msg.autoAnswer = "TRUE"
"@
    [IO.File]::WriteAllText($vmx,$config+"`n",$utf8)
    $machines += @{role=$role;vmx=$vmx;disk=$disk;seed=$iso;serial=$serial;network='existing VMware NAT';started=$false}
}
@{version='14.4-RELEASE';image_sha256=$proof.sha256;template_sha256=$conversion.template_sha256;host_network_modified=$false;machines=$machines} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output "Fresh FreeBSD guests prepared: $($Roles -join ', '); not started. Pin SSH host keys from their serial bootstrap output."
