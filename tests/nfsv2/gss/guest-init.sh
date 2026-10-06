#!/bin/sh
set -eu
umask 077
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /run/rpcbind /run/lock /data /evidence /proc/fs/nfsd
modprobe virtio_net
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2
modprobe 9pnet_virtio
mount -t 9p -o trans=virtio,version=9p2000.L evidence /evidence
modprobe nfsd
modprobe rpcsec_gss_krb5
mount -t nfsd nfsd /proc/fs/nfsd
hostname server.nfs.test
printf '127.0.0.1 localhost server.nfs.test\n' > /etc/hosts
for name in alice bob; do
 id=20001
 test "$name" = alice || id=20002
 groupadd -g "$id" "$name"
 useradd -u "$id" -g "$id" -M -s /usr/sbin/nologin "$name"
done
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
 default_realm = NFS.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 udp_preference_limit = 1
[realms]
 NFS.TEST = {
  kdc = 127.0.0.1:88
 }
EOF
cat > /etc/idmapd.conf <<'EOF'
[General]
Domain = nfs.test
Local-Realms = NFS.TEST
[Mapping]
Nobody-User = nobody
Nobody-Group = nogroup
[Translation]
Method = nsswitch
GSS-Methods = nsswitch
EOF
# The companion disposable KDC exports only fresh test keys through runtime
# storage. No KDC is required inside the guest for AP_REQ acceptance.
test -f /evidence/kdc.ready
cp /evidence/credentials/server.keytab /etc/krb5.keytab
rpcbind -w
rpc.svcgssd -f -p nfs/server.nfs.test@NFS.TEST > /evidence/svcgssd.log 2>&1 &
chmod 1777 /data
printf '/data *(rw,sync,no_subtree_check,insecure,no_root_squash,sec=krb5:krb5i:krb5p)\n' > /etc/exports
printf '+2 +3 -4\n' > /proc/fs/nfsd/versions
if test -f /evidence/v4-acl.enabled; then
 # A separate explicit AUTH_SYS namespace for native v4 ACL command checks.
 mkdir -p /v4/data/acl/inherit
 mount --bind /v4/data /v4/data
 chmod 755 /v4 /v4/data /v4/data/acl
 chown 20001:20001 /v4/data/acl /v4/data/acl/inherit
 setfacl --no-mask --set 'u::rwx,u:20002:rwx,g::---,m::rwx,o::---' /v4/data/acl/inherit
 setfacl --no-mask --default --set 'u::rwx,u:20002:rwx,g::---,m::rwx,o::---' /v4/data/acl/inherit
 printf '/v4 *(ro,fsid=0,sync,no_subtree_check,insecure,no_root_squash,sec=sys)\n/v4/data *(rw,fsid=201,sync,no_subtree_check,insecure,no_root_squash,sec=sys)\n' >> /etc/exports
 printf '+4 +4.0 +4.1 +4.2\n' > /proc/fs/nfsd/versions
 printf '10\n' > /proc/fs/nfsd/nfsv4gracetime
fi
if test -f /evidence/v4-gss.enabled; then
 mkdir -p /v4/data
 mount --bind /data /v4/data
 chmod 755 /v4
 printf '/v4 *(ro,fsid=0,sync,no_subtree_check,insecure,no_root_squash,sec=krb5:krb5i:krb5p)\n/v4/data *(rw,fsid=201,sync,no_subtree_check,insecure,no_root_squash,sec=krb5:krb5i:krb5p)\n' >> /etc/exports
 printf '+4 +4.0 +4.1 +4.2\n' > /proc/fs/nfsd/versions
 printf '10\n' > /proc/fs/nfsd/nfsv4gracetime
fi
rpc.mountd -V 2 -p 20048
exportfs -ra
printf 'tcp 2049\n' > /proc/fs/nfsd/portlist
printf 'udp 2049\n' > /proc/fs/nfsd/portlist
printf '4\n' > /proc/fs/nfsd/threads
cat /proc/fs/nfsd/versions > /evidence/nfsd-versions.txt
cat /proc/fs/nfsd/portlist > /evidence/nfsd-ports.txt
rpcinfo -p > /evidence/rpc-services.txt
uname -a > /evidence/kernel.txt
printf 'READY\n' > /evidence/server.ready
while ! test -f /evidence/server.stop; do
 if test -f /evidence/server.verify && ! test -f /evidence/server.verified; then
  find /data -type f -exec sha256sum '{}' + > /evidence/native-sha256.txt
  getfacl -n -p -R /data > /evidence/native-acl.txt
  if test -d /v4; then
   getfacl -n -p -R /v4 > /evidence/native-v4-acl.txt
   find /v4 -type f -exec sha256sum '{}' + > /evidence/native-v4-sha256.txt
  fi
  dmesg > /evidence/kernel-log.txt
  printf 'VERIFIED\n' > /evidence/server.verified
 fi
 sleep 1
done
exportfs -au
printf '0\n' > /proc/fs/nfsd/threads
sync
busybox poweroff -f
