#!/bin/sh
set -eu
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
mount -t nfsd nfsd /proc/fs/nfsd
chmod 777 /data
for platform in windows linux; do
 for transport in tcp udp; do
  for kind in api cli empty local-change hardlink special; do
   name=/data/$platform-$transport-$kind
   printf 'old-data\n' > "$name"
   chown 20001:20001 "$name"
   chmod 640 "$name"
   setfacl -m u:20002:r-- "$name"
  done
  ln /data/$platform-$transport-hardlink /data/$platform-$transport-hardlink-alias
  chmod u+s /data/$platform-$transport-special
 done
done
getfacl -n -p /data/* > /evidence/acl-before.txt
printf '/data *(rw,sync,no_subtree_check,insecure,no_root_squash)\n' > /etc/exports
rpcbind -w
# The packaged rpc.nfsd command refuses -V2 even with a capable kernel.
# Configure the documented nfsd control filesystem directly in this guest.
printf '+2 +3 -4\n' > /proc/fs/nfsd/versions
rpc.mountd -V 2 -p 20048
exportfs -ra
printf 'tcp 2049\n' > /proc/fs/nfsd/portlist
printf 'udp 2049\n' > /proc/fs/nfsd/portlist
printf '4\n' > /proc/fs/nfsd/threads
cat /proc/fs/nfsd/versions > /evidence/nfsd-versions.txt
cat /proc/fs/nfsd/threads > /evidence/nfsd-threads.txt
cat /proc/fs/nfsd/portlist > /evidence/nfsd-ports.txt
ss -lnptu > /evidence/listeners.txt
ip addr > /evidence/addresses.txt
ip route > /evidence/routes.txt
timeout 5 rpcinfo -a 127.0.0.1.8.1 -T tcp 100003 2 > /evidence/nfs2-probe.txt 2>&1 || true
timeout 5 rpcinfo -a 127.0.0.1.8.1 -T tcp 100227 2 > /evidence/acl2-probe.txt 2>&1 || true
rpcinfo -p > /evidence/rpc-services.txt
uname -a > /evidence/kernel.txt
printf 'READY\n' > /evidence/server.ready
while ! test -f /evidence/server.stop; do
 if test -f /evidence/server.verify && ! test -f /evidence/server.verified; then
  sha256sum /data/* > /evidence/native-sha256.txt
  getfacl -n -p /data/* > /evidence/acl-after.txt
  find /data -maxdepth 2 -printf '%P %y %s %u %g %m\n' > /evidence/native-files.txt
  printf 'VERIFIED\n' > /evidence/server.verified
 fi
 sleep 1
done
exportfs -au
printf '0\n' > /proc/fs/nfsd/threads
sync
busybox poweroff -f
