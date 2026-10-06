#!/bin/sh
set -eu
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
role=$(cat /fixture-role)
if test "$role" = source; then node=1; peer=2; else node=2; peer=1; fi
hostname "copy-$role"
mkdir -p /run/rpcbind /run/lock /data /evidence /proc/fs/nfsd
modprobe virtio_net
ip link set lo up
ip link set eth0 up
ip addr add "10.77.$node.15/24" dev eth0
ip route add default via "10.77.$node.2"
ip link set eth1 up
ip addr add "10.78.0.$node/30" dev eth1
ip route add "10.77.$peer.15/32" via "10.78.0.$peer"
modprobe 9pnet_virtio
mount -t 9p -o trans=virtio,version=9p2000.L evidence /evidence
modprobe nfs
modprobe nfsd inter_copy_offload_enable=1
mount -t nfsd nfsd /proc/fs/nfsd
chmod 777 /data
printf '/data *(rw,sync,no_subtree_check,insecure,no_root_squash,fsid=0)\n' > /etc/exports
rpcbind -w
rpc.mountd -p 20048
exportfs -ra
printf '+3 +4 +4.1 +4.2\n' > /proc/fs/nfsd/versions
printf '10\n' > /proc/fs/nfsd/nfsv4gracetime
printf 'tcp 2049\n' > /proc/fs/nfsd/portlist
printf '4\n' > /proc/fs/nfsd/threads
uname -a > /evidence/kernel.txt
cat /sys/module/nfsd/parameters/inter_copy_offload_enable > /evidence/ssc-enabled.txt
ip -brief address > /evidence/addresses.txt
sleep 12
printf 'READY\n' > /evidence/server.ready
while ! test -f /evidence/server.stop; do
 if test -f /evidence/server.verify && ! test -f /evidence/server.verified; then
  sha256sum /data/* > /evidence/native-sha256.txt
  stat -c '%n %s %u %g %a' /data/* > /evidence/native-files.txt
  printf 'VERIFIED\n' > /evidence/server.verified
 fi
 sleep 1
done
exportfs -au
printf '0\n' > /proc/fs/nfsd/threads
sync
busybox poweroff -f
