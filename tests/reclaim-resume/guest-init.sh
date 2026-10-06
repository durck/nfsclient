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
printf '/data *(rw,sync,no_subtree_check,insecure,no_root_squash,fsid=0)\n' > /etc/exports
rpcbind -w
rpc.mountd -p 20048
exportfs -ra
printf '%s\n' '-3 +4 +4.1 +4.2' > /proc/fs/nfsd/versions
printf '10\n' > /proc/fs/nfsd/nfsv4gracetime
printf 'tcp 2049\n' > /proc/fs/nfsd/portlist
printf '4\n' > /proc/fs/nfsd/threads
uname -a > /evidence/kernel.txt
cat /proc/fs/nfsd/versions > /evidence/versions.txt
sleep 12
printf 'READY\n' > /evidence/server.ready
while ! test -f /evidence/server.stop; do
 if test -f /evidence/grace-request; then
  token=$(cat /evidence/grace-request)
  done_token=$(cat /evidence/grace-done 2>/dev/null || true)
  if test -n "$token" && test "$token" != "$done_token"; then
   if test "$(cat /proc/fs/nfsd/v4_end_grace)" != Y; then
    echo Y > /proc/fs/nfsd/v4_end_grace || true
   fi
   if test "$(cat /proc/fs/nfsd/v4_end_grace)" = Y; then
    printf '%s' "$token" > /evidence/grace-done
   fi
  fi
 fi
 if test -f /evidence/restart-request; then
  token=$(cat /evidence/restart-request)
  done_token=$(cat /evidence/restart-done 2>/dev/null || true)
  if test -n "$token" && test "$token" != "$done_token"; then
   printf '0\n' > /proc/fs/nfsd/threads
   sleep 1
   printf 'tcp 2049\n' > /proc/fs/nfsd/portlist
   printf '4\n' > /proc/fs/nfsd/threads
   printf '%s\n' "$token" >> /evidence/restarts.log
   printf '%s' "$token" > /evidence/restart-done
  fi
 fi
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
