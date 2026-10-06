#!/bin/sh
set -eu
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
hostname nlm-reclaim
printf '127.0.0.1 localhost\n127.0.0.2 nlm-windows\n127.0.0.3 nlm-linux\n10.0.2.15 nlm-reclaim\n10.0.2.2 fixture-nat\n172.17.0.1 fixture-host\n' > /etc/hosts
mkdir -p /run/rpcbind /run/lock /data /evidence /proc/fs/nfsd
modprobe virtio_net
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2
modprobe 9pnet_virtio
mount -t 9p -o trans=virtio,version=9p2000.L evidence /evidence
boot=$(cat /proc/sys/kernel/random/boot_id)
modprobe lockd
printf '19521\n' > /proc/sys/fs/nfs/nlm_tcpport
printf '19521\n' > /proc/sys/fs/nfs/nlm_udpport
printf '30\n' > /proc/sys/fs/nfs/nlm_grace_period
printf '5\n' > /proc/sys/fs/nfs/nlm_timeout
modprobe nfsd
mount -t nfsd nfsd /proc/fs/nfsd
chmod 777 /data
printf '/data *(rw,sync,no_subtree_check,insecure,no_root_squash,fsid=0)\n' > /etc/exports
printf '[sm-notify]\nlift-grace=n\nretry-time=1\n' > /etc/nfs.conf
rpcbind -w
# Foreground statd also forces foreground sm-notify. Run notification startup
# separately: it advances persistent state before daemonizing, then statd -L
# reads that epoch without waiting for unreachable NAT notification recipients.
sm-notify
rpc.statd -F -d -L -p 20024 > "/evidence/statd-$boot.log" 2>&1 &
attempt=0
until rpcinfo -T tcp 127.0.0.1 100024 1 >/dev/null 2>&1; do
 attempt=$((attempt+1))
 test "$attempt" -le 30
 sleep 1
done
rpc.mountd -p 19548
exportfs -ra
printf '+2 +3 -4\n' > /proc/fs/nfsd/versions
printf '30\n' > /proc/fs/nfsd/nfsv4gracetime
printf 'tcp 19549\n' > /proc/fs/nfsd/portlist
printf 'udp 19549\n' > /proc/fs/nfsd/portlist
printf '4\n' > /proc/fs/nfsd/threads
while true; do
 printf 'UPTIME '; cat /proc/uptime
 cat /proc/locks
 sleep 1
done > "/evidence/locks-history-$boot.txt" &
uname -a > /evidence/kernel.txt
cat /proc/fs/nfsd/versions > /evidence/versions.txt
printf '%s\n' "$boot" >> /evidence/boots.log
od -An -tu4 /var/lib/nfs/state >> /evidence/statd-states.log
cat /proc/locks > "/evidence/locks-$boot.txt"
python3 /fixture-probe.py > "/evidence/probe-$boot.log" 2>&1 &
token=$(cat /evidence/restart-request 2>/dev/null || true)
if test -n "$token"; then printf '%s' "$token" > /evidence/restart-done; fi
sleep 32
printf '%s' "$token" > /evidence/grace-ended
printf 'READY\n' > /evidence/server.ready
while ! test -f /evidence/server.stop; do
 requested=$(cat /evidence/restart-request 2>/dev/null || true)
 if test "$requested" != "$token"; then
  printf '%s\n' "$requested" >> /evidence/restarts.log
  sync
  busybox reboot -f
 fi
 if test -f /evidence/server.verify && ! test -f /evidence/server.verified; then
  sha256sum /data/* > /evidence/native-sha256.txt
  printf 'VERIFIED\n' > /evidence/server.verified
 fi
 sleep 1
done
exportfs -au
printf '0\n' > /proc/fs/nfsd/threads
sync
busybox poweroff -f
