#!/bin/sh
set -eu
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /run/rpcbind /run/lock /evidence /proc/fs/nfsd /storage
modprobe virtio_net
ip link set lo up
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2
modprobe 9pnet_virtio
mount -t 9p -o trans=virtio,version=9p2000.L evidence /evidence
modprobe nfsd
mount -t nfsd nfsd /proc/fs/nfsd
: > /etc/exports
: > /evidence/storage-oracle.txt
set -- b c d e f g
for policy in open restricted; do
 for fs in ext4 xfs btrfs; do
  device=/dev/vd$1
  shift
  point=/storage/$fs-$policy
  mkdir -p "$point"
  modprobe "$fs"
  case "$fs" in
   ext4) mkfs.ext4 -q -F "$device" ;;
   xfs) mkfs.xfs -q -f "$device" ;;
   btrfs) mkfs.btrfs -q -f "$device" ;;
  esac
  mount -t "$fs" "$device" "$point"
  # A Btrfs subvolume exercises the 256+ root-object IDs already advertised
  # by discovery, with its directory exported below that subvolume root.
  if test "$fs" = btrfs; then
   btrfs subvolume create "$point/volume"
   umount "$point"
   mount -t btrfs -o subvol=volume "$device" "$point"
  fi
  mkdir "$point/export"
  printf '%s-%s-native-root\n' "$fs" "$policy" > "$point/root-marker"
  printf '%s-%s-export\n' "$fs" "$policy" > "$point/export/inside-marker"
  chmod 755 "$point" "$point/export"
  chmod 644 "$point/root-marker" "$point/export/inside-marker"
  check=no_subtree_check
  test "$policy" != restricted || check=subtree_check
  printf '%s/export *(rw,sync,%s,insecure,no_root_squash,sec=sys)\n' "$point" "$check" >> /etc/exports
  stat -c "$fs $policy root_inode=%i dev=%d mode=%a" "$point" >> /evidence/storage-oracle.txt
  stat -c "$fs $policy export_inode=%i dev=%d mode=%a" "$point/export" >> /evidence/storage-oracle.txt
 done
done
modprobe vfat
modprobe exfat
mkdir /storage/fat32 /storage/exfat
mkfs.fat -F 32 /dev/vdh
mkfs.exfat /dev/vdi
mount -t vfat /dev/vdh /storage/fat32
mount -t exfat /dev/vdi /storage/exfat
rpcbind -w
printf -- '-2 +3 -4\n' > /proc/fs/nfsd/versions
rpc.mountd -V 3 -p 20048
exportfs -ra
printf 'tcp 2049\n' > /proc/fs/nfsd/portlist
printf '4\n' > /proc/fs/nfsd/threads
exportfs -v > /evidence/exports.txt
cat /proc/mounts > /evidence/mounts.txt
uname -a > /evidence/kernel.txt
printf 'READY\n' > /evidence/server.ready
while ! test -f /evidence/server.stop; do
 if test -f /evidence/local-tests.run && ! test -f /evidence/local-tests.done; then
  set +e
  NFS_VIEWER_STORAGE_PORT=2049 NFS_VIEWER_STORAGE_MOUNT_PORT=20048 NFS_VIEWER_STORAGE_LOCAL_DIR=/storage /evidence/session.test -test.v -test.run '^TestNativeLocalPublication$' > /evidence/local-publication.log 2>&1
  result=$?
  set -e
  printf '%s\n' "$result" > /evidence/local-tests.done
 fi
 if test -f /evidence/server.verify && ! test -f /evidence/server.verified; then
  find /storage -name '*published*' -type f -exec sha256sum '{}' + > /evidence/native-published-sha256.txt
  printf 'VERIFIED\n' > /evidence/server.verified
 fi
 sleep 1
done
exportfs -au
printf '0\n' > /proc/fs/nfsd/threads
sync
busybox poweroff -f
