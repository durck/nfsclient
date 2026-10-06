#!/bin/sh
set -eu
# Fixture roots must be disposable tmpfs, never the host or a production mount.
test "$(stat -f -c %T /data)" = tmpfs
test "$(stat -f -c %T /readonly)" = tmpfs
test "$(stat -f -c %T /squashed)" = tmpfs
mkdir -p /run/rpcbind /var/lib/nfs /var/state/nfs
chmod 1777 /data /squashed
chmod 755 /readonly
mkdir /data/wide
i=0
while [ "$i" -lt 300 ]; do
    touch "/data/wide/entry-$(printf '%03d' "$i")"
    i=$((i + 1))
done
printf 'NFSv2 fixture\n' > /data/public.txt
printf 'private-alice\n' > /data/private.txt
printf 'shared-group\n' > /data/group.txt
chown 20001:20001 /data/private.txt
chown 0:20003 /data/group.txt
chmod 600 /data/private.txt
chmod 640 /data/group.txt
ln -s public.txt /data/link.txt
ln -s missing /data/dangling.txt
printf 'read-only-seed\n' > /readonly/seed
truncate -s 2147483647 /data/boundary.bin
printf 'V2-END' | dd of=/data/boundary.bin bs=1 seek=2147483641 conv=notrunc status=none
truncate -s 2147483648 /data/too-large.bin
printf '%s\n' '/data (rw,no_root_squash,no_all_squash,insecure)' '/readonly (ro,no_root_squash,no_all_squash,insecure)' '/squashed (rw,root_squash,no_all_squash,insecure)' > /etc/exports
rpcbind -w
# The historical major(device)==0 heuristic mistakes tmpfs for NFS. Permit
# this checked disposable tmpfs; no host/NFS filesystem is mounted here.
/usr/local/sbin/rpc.mountd -F -r -P 20048 &
exec /usr/local/sbin/rpc.nfsd -F -r -P 2049
