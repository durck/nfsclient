#!/bin/sh
set -eu
mkdir /tmp/guest
cp -a /bin /sbin /lib /lib64 /usr /etc /var /boot /tmp/guest/
mkdir -p /tmp/guest/dev /tmp/guest/proc /tmp/guest/sys /tmp/guest/run /tmp/guest/tmp /tmp/guest/evidence /tmp/guest/root
cp /fixture/guest-init.sh /tmp/guest/fixture-init
chmod 755 /tmp/guest/fixture-init
cp /boot/vmlinuz-* /evidence/vmlinuz
cp /boot/initrd.img-* /evidence/initrd
cp /boot/config-* /evidence/kernel-config
cp /opt/nfsd-ssc-build.txt /evidence/
sha256sum /lib/modules/*/kernel/fs/nfsd/nfsd.ko > /evidence/nfsd-module.sha256
for role in source destination; do
 test ! -e "/evidence/$role/root.ext4"
 mkdir -p "/evidence/$role"
 printf '%s\n' "$role" > /tmp/guest/fixture-role
 truncate -s 1536M "/tmp/$role.ext4"
 mkfs.ext4 -q -F -d /tmp/guest "/tmp/$role.ext4"
 if test "$role" = source; then node=1; port=2049; link=listen=127.0.0.1:12000; else node=2; port=2050; link=connect=127.0.0.1:12000; fi
 qemu-system-x86_64 -accel tcg -m 768 -smp 2 -nographic -no-reboot -kernel /evidence/vmlinuz -initrd /evidence/initrd -append 'root=/dev/vda rw console=ttyS0 net.ifnames=0 noresume init=/fixture-init' -drive "file=/tmp/$role.ext4,format=raw,if=virtio" -netdev "user,id=front,net=10.77.$node.0/24,hostfwd=tcp:0.0.0.0:$port-10.77.$node.15:2049" -device virtio-net-pci,netdev=front,mac=52:54:00:01:00:0$node -netdev "socket,id=back,$link" -device virtio-net-pci,netdev=back,mac=52:54:00:02:00:0$node -object "filter-dump,id=capture,netdev=front,file=/evidence/$role/client-network.pcap" -object "filter-dump,id=ssc,netdev=back,file=/evidence/$role/server-network.pcap" -virtfs "local,path=/evidence/$role,mount_tag=evidence,security_model=none" > "/evidence/$role/console.log" 2>&1 &
 eval "${role}_pid=$!"
done
wait "$source_pid"
wait "$destination_pid"
cp /tmp/source.ext4 /evidence/source/root.ext4
cp /tmp/destination.ext4 /evidence/destination/root.ext4
