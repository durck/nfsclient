#!/bin/sh
set -eu
test ! -e /evidence/root.ext4
mkdir /tmp/guest
cp -a /bin /sbin /lib /lib64 /usr /etc /var /boot /tmp/guest/
mkdir -p /tmp/guest/dev /tmp/guest/proc /tmp/guest/sys /tmp/guest/run /tmp/guest/tmp /tmp/guest/evidence /tmp/guest/root
cp /fixture/guest-init.sh /tmp/guest/fixture-init
cp /fixture/probe.py /tmp/guest/fixture-probe.py
chmod 755 /tmp/guest/fixture-init
truncate -s 1536M /tmp/root.ext4
mkfs.ext4 -q -F -d /tmp/guest /tmp/root.ext4
cp /boot/vmlinuz-* /evidence/vmlinuz
cp /boot/initrd.img-* /evidence/initrd
cp /boot/config-* /evidence/kernel-config
sha256sum /lib/modules/*/kernel/fs/nfsd/nfsd.ko > /evidence/nfsd-module.sha256
count=0
while ! test -f /evidence/server.stop; do
 count=$((count+1))
 test "$count" -le 32
 qemu-system-x86_64 -accel tcg -m 768 -smp 2 -nographic -no-reboot -kernel /evidence/vmlinuz -initrd /evidence/initrd -append 'root=/dev/vda rw console=ttyS0 net.ifnames=0 noresume init=/fixture-init' -drive file=/tmp/root.ext4,format=raw,if=virtio -netdev user,id=net,hostfwd=tcp:0.0.0.0:19511-:111,hostfwd=udp:0.0.0.0:19511-:111,hostfwd=tcp:0.0.0.0:20024-:20024,hostfwd=tcp:0.0.0.0:19521-:19521,hostfwd=tcp:0.0.0.0:19548-:19548,hostfwd=udp:0.0.0.0:19548-:19548,hostfwd=tcp:0.0.0.0:19549-:19549,hostfwd=udp:0.0.0.0:19549-:19549 -device virtio-net-pci,netdev=net -object "filter-dump,id=capture,netdev=net,file=/evidence/network-$count.pcap" -virtfs local,path=/evidence,mount_tag=evidence,security_model=none > "/evidence/console-$count.log" 2>&1
done
cp /tmp/root.ext4 /evidence/root.ext4
