#!/bin/sh
set -eu
test -d /evidence
test ! -e /evidence/server.ready
mkdir /tmp/guest
cp -a /bin /sbin /lib /lib64 /usr /etc /var /boot /tmp/guest/
mkdir -p /tmp/guest/dev /tmp/guest/proc /tmp/guest/sys /tmp/guest/run /tmp/guest/tmp /tmp/guest/evidence /tmp/guest/root
cp /fixture/guest-init.sh /tmp/guest/fixture-init
chmod 755 /tmp/guest/fixture-init
truncate -s 1536M /tmp/root.ext4
mkfs.ext4 -q -F -d /tmp/guest /tmp/root.ext4
# All disks are private sparse regular files in this disposable container.
for n in 1 2 3 4 5 6 7 8; do truncate -s 384M /tmp/data$n.raw; done
exec qemu-system-x86_64 -accel tcg -m 1024 -smp 2 -nographic -no-reboot -kernel /boot/vmlinuz-* -initrd /boot/initrd.img-* -append 'root=/dev/vda rw console=ttyS0 net.ifnames=0 noresume init=/fixture-init' -drive file=/tmp/root.ext4,format=raw,if=virtio -drive file=/tmp/data1.raw,format=raw,if=virtio -drive file=/tmp/data2.raw,format=raw,if=virtio -drive file=/tmp/data3.raw,format=raw,if=virtio -drive file=/tmp/data4.raw,format=raw,if=virtio -drive file=/tmp/data5.raw,format=raw,if=virtio -drive file=/tmp/data6.raw,format=raw,if=virtio -drive file=/tmp/data7.raw,format=raw,if=virtio -drive file=/tmp/data8.raw,format=raw,if=virtio -netdev user,id=net,hostfwd=tcp:0.0.0.0:2049-:2049,hostfwd=tcp:0.0.0.0:20048-:20048 -device virtio-net-pci,netdev=net -virtfs local,path=/evidence,mount_tag=evidence,security_model=none
