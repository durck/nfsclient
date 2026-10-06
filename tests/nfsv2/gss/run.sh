#!/bin/sh
set -eu
# /evidence is a dedicated empty runtime directory, outside the repository.
test -d /evidence
test ! -e /evidence/server.ready
mkdir /tmp/guest
cp -a /bin /sbin /lib /lib64 /usr /etc /var /boot /tmp/guest/
mkdir -p /tmp/guest/dev /tmp/guest/proc /tmp/guest/sys /tmp/guest/run /tmp/guest/tmp /tmp/guest/evidence /tmp/guest/root
cp /fixture/guest-init.sh /tmp/guest/fixture-init
chmod 755 /tmp/guest/fixture-init
truncate -s 1536M /tmp/root.ext4
mkfs.ext4 -q -F -d /tmp/guest /tmp/root.ext4
qemu-system-x86_64 -accel tcg -m 768 -smp 2 -nographic -no-reboot -kernel /boot/vmlinuz-* -initrd /boot/initrd.img-* -append 'root=/dev/vda rw console=ttyS0 net.ifnames=0 noresume init=/fixture-init' -drive file=/tmp/root.ext4,format=raw,if=virtio -netdev user,id=net,hostfwd=tcp:0.0.0.0:2049-:2049,hostfwd=udp:0.0.0.0:2049-:2049,hostfwd=tcp:0.0.0.0:20048-:20048,hostfwd=udp:0.0.0.0:20048-:20048 -device virtio-net-pci,netdev=net -virtfs local,path=/evidence,mount_tag=evidence,security_model=none
