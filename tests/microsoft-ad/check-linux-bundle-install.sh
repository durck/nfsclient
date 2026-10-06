#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
# Run only in a fresh disposable Ubuntu 24.04 container with --network none.
test -f /.dockerenv
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
printf 'deb [trusted=yes] file:/bundle ./\n' > /etc/apt/offline.list
apt-get -o Dir::Etc::sourcelist=/etc/apt/offline.list -o Dir::Etc::sourceparts=- update
apt-get -y --no-install-recommends --no-remove -o Dir::Etc::sourcelist=/etc/apt/offline.list -o Dir::Etc::sourceparts=- install nfs-kernel-server sssd-ad sssd-tools adcli krb5-user
apt-get check
test -z "$(dpkg --audit)"
dpkg-query -W '-f=${Package}\t${Version}\t${db:Status-Status}\n' nfs-kernel-server sssd-ad sssd-tools adcli krb5-user
echo NFS_LAB_CONTAINER_OFFLINE_INSTALL_COMPLETE
