#!/bin/sh
set -eu
umask 077
python3 /provision.py
conf=/run/nfs-ad/etc/smb.conf
for user in alice bob disabled; do
    samba-tool domain exportkeytab /run/nfs-ad/$user.keytab --principal=$user --configfile=$conf
done
samba-tool user disable disabled --configfile=$conf
samba-tool domain exportkeytab /etc/krb5.keytab --principal=nfs/server.ad.nfs.test --configfile=$conf
samba -i --no-process-group --configfile=$conf > /run/nfs-ad/samba.log 2>&1 &
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if kinit -k -t /run/nfs-ad/alice.keytab -c /run/nfs-ad/alice.ccache alice@AD.NFS.TEST 2>/run/nfs-ad/readiness.log; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" != 1 ]; then
    cat /run/nfs-ad/readiness.log /run/nfs-ad/samba.log
    exit 1
fi
kinit -k -t /run/nfs-ad/bob.keytab -c /run/nfs-ad/bob.ccache bob@AD.NFS.TEST
rpcbind
echo 'Samba AD fixture ready'
exec ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf
