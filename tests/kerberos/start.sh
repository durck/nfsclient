#!/bin/sh
set -eu
umask 077
mkdir -p /run/nfs-test /var/lib/krb5kdc
# Force real KRB_ERR_RESPONSE_TOO_BIG replies in a separate opt-in fixture.
if [ "${KRB5_TEST_SMALL_UDP:-0}" = 1 ]; then
 printf '[kdcdefaults]\n kdc_max_dgram_reply_size = 128\n' > /run/nfs-test/kdc.conf
 export KRB5_KDC_PROFILE=/run/nfs-test/kdc.conf
fi
# Disposable keys generated at startup; no credentials in the image or source.
master=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
kdb5_util create -s -P "$master" >/dev/null
unset master
enctype=${KRB5_TEST_ENCTYPE:-aes256-cts-hmac-sha1-96}
case "$enctype" in
 aes128-cts-hmac-sha1-96|aes256-cts-hmac-sha1-96) ;;
 *) echo 'Unsupported fixture enctype' >&2; exit 1 ;;
esac
# Restrict all principals to one enctype to make each interoperability run explicit.
kadmin.local -q "addprinc -randkey -e $enctype:normal root@NFS.TEST" >/dev/null
if [ "${KRB5_TEST_AS_ALIAS:-0}" = 1 ]; then
 # MIT 1.22+ DB2 aliases; the earlier base fixture intentionally cannot opt in.
 kadmin.local -q 'add_alias root-alias@NFS.TEST root@NFS.TEST' >/dev/null
 kadmin.local -q 'modprinc +requires_preauth root@NFS.TEST' >/dev/null
 if [ "${KRB5_TEST_AS_ENTERPRISE:-0}" = 1 ]; then
  kadmin.local -q 'add_alias root-alias\@NFS.TEST@NFS.TEST root@NFS.TEST' >/dev/null
 fi
fi
kadmin.local -q "addprinc -randkey -e $enctype:normal nfs/server.nfs.test@NFS.TEST" >/dev/null
if [ "${KRB5_TEST_SHORT_LIFE:-0}" = 1 ]; then
 kadmin.local -q 'modprinc -maxlife "4 seconds" nfs/server.nfs.test@NFS.TEST' >/dev/null
fi
kadmin.local -q 'ktadd -norandkey -k /run/nfs-test/client.keytab root@NFS.TEST' >/dev/null
for user in alice bob; do
 kadmin.local -q "addprinc -randkey -e $enctype:normal $user@NFS.TEST" >/dev/null
 kadmin.local -q "ktadd -norandkey -k /run/nfs-test/$user.keytab $user@NFS.TEST" >/dev/null
done
kadmin.local -q 'ktadd -norandkey -k /etc/krb5.keytab nfs/server.nfs.test@NFS.TEST' >/dev/null
if [ "${KRB5_TEST_MULTIHOP:-0}" = 1 ]; then
 sh /multi-hop.sh
elif [ "${KRB5_TEST_CROSS_REALM:-0}" = 1 ]; then
 sh /cross-realm.sh
fi
# Independent KDC process/database with a one-time snapshot of this disposable
# realm. This is a replica fixture, not a test of ongoing database replication.
if [ "${KRB5_TEST_REPLICA:-0}" = 1 ]; then
 mkdir -p /run/nfs-test/replica
 kdb5_util dump /run/nfs-test/replica.dump
 kdb5_util -d /run/nfs-test/replica/principal load /run/nfs-test/replica.dump
 rm /run/nfs-test/replica.dump
 krb5kdc -d /run/nfs-test/replica/principal -p 10088 -P /run/nfs-test/replica.pid
fi
krb5kdc
rpcbind
exec ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf
