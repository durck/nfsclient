#!/bin/sh
set -eu
umask 077
test ! -e /evidence/kdc.ready
mkdir -m 700 /evidence/credentials
mkdir -p /var/lib/krb5kdc
cat > /etc/krb5kdc/kdc.conf <<'EOF'
[realms]
 NFS.TEST = {
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  default_principal_flags = +preauth
  disable_pac = true
 }
EOF
master=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
kdb5_util create -s -P "$master" >/dev/null 2>&1
unset master
for name in alice bob; do
 kadmin.local -q "addprinc -randkey $name@NFS.TEST" >/dev/null 2>&1
 kadmin.local -q "ktadd -norandkey -k /evidence/credentials/$name.keytab $name@NFS.TEST" >/dev/null 2>&1
done
kadmin.local -q 'addprinc -randkey nfs/server.nfs.test@NFS.TEST' >/dev/null 2>&1
kadmin.local -q 'ktadd -norandkey -k /evidence/credentials/server.keytab nfs/server.nfs.test@NFS.TEST' >/dev/null 2>&1
krb5kdc -n &
kdc_pid=$!
trap 'kill "$kdc_pid" 2>/dev/null || true; rm -f /evidence/credentials/alice.keytab /evidence/credentials/bob.keytab /evidence/credentials/server.keytab /evidence/credentials/alice.ccache' EXIT INT TERM
attempt=0
until kinit -k -t /evidence/credentials/alice.keytab -c FILE:/evidence/credentials/alice.ccache alice@NFS.TEST; do
 attempt=$((attempt + 1))
 test "$attempt" -lt 20
 sleep 1
done
printf 'READY\n' > /evidence/kdc.ready
wait "$kdc_pid"
