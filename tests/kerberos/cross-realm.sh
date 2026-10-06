#!/bin/sh
set -eu
umask 077
mkdir -p /run/nfs-test/client-realm
client_db=/run/nfs-test/client-realm/principal
client_profile=/run/nfs-test/client-realm/kdc.conf
cat > "$client_profile" <<'EOF'
[realms]
 CLIENT.TEST = {
  database_name = /run/nfs-test/client-realm/principal
  key_stash_file = /run/nfs-test/client-realm/stash
 }
[logging]
 kdc = STDERR
EOF
home_admin() { KRB5_KDC_PROFILE="$client_profile" kadmin.local -r CLIENT.TEST -d "$client_db" "$@"; }
# Independent home realm; no user or service keys are copied from NFS.TEST.
master=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
KRB5_KDC_PROFILE="$client_profile" kdb5_util -r CLIENT.TEST -d "$client_db" create -s -P "$master" >/dev/null
unset master
home_admin -q 'addprinc -randkey -e aes256-cts-hmac-sha1-96:normal alice@CLIENT.TEST' >/dev/null
home_admin -q 'ktadd -norandkey -k /run/nfs-test/foreign.keytab alice@CLIENT.TEST' >/dev/null
# One-way direct trust: CLIENT.TEST users can request NFS.TEST service tickets.
# The same random trust secret, enctype and kvno are installed in both databases.
trust=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
home_admin -q "addprinc -requires_preauth -e aes256-cts-hmac-sha1-96:normal -kvno 1 -pw $trust krbtgt/NFS.TEST@CLIENT.TEST" >/dev/null
kadmin.local -q "addprinc -requires_preauth -e aes256-cts-hmac-sha1-96:normal -kvno 1 -pw $trust krbtgt/NFS.TEST@CLIENT.TEST" >/dev/null
unset trust
cp /cross.conf /run/nfs-test/cross.conf
# Deliberate server-side mapping of exactly one foreign test principal.
printf '\nalice@CLIENT.TEST = alice\n' >> /etc/idmapd.conf
# krb5kdc applies preceding database/port options when it processes each -r.
KRB5_KDC_PROFILE="$client_profile" krb5kdc -d "$client_db" -p 20088 -P /run/nfs-test/client-realm.pid -r CLIENT.TEST
for attempt in 1 2 3 4 5; do
 if KRB5_CONFIG=/run/nfs-test/cross.conf kinit -k -t /run/nfs-test/foreign.keytab -c /run/nfs-test/foreign.ccache alice@CLIENT.TEST 2>/run/nfs-test/client-init.err; then
  exit 0
 fi
 sleep 0.2
done
cat /run/nfs-test/client-init.err >&2
exit 1
