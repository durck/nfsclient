#!/bin/sh
set -eu
umask 077
# Three independent databases, with only CLIENT -> MID -> NFS trust keys.
# No direct CLIENT -> NFS trust and no copy of Alice into another realm.
for slug in client mid; do
 case "$slug" in
  client) realm=CLIENT.TEST ;;
  mid) realm=MID.TEST ;;
 esac
 mkdir -p "/run/nfs-test/$slug-realm"
 profile="/run/nfs-test/$slug-realm/kdc.conf"
 cat > "$profile" <<EOF
[realms]
 $realm = {
  database_name = /run/nfs-test/$slug-realm/principal
  key_stash_file = /run/nfs-test/$slug-realm/stash
 }
[logging]
 kdc = FILE:/run/nfs-test/$slug-realm/kdc.log
EOF
 master=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
 KRB5_KDC_PROFILE="$profile" kdb5_util -r "$realm" -d "/run/nfs-test/$slug-realm/principal" create -s -P "$master" >/dev/null
 unset master
done
home_admin() { KRB5_KDC_PROFILE=/run/nfs-test/client-realm/kdc.conf kadmin.local -r CLIENT.TEST -d /run/nfs-test/client-realm/principal "$@"; }
mid_admin() { KRB5_KDC_PROFILE=/run/nfs-test/mid-realm/kdc.conf kadmin.local -r MID.TEST -d /run/nfs-test/mid-realm/principal "$@"; }
home_admin -q 'addprinc -randkey -e aes256-cts-hmac-sha1-96:normal alice@CLIENT.TEST' >/dev/null
home_admin -q 'ktadd -norandkey -k /run/nfs-test/foreign.keytab alice@CLIENT.TEST' >/dev/null
trust=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
home_admin -q "addprinc -requires_preauth -e aes256-cts-hmac-sha1-96:normal -kvno 1 -pw $trust krbtgt/MID.TEST@CLIENT.TEST" >/dev/null
mid_admin -q "addprinc -requires_preauth -e aes256-cts-hmac-sha1-96:normal -kvno 1 -pw $trust krbtgt/MID.TEST@CLIENT.TEST" >/dev/null
unset trust
trust=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
mid_admin -q "addprinc -requires_preauth -e aes256-cts-hmac-sha1-96:normal -kvno 1 -pw $trust krbtgt/NFS.TEST@MID.TEST" >/dev/null
kadmin.local -q "addprinc -requires_preauth -e aes256-cts-hmac-sha1-96:normal -kvno 1 -pw $trust krbtgt/NFS.TEST@MID.TEST" >/dev/null
unset trust
# MIT KDC routing and server transited policy, not client-side capaths support.
sed 's/default_realm = CLIENT.TEST/default_realm = NFS.TEST/' /multi-hop.conf > /etc/krb5.conf
cat >> /etc/krb5.conf <<'EOF'
[capaths]
 CLIENT.TEST = {
  MID.TEST = .
  NFS.TEST = MID.TEST
 }
 MID.TEST = {
  NFS.TEST = .
 }
EOF
cp /multi-hop.conf /run/nfs-test/cross.conf
printf '\nalice@CLIENT.TEST = alice\n' >> /etc/idmapd.conf
KRB5_KDC_PROFILE=/run/nfs-test/client-realm/kdc.conf krb5kdc -d /run/nfs-test/client-realm/principal -p 20088 -P /run/nfs-test/client-realm.pid -r CLIENT.TEST
KRB5_KDC_PROFILE=/run/nfs-test/mid-realm/kdc.conf krb5kdc -d /run/nfs-test/mid-realm/principal -p 30088 -P /run/nfs-test/mid-realm.pid -r MID.TEST
for attempt in 1 2 3 4 5; do
 if KRB5_CONFIG=/run/nfs-test/cross.conf kinit -k -t /run/nfs-test/foreign.keytab -c /run/nfs-test/foreign.ccache alice@CLIENT.TEST 2>/run/nfs-test/client-init.err; then
  echo 'Three-realm fixture ready: CLIENT.TEST -> MID.TEST -> NFS.TEST'
  exit 0
 fi
 sleep 0.2
done
cat /run/nfs-test/client-init.err >&2
exit 1
