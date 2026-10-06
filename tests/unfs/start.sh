#!/bin/sh
set -eu
for path in /data /squashed /readonly /secure; do
 test "$(stat -f -c %T "$path")" = tmpfs || { echo "Fixture requires tmpfs at $path" >&2; exit 1; }
 chmod 0777 "$path"
done
mkdir /data/wide /data/shared /data/sticky /data/acl-inherit /squashed/private
chmod 0755 /data/wide
i=0
while [ "$i" -lt 300 ]; do
 name=$(printf 'entry-%03d.txt' "$i")
 printf 'fixture-%03d\n' "$i" > "/data/wide/$name"
 i=$((i + 1))
done
printf 'UNFS fixture\n' > /data/read.txt
ln -s read.txt /data/link.txt
ln -s missing /data/dangling
chown root:shared /data/shared
chmod 2770 /data/shared
chmod 1777 /data/sticky
chown alice:alice /data/acl-inherit
chmod 0700 /data/acl-inherit
setfacl -m u:bob:rx /data/acl-inherit
setfacl -d -m u::rwx,u:bob:rx,g::---,m::rwx,o::--- /data/acl-inherit
chmod 0700 /squashed/private
printf 'private fixture\n' > /squashed/private/file
chmod 0600 /squashed/private/file
printf 'read-only export\n' > /readonly/read.txt
chmod 0644 /readonly/read.txt
exec /usr/local/sbin/unfsd -d -p -n 2049 -m 20048 -e /etc/exports
