#!/bin/sh
set -eu
# Require disposable, separately mounted memory filesystems; never export the
# container overlay or a caller's host directory by accidental configuration.
for path in /data /squashed; do
 test "$(stat -f -c %T "$path")" = tmpfs || { echo "Fixture requires tmpfs at $path" >&2; exit 1; }
 chmod 0777 "$path"
done
mkdir /data/shared /data/sticky /data/acl /data/acl-inherit /squashed/root-only
chown root:shared /data/shared
chmod 2770 /data/shared
chmod 1777 /data/sticky
printf 'ACL fixture data\n' > /data/acl/read.txt
chmod 0700 /data/acl
chmod 0600 /data/acl/read.txt
setfacl -m u:bob:rx /data/acl
setfacl -m u:bob:r /data/acl/read.txt
# Alice owns the tree. Bob inherits read/traverse rights only; neither the
# owning group nor other users grant access, so mode bits cannot mask a bad test.
chown alice:alice /data/acl-inherit
chmod 0700 /data/acl-inherit
setfacl -m u:bob:rx /data/acl-inherit
setfacl -d -m u::rwx,u:bob:rx,g::---,m::rwx,o::--- /data/acl-inherit
chmod 0700 /squashed/root-only
printf 'root-only fixture data\n' > /squashed/root-only/private.txt
chmod 0600 /squashed/root-only/private.txt
exec sh /auth-start.sh
