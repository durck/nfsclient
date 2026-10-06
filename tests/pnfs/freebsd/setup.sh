#!/bin/sh
# Disposable stock FreeBSD 14.4 pNFS FILE-layout fixture. See tests/README.md.
set -eu
umask 077

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
    cat >&2 <<'EOF'
Usage: setup.sh prepare|start|status mds|ds
Required environment: LAB_TAG, LAB_MASTER, LAB_DATA_SERVER, LAB_CLIENT_CIDR
Use numeric IPv4 addresses and a CIDR subnet for this disposable lab.
EOF
    exit 2
}

[ "$#" -eq 2 ] || usage
action=$1
role=$2
case "$action" in prepare|start|status) ;; *) usage ;; esac
case "$role" in mds|ds) ;; *) usage ;; esac
[ "$(uname -s)" = FreeBSD ] || fail 'This script runs only on FreeBSD.'
[ "$(id -u)" = 0 ] || fail 'Run as root on a newly created fixture VM.'
case "$(uname -r)" in
    14.4-RELEASE|14.4-RELEASE-p[0-9]*) ;;
    *) fail 'Expected the pinned FreeBSD 14.4-RELEASE family.' ;;
esac

: "${LAB_TAG:?Set a new short lowercase fixture tag}"
: "${LAB_MASTER:?Set the MDS IPv4 address}"
: "${LAB_DATA_SERVER:?Set the DS IPv4 address}"
: "${LAB_CLIENT_CIDR:?Set the explicit client IPv4 subnet/CIDR}"
case "$LAB_TAG" in ''|*[!a-z0-9-]*|-*|*-) fail 'Invalid LAB_TAG.' ;; esac
[ "${#LAB_TAG}" -le 32 ] || fail 'LAB_TAG must be at most 32 characters.'

ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 { exit 1 }
        { for (i = 1; i <= 4; i++)
            if ($i !~ /^[0-9]+$/ || length($i) > 3 || $i + 0 > 255) exit 1 }
    '
}
ipv4 "$LAB_MASTER" || fail 'LAB_MASTER must be a numeric IPv4 address.'
ipv4 "$LAB_DATA_SERVER" || fail 'LAB_DATA_SERVER must be a numeric IPv4 address.'
[ "$LAB_MASTER" != "$LAB_DATA_SERVER" ] || fail 'MDS and DS require separate VMs.'
case "$LAB_CLIENT_CIDR" in */*) ;; *) fail 'LAB_CLIENT_CIDR needs a prefix length.' ;; esac
network=${LAB_CLIENT_CIDR%/*}
prefix=${LAB_CLIENT_CIDR##*/}
ipv4 "$network" || fail 'Invalid client subnet address.'
case "$prefix" in ''|*[!0-9]*) fail 'Invalid client subnet prefix.' ;; esac
[ "${#prefix}" -le 2 ] && [ "$prefix" -ge 1 ] && [ "$prefix" -le 32 ] ||
    fail 'Use an explicit IPv4 prefix between 1 and 32.'

root=/var/db/nfs-viewer-pnfs-$LAB_TAG
if [ "$role" = mds ]; then bind=$LAB_MASTER; else bind=$LAB_DATA_SERVER; fi
ifconfig -a | awk -v ip="$bind" '$1 == "inet" && $2 == ip { found = 1 }
    END { exit !found }' || fail "This VM does not own the selected $role address $bind."

configuration() {
    printf 'role=%s\ntag=%s\nmaster=%s\ndata_server=%s\nclient_cidr=%s\n' \
        "$role" "$LAB_TAG" "$LAB_MASTER" "$LAB_DATA_SERVER" "$LAB_CLIENT_CIDR"
}

no_existing_nfs() {
    if pgrep -x 'nfsd|mountd|nfsuserd' >/dev/null; then
        fail 'Existing NFS daemons found; use a fresh fixture VM.'
    fi
    if [ -f /etc/exports ] && awk '
        /^[[:space:]]*(#|$)/ { next } { found = 1 }
        END { exit !found }' /etc/exports; then
        fail 'Existing /etc/exports configuration found; use a fresh fixture VM.'
    fi
    if sockstat -4 -l -P tcp -p 2049 | awk 'NR > 1 { found = 1 }
        END { exit !found }'; then
        fail 'TCP port 2049 is already occupied.'
    fi
}

if [ "$action" = prepare ]; then
    no_existing_nfs
    [ ! -e "$root" ] && [ ! -L "$root" ] || fail "Refusing to reuse $root."
    if [ "$role" = mds ]; then
        [ ! -L /boot/loader.conf ] || fail 'Refusing to edit a loader.conf symlink.'
        for loader in /boot/loader.conf /boot/loader.conf.local /boot/loader.conf.d/*.conf; do
            [ -f "$loader" ] || continue
            if awk '/^[[:space:]]*#/ { next }
                /vfs[.]nfsd[.]layouthighwater[[:space:]]*=/ { found = 1 }
                END { exit !found }' "$loader"; then
                fail "Existing layout high-water setting in $loader; use a fresh VM."
            fi
        done
    fi
    mkdir -m 0700 "$root"
    configuration > "$root/fixture.conf"
    if [ "$role" = ds ]; then
        mkdir -m 0700 "$root/storage"
        n=0
        while [ "$n" -lt 20 ]; do
            mkdir -m 0700 "$root/storage/ds$n"
            n=$((n + 1))
        done
        chown -R 0:0 "$root/storage"
        cat > "$root/exports" <<EOF
$root/storage -maproot=root -sec=sys $LAB_MASTER
$root/storage -sec=sys -network $LAB_CLIENT_CIDR
V4: $root/storage -sec=sys -network $LAB_CLIENT_CIDR
EOF
    else
        mkdir -m 0700 "$root/ds-mount"
        mkdir -m 1777 "$root/export"
        chown 25001:25000 "$root/export"
        # Set mode after chown: chown may clear special permission bits.
        chmod 1777 "$root/export"
        cat > "$root/exports" <<EOF
$root/export -sec=sys -network $LAB_CLIENT_CIDR
V4: $root/export -sec=sys -network $LAB_CLIENT_CIDR
EOF
        cat >> /boot/loader.conf <<EOF

# BEGIN nfs-viewer-pnfs-$LAB_TAG
vfs.nfsd.layouthighwater="1"
# END nfs-viewer-pnfs-$LAB_TAG
EOF
        printf '%s\n' 'MDS loader configuration written. Reboot this fixture VM before start.'
    fi
    printf 'Prepared %s at %s. No NFS service was started.\n' "$role" "$root"
    exit 0
fi

[ -d "$root" ] && [ ! -L "$root" ] && [ -f "$root/fixture.conf" ] ||
    fail 'Run prepare with these exact settings first.'
[ "$(configuration)" = "$(cat "$root/fixture.conf")" ] ||
    fail 'Settings do not match the prepared fixture.'

if [ "$action" = start ]; then
    no_existing_nfs
    [ ! -e "$root/started" ] || fail 'Fixture has already been started; inspect it manually.'
    if ! sysctl -n vfs.nfsd.server_max_nfsvers >/dev/null 2>&1; then
        kldload nfsd
    fi
    sysctl vfs.nfs.enable_uidtostring=1 vfs.nfsd.enable_stringtouid=1
    sysctl vfs.nfsd.server_min_nfsvers=4 vfs.nfsd.server_max_nfsvers=4
    sysctl vfs.nfsd.nfs_privport=0 vfs.nfsd.default_flexfile=0
    if [ "$role" = mds ]; then
        [ "$(sysctl -n vfs.nfsd.layouthighwater)" = 1 ] ||
            fail 'MDS layouthighwater is not 1. Reboot after prepare; do not patch the server.'
        # Each VM uses the same tag; the DS exports its storage as the NFSv4 root.
        mount -t nfs -o nfsv4,minorversion=2,soft,retrans=2 \
            "$LAB_DATA_SERVER:/" "$root/ds-mount"
    fi
    if ! pgrep -x rpcbind >/dev/null; then
        rpcbind
        printf '%s\n' 'rpcbind was started by this fixture' > "$root/rpcbind-owned"
    fi
    mountd -h "$bind" "$root/exports"
    if [ "$role" = mds ]; then
        nfsd -t -h "$bind" --minthreads 4 --maxthreads 16 \
            -p "$LAB_DATA_SERVER:$root/ds-mount"
    else
        nfsd -t -h "$bind" --minthreads 4 --maxthreads 16
    fi
    # Keep stock daemon PIDs as cleanup evidence; never stop an unrelated PID.
    pgrep -x nfsd > "$root/nfsd.pids"
    pgrep -x mountd > "$root/mountd.pids"
    if [ -f "$root/rpcbind-owned" ]; then pgrep -x rpcbind > "$root/rpcbind.pids"; fi
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$root/started"
    printf 'Started stock %s; review status and protocol evidence before calling the fixture validated.\n' "$role"
fi

configuration
freebsd-version -kru
uname -a
sha256 /boot/kernel/kernel /usr/sbin/nfsd /usr/sbin/mountd
sysctl vfs.nfsd.layouthighwater vfs.nfsd.default_flexfile \
    vfs.nfsd.server_min_nfsvers vfs.nfsd.server_max_nfsvers
sockstat -4 -l -P tcp -p 2049
if [ "$role" = mds ]; then
    mount -t nfs
    stat -f 'path=%N uid=%u gid=%g mode=%Lp' "$root/export"
else
    stat -f 'path=%N uid=%u gid=%g mode=%Lp' "$root/storage" "$root/storage"/ds*
fi
