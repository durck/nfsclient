#!/bin/sh
# Run only inside a new disposable node image with the pinned SDK and FSAL.
set -eu
role=${1:?expected mds or ds}
: "${LAB_SUBNET:?explicit isolated Docker subnet required}"
: "${LAB_MASTER:?explicit lab master name required}"
case "$role" in mds|ds) ;; *) exit 2;; esac
export LD_LIBRARY_PATH=/opt/lizardfs/lib:/usr/lib
mkdir -p /lab/state /lab/chunks /var/run/ganesha /var/lib/nfs/ganesha
if [ "$role" = mds ]; then
    test ! -e /lab/state/metadata.mfs || { echo 'fresh metadata directory required' >&2; exit 1; }
    cp /lz-source/src/data/metadata.mfs /lab/state/metadata.mfs
    printf '%s / rw,alldirs,maproot=0\n' "$LAB_SUBNET" > /lab/exports.cfg
    cat > /lab/master.cfg <<EOF
WORKING_USER = root
WORKING_GROUP = root
DATA_PATH = /lab/state
EXPORTS_FILENAME = /lab/exports.cfg
PERSONALITY = master
OPERATIONS_DELAY_INIT = 0
EOF
    /opt/lizardfs/sbin/mfsmaster -d -c /lab/master.cfg start > /lab/storage.log 2>&1 &
    mds=true
    ds=false
else
    printf '/lab/chunks\n' > /lab/hdd.cfg
    cat > /lab/chunkserver.cfg <<EOF
WORKING_USER = root
WORKING_GROUP = root
DATA_PATH = /lab/state
MASTER_HOST = $LAB_MASTER
MASTER_PORT = 9420
HDD_CONF_FILENAME = /lab/hdd.cfg
HDD_LEAVE_SPACE_DEFAULT = 64MiB
EOF
    /opt/lizardfs/sbin/mfschunkserver -d -c /lab/chunkserver.cfg start > /lab/storage.log 2>&1 &
    mds=false
    ds=true
fi
storage=$!
trap 'kill "$storage" 2>/dev/null || true' EXIT
cat > /lab/ganesha.conf <<EOF
NFS_Core_Param {
 Protocols = 4;
 NFS_Port = 2049;
 Enable_NLM = false;
 Enable_RQUOTA = false;
 Plugins_Dir = /usr/lib/ganesha;
}
NFSV4 { Minor_Versions = 1, 2; Lease_Lifetime = 60; Grace_Period = 10; }
NFS_KRB5 { Active_krb5 = false; }
LizardFS { PNFS_MDS = $mds; PNFS_DS = $ds; }
EXPORT {
 Export_Id = 77;
 Path = /;
 Pseudo = /data;
 Access_Type = RW;
 Squash = No_Root_Squash;
 SecType = sys;
 Protocols = 4;
 Transports = TCP;
 FSAL { Name = LizardFS; hostname = $LAB_MASTER; port = "9421"; }
}
LOG { Default_Log_Level = EVENT; Components { PNFS = DEBUG; } }
EOF
# The native client initializes immediately; do not race master socket setup.
python3 - "$LAB_MASTER" <<'PY'
import socket
import sys
import time
deadline = time.monotonic() + 30
while True:
    try:
        with socket.create_connection((sys.argv[1], 9421), timeout=1):
            break
    except OSError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.2)
PY
if [ "${LAB_STORAGE_ONLY:-0}" = 1 ]; then
    wait "$storage"
    exit $?
fi
/opt/ganesha-lizard/bin/ganesha.nfsd -F -f /lab/ganesha.conf -L /lab/ganesha.log &
ganesha=$!
trap 'kill "$ganesha" "$storage" 2>/dev/null || true; wait || true' EXIT INT TERM
wait "$ganesha"
