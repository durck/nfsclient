"""Disposable SSSD KCM plus MIT KDC/Ganesha fixture; no host cache mounts."""
import os
from pathlib import Path
import signal
import subprocess
import time

os.umask(0o077)
root = Path("/run/nfs-test")
root.mkdir(parents=True, exist_ok=True)
socket = Path("/var/run/.heim_org.h5l.kcm-socket")
Path("/etc/sssd/sssd.conf").write_text(
    "[sssd]\nconfig_file_version = 2\nservices =\ndomains =\n"
    f"[kcm]\nsocket_path = {socket}\n"
    "ccache_storage = memory\ntgt_renewal = false\n", encoding="utf-8")
os.chmod("/etc/sssd/sssd.conf", 0o600)
conf = Path("/etc/krb5.conf").read_text(encoding="utf-8")
conf = conf.replace("[libdefaults]", f"[libdefaults]\n kcm_socket = {socket}")
Path("/etc/krb5.conf").write_text(conf, encoding="utf-8")
children = []

def stop(signum, frame):
    for child in children:
        child.terminate()
    raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
log = (root / "kcm.log").open("wb")
children.append(subprocess.Popen(["/usr/libexec/sssd/sssd_kcm", "--logger=stderr"], stdout=log, stderr=log))
children.append(subprocess.Popen(["sh", "/start.sh"]))
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    if children[0].poll() is not None:
        raise SystemExit("native KCM exited; inspect test-owned kcm.log")
    if socket.exists() and (root / "client.keytab").exists():
        init = subprocess.run(["kinit", "-k", "-t", str(root / "client.keytab"), "-c", "KCM:0:nfs-viewer", "root@NFS.TEST"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if init.returncode == 0:
            (root / "kcm.ready").write_text("READY\n", encoding="utf-8")
            break
    time.sleep(0.1)
else:
    raise SystemExit("native KCM/KDC initialization timeout")
while all(child.poll() is None for child in children):
    time.sleep(0.2)
raise SystemExit("native fixture process stopped")
