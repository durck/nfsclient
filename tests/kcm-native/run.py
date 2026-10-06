"""Run real SSSD KCM/MIT/Ganesha evidence in a disposable, network-isolated container.

Usage: python tests/kcm-native/run.py --repository PATH --output PATH
Repository must contain authenticated Ubuntu indexes and selected packages from
prepare-repository.py. The runner mounts no host credentials and publishes no
ports. Test-generated credentials live only in the --rm container.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument("--repository", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
workspace = Path(__file__).resolve().parents[2]
repo, output = args.repository.resolve(), args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
for filename in ("start.py", "ubuntu.sources"):
    shutil.copyfile(Path(__file__).with_name(filename), repo / filename)
image = "nfs-viewer-kcm-native-test"
container = "nfs-kcm-native-" + uuid.uuid4().hex[:12]

def run(command, log=None, **kwargs):
    if log is None:
        return subprocess.run(command, check=True, cwd=workspace, **kwargs)
    with (output / log).open("w", encoding="utf-8") as stream:
        return subprocess.run(command, check=True, cwd=workspace, stdout=stream, stderr=subprocess.STDOUT, **kwargs)

run(["docker", "build", "--network", "none", "-f", str(Path(__file__).with_name("Dockerfile")), "-t", image, str(repo)], "build.log")
env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
for package in ("krbgss", "nfs"):
    run(["go", "test", "-c", "./internal/" + package, "-o", str(output / (package + ".test"))], env=env)
run(["docker", "run", "--rm", "--network", "none", "--hostname", "server.nfs.test", "--name", container, "-d", "-e", "KRB5_TEST_SHORT_LIFE=1", image], stdout=subprocess.DEVNULL)
try:
    deadline = time.monotonic() + 45
    while subprocess.run(["docker", "exec", container, "test", "-f", "/run/nfs-test/kcm.ready"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        if time.monotonic() >= deadline:
            raise RuntimeError("native KCM fixture readiness timeout")
        time.sleep(0.1)
    for package in ("krbgss", "nfs"):
        run(["docker", "cp", str(output / (package + ".test")), container + ":/tmp/" + package + ".test"])
    prefix = ["docker", "exec", "-e", "NFS_VIEWER_KCM_DAEMON_NATIVE=1", "-e", "NFS_VIEWER_KCM_NATIVE=1",
              "-e", "NFS_VIEWER_KCM_NAME=KCM:0:nfs-viewer", "-e", "NFS_VIEWER_KCM_SOCKET=/var/run/.heim_org.h5l.kcm-socket",
              "-e", "NFS_VIEWER_KRB5_CONFIG=/etc/krb5.conf", "-e", "NFS_VIEWER_KRB5_PORT=2049", "-e", "NFS_VIEWER_KRB5_MOUNT_PORT=20048", container]
    run(prefix + ["/tmp/krbgss.test", "-test.run=^TestKCM", "-test.v", "-test.count=1"], "krbgss-native.log")
    run(prefix + ["/tmp/nfs.test", "-test.run=^TestKCM", "-test.v", "-test.count=1"], "nfs-native.log")
    run(["docker", "exec", container, "dpkg-query", "-W", "sssd-kcm", "krb5-user", "nfs-ganesha"], "native-versions.txt")
    print("Native SSSD KCM provider and NFS lifecycle tests PASS; CGO_ENABLED=0.")
finally:
    subprocess.run(["docker", "stop", "--time", "3", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
