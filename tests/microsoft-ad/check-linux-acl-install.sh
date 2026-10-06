#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
test -f /.dockerenv
python3 /scripts/verify-linux-bundle.py check /bundle --profile posix-acl
printf 'deb [trusted=yes] file:/bundle ./\n' > /etc/apt/offline-acl.list
apt-get -o Dir::Etc::sourcelist=/etc/apt/offline-acl.list -o Dir::Etc::sourceparts=- update
apt-get -y --no-install-recommends --no-remove -o Dir::Etc::sourcelist=/etc/apt/offline-acl.list -o Dir::Etc::sourceparts=- install acl
apt-get check
test -z "$(dpkg --audit)"
python3 - <<'PY'
import importlib.util
import os
import pathlib
import subprocess
spec = importlib.util.spec_from_file_location("kernel_fixture", "/scripts/run-kernel-nfs.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
fixture.prepare_fixture("acl-container-check")
snapshot = fixture.acl_snapshot()
assert "default:user:20002:rwx" in snapshot
assert "default:mask::rwx" in snapshot
grant = str(fixture.ROOT / "data/acl/grant/read.txt")
assert "user:20002:r--" in fixture.command("getfacl", "-n", grant)
assert "default:" not in fixture.command("getfacl", "-n", str(fixture.ROOT / "data/acl/replace"))
def bob():
    os.setgroups([])
    os.setgid(20002)
    os.setuid(20002)
read = subprocess.run(["cat", grant], preexec_fn=bob, text=True, capture_output=True)
assert read.returncode == 0 and read.stdout == "acl grant fixture\n", read
write = subprocess.run(["python3", "-c", "import sys;open(sys.argv[1],'w').write('denied')", grant], preexec_fn=bob, text=True, capture_output=True)
assert write.returncode != 0 and "PermissionError" in write.stderr, write
assert pathlib.Path(grant).read_text() == "acl grant fixture\n"
foreign_owner = fixture.ROOT / "data/acl/mismatch/foreign-owner"
foreign_group = fixture.ROOT / "data/acl/mismatch/foreign-group"
assert (foreign_owner.stat().st_uid, foreign_owner.stat().st_gid, foreign_owner.stat().st_mode & 0o777) == (20002, 20001, 0o660)
assert (foreign_group.stat().st_uid, foreign_group.stat().st_gid, foreign_group.stat().st_mode & 0o777) == (20001, 20003, 0o640)
for path, expected in ((foreign_owner, "owner mismatch fixture\n"), (foreign_group, "group mismatch fixture\n")):
    result = subprocess.run(["cat", str(path)], preexec_fn=bob, text=True, capture_output=True)
    assert result.returncode == 0 and result.stdout == expected
def alice():
    os.setgroups([])
    os.setgid(20001)
    os.setuid(20001)
result = subprocess.run(["cat", str(foreign_owner)], preexec_fn=alice, text=True, capture_output=True)
assert result.returncode == 0 and result.stdout == "owner mismatch fixture\n"
print(snapshot)
print("NFS_LAB_CONTAINER_ACL_FIXTURE_COMPLETE: named-user read allowed; write denied; default ACL and replacement isolation verified")
PY
dpkg-query -W '-f=${Package}\t${Version}\t${db:Status-Status}\n' acl libacl1
echo NFS_LAB_CONTAINER_ACL_OFFLINE_INSTALL_COMPLETE
