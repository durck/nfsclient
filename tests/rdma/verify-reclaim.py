#!/usr/bin/env python3
"""Independent retained-content and restart-fixture oracle for reclaim."""
import hashlib
import json
import pathlib
import subprocess
import sys

run = pathlib.Path(sys.argv[1]).resolve()
assert run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and run.name.startswith('rdma-')
e = json.loads((run/'evidence.json').read_text())
assert e['passed'] and e['domain_preserved'] and e['before'] == e['after']
assert e['services_before'] == e['services_after'] and e['owned_modules_removed'] and e['rdma_device_removed']
assert e['restart_tokens'] == list('123456123456'), e['restart_tokens']
payload = b'reclaimed state\0'*4096
expected = set()
for os in ('windows', 'linux'):
    for version in ('4.0', '4.1', '4.2'):
        expected.update(('reclaim-%s-%s' % (os, version), 'reclaim-%s-%s-range' % (os, version), 'reclaim-cli-%s-%s' % (os, version)))
files = []
for p in (run/'tree/data').iterdir():
    if p.name == 'seed':
        assert p.read_bytes() == b'real software-iWARP NFS fixture\n'
        continue
    assert p.name in expected
    expected.remove(p.name)
    s = p.lstat()
    assert p.is_file() and not p.is_symlink() and p.read_bytes() == payload
    assert (s.st_uid, s.st_gid, s.st_mode & 0o7777) == (25001, 25000, 0o644)
    files.append(dict(name=p.name, bytes=s.st_size, sha256=hashlib.sha256(payload).hexdigest()))
assert not expected
assert not subprocess.check_output(['exportfs', '-v']).strip()
for p in ('/srv/nfs-viewer-rdma', '/etc/nfs.conf.d/99-nfs-viewer-rdma.conf', '/etc/exports.d/nfs-viewer-rdma.exports', '/sys/class/infiniband/nvfs-siw'):
    assert not pathlib.Path(p).exists()
print(json.dumps(dict(passed=True, files=files, real_server_restarts=12, native_bytes_and_metadata=True, modules_and_services_restored=True), indent=2))
