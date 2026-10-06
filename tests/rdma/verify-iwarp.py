#!/usr/bin/env python3
"""Independent native filesystem oracle for the bounded iWARP transfer lane."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

run = pathlib.Path(sys.argv[1]).resolve()
assert run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and run.name.startswith('rdma-')
e = json.loads((run/'evidence.json').read_text())
assert e['passed'] and e['domain_preserved'] and e['before'] == e['after']
assert e['services_before'] == e['services_after']
assert e['owned_modules_removed'] and e['rdma_device_removed']
assert 'rdma 20049' in e['listeners'] and 'nvfs-siw/1 state ACTIVE' in e['rdma_link']
assert {'siw', 'rpcrdma'} <= set(e['modules_loaded'])
payload = bytes((i*17+i//251) % 256 for i in range((1 << 20)+17))
expected = {'iwarp-%s-%s-%s' % (kind, os, v) for kind in ('api', 'cli') for os in ('linux', 'windows') for v in ('4.0', '4.1', '4.2')}
found = set()
files = []
for p in (run/'tree/data').iterdir():
    if p.name == 'seed':
        assert p.read_bytes() == b'real software-iWARP NFS fixture\n'
        continue
    assert p.name in expected and p.name not in found
    found.add(p.name)
    s = p.lstat()
    assert p.is_file() and not p.is_symlink() and p.read_bytes() == payload
    assert (s.st_uid, s.st_gid, s.st_mode & 0o7777) == (25001, 25000, 0o644)
    files.append(dict(name=p.name, bytes=s.st_size, sha256=hashlib.sha256(payload).hexdigest()))
assert found == expected
assert not subprocess.check_output(['exportfs', '-v']).strip()
for p in ('/srv/nfs-viewer-rdma', '/etc/nfs.conf.d/99-nfs-viewer-rdma.conf', '/etc/exports.d/nfs-viewer-rdma.exports', '/sys/class/infiniband/nvfs-siw'):
    assert not pathlib.Path(p).exists()
print(json.dumps(dict(passed=True, files=files, real_iwarp_listener=True, native_bytes_and_metadata=True, modules_and_services_restored=True), indent=2))
