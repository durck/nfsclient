#!/usr/bin/env python3
"""Native byte/metadata/xattr oracle, independent of the NFS client codec."""
import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

run = pathlib.Path(sys.argv[1]).resolve()
assert run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and run.name.startswith('tls-')
evidence = json.loads((run/'evidence.json').read_text())
assert evidence['passed'] and evidence['domain_preserved']
assert evidence['before'] == evidence['after'] and evidence['services_before'] == evidence['services_after']
payload = b'xattr metadata fixture\n'
counts = collections.Counter()
files = []
for p in (run/'tree/data').iterdir():
    if p.name == 'seed':
        assert p.read_bytes() == b'kernel RPC-with-TLS fixture\n'
        continue
    if p.name == 'readonly':
        assert p.read_bytes() == b'immutable-space-fixture\n' and p.stat().st_mode & 0o7777 == 0o444
        assert not os.listxattr(p)
        continue
    if p.name == 'link':
        assert p.is_symlink() and os.readlink(p) == 'readonly'
        continue
    match = re.fullmatch(r'xattr-(api|cli)-(windows|linux)-(?:(true|false)-)?\d+(-dir)?', p.name)
    assert match, p
    kind, platform, locked, directory = match.groups()
    counts[kind, platform, bool(directory)] += 1
    s = p.lstat()
    assert not p.is_symlink() and (s.st_uid, s.st_gid) == (25001, 25000)
    if directory:
        assert kind == 'api' and p.is_dir() and not list(p.iterdir()) and s.st_mode & 0o7777 == 0o755
        expected = {'user.directory': payload}
    else:
        assert p.is_file() and s.st_mode & 0o7777 == 0o644 and p.read_bytes() == payload
        if kind == 'api':
            expected = {'user.binary': bytes(range(256))*4, 'user.empty': b'', 'user.пример': b'UTF-8 key'}
            expected.update({'user.entry-%02d' % i: bytes((i, 0, 255)) for i in range(20)})
        else:
            expected = {'user.binary': bytes((2, 3, 255)), 'user.empty': b''}
    actual = {name: os.getxattr(p, name) for name in os.listxattr(p)}
    assert actual == expected, (p, actual.keys(), expected.keys())
    files.append(dict(name=p.name, directory=bool(directory), xattrs={k: hashlib.sha256(v).hexdigest() for k, v in sorted(actual.items())}))
assert dict(counts) == {(kind, platform, directory): 2 for platform in ('windows', 'linux') for kind, directory in (('api', False), ('api', True), ('cli', False))}, counts
assert not subprocess.check_output(['exportfs', '-v']).strip()
for p in ('/srv/nfs-viewer-tls', '/etc/nfs.conf.d/99-nfs-viewer-tls.conf', '/etc/exports.d/nfs-viewer-tls.exports'):
    assert not pathlib.Path(p).exists()
print(json.dumps(dict(passed=True, objects=files, native_xattrs_verified=True, domain_preserved=True, services_restored=True), indent=2))
