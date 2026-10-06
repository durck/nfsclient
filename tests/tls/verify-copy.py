#!/usr/bin/env python3
"""Independently verify intra-server COPY results and unchanged sources."""
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
source = bytes((i*31+i//257) % 251 for i in range(262144))
destination = bytearray(327680)
destination[:32768] = b'D'*32768
destination[32768:163840] = source[65536:196608]
destination[262144:] = source[:65536]
counts = collections.Counter()
files = []
for p in (run/'tree/data').iterdir():
    if p.name == 'seed':
        assert p.read_bytes() == b'kernel RPC-with-TLS fixture\n'
        continue
    if p.name == 'readonly':
        assert p.read_bytes() == b'immutable-space-fixture\n' and p.stat().st_mode & 0o7777 == 0o444
        continue
    if p.name == 'link':
        assert p.is_symlink() and os.readlink(p) == 'readonly'
        continue
    match = re.fullmatch(r'copy-(api|cli)-(windows|linux)-(?:(false|true)-)?\d+-(src|dst)', p.name)
    assert match, p
    kind, platform, locked, role = match.groups()
    counts[kind, platform, locked, role] += 1
    expected = source if role == 'src' else destination
    s = p.lstat()
    assert p.is_file() and not p.is_symlink()
    assert (s.st_uid, s.st_gid, s.st_mode & 0o7777, s.st_size) == (25001, 25000, 0o644, len(expected))
    assert p.read_bytes() == expected, p
    files.append(dict(name=p.name, bytes=s.st_size, sha256=hashlib.sha256(expected).hexdigest(), uid=s.st_uid, gid=s.st_gid, mode=oct(s.st_mode & 0o7777)))
wanted = {}
for platform in ('windows', 'linux'):
    for role in ('src', 'dst'):
        for locked in ('false', 'true'):
            wanted['api', platform, locked, role] = 1
        wanted['cli', platform, None, role] = 2
assert dict(counts) == wanted, counts
assert not subprocess.check_output(['exportfs', '-v']).strip()
for p in ('/srv/nfs-viewer-tls', '/etc/nfs.conf.d/99-nfs-viewer-tls.conf', '/etc/exports.d/nfs-viewer-tls.exports'):
    assert not pathlib.Path(p).exists()
print(json.dumps(dict(passed=True, files=files, domain_preserved=True, services_restored=True, clone_supported=False), indent=2))
