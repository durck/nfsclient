#!/usr/bin/env python3
"""Verify resumed upload bytes/metadata independently after fixture shutdown."""
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
payload = bytes((i*31+i//257) % 251 for i in range(262144))*4+b'upload-resume-end!'
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
    match = re.fullmatch(r'reput-(api|cli)-(windows|linux)-(4\.[012])-\d+', p.name)
    assert match, p
    kind, platform, version = match.groups()
    counts[kind, platform, version] += 1
    s = p.lstat()
    assert p.is_file() and not p.is_symlink()
    assert (s.st_uid, s.st_gid, s.st_mode & 0o7777, s.st_size) == (25001, 25000, 0o644, len(payload))
    assert p.read_bytes() == payload, p
    files.append(dict(name=p.name, bytes=s.st_size, sha256=hashlib.sha256(payload).hexdigest(), uid=s.st_uid, gid=s.st_gid, mode=oct(s.st_mode & 0o7777)))
wanted = {}
for platform in ('windows', 'linux'):
    for version in ('4.0', '4.1', '4.2'):
        wanted['api', platform, version] = 1
        wanted['cli', platform, version] = 2
assert dict(counts) == wanted, counts
assert not subprocess.check_output(['exportfs', '-v']).strip()
for p in ('/srv/nfs-viewer-tls', '/etc/nfs.conf.d/99-nfs-viewer-tls.conf', '/etc/exports.d/nfs-viewer-tls.exports'):
    assert not pathlib.Path(p).exists()
print(json.dumps(dict(passed=True, files=files, domain_preserved=True, services_restored=True), indent=2))
