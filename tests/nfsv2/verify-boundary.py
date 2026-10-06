#!/usr/bin/env python3
"""Native oracle for four complete, retained NFSv2 boundary transfers."""
import hashlib
import json
import pathlib
import subprocess

root = pathlib.Path('/data')
assert subprocess.check_output(['stat', '-f', '-c', '%T', str(root)]).strip() == b'tmpfs'
size = (1 << 31)-1
block = bytes(range(251))*4096
expected = hashlib.sha256()
remaining = size
while remaining:
    n = min(remaining, len(block))
    expected.update(block[:n])
    remaining -= n
digest = expected.hexdigest()
files = []
for platform in ('linux', 'windows'):
    for transport in ('tcp', 'udp'):
        p = root/('boundary-full-'+platform+'-'+transport)
        s = p.lstat()
        assert p.is_file() and not p.is_symlink() and s.st_size == size
        assert (s.st_uid, s.st_gid, s.st_mode & 0o7777) == (20001, 20001, 0o600)
        with p.open('rb') as f:
            actual = hashlib.file_digest(f, 'sha256').hexdigest()
        assert actual == digest, p
        files.append(dict(name=p.name, bytes=s.st_size, sha256=actual, uid=s.st_uid, gid=s.st_gid, mode='0600'))
assert not list(root.glob('.nfs-upload-*'))
assert (root/'public.txt').read_bytes() == b'NFSv2 fixture\n'
assert pathlib.Path('/readonly/seed').read_bytes() == b'read-only-seed\n'
print(json.dumps(dict(passed=True, bytes_per_file=size, files=files, independently_computed_pattern=True, no_staging_leftovers=True), indent=2))
