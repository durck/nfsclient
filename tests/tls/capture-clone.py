#!/usr/bin/env python3
"""Capture independent bytes and FIEMAP sharing before unmounting a private image."""
import collections
import fcntl
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys

root, output = map(pathlib.Path, sys.argv[1:])
assert root == pathlib.Path('/srv/nfs-viewer-tls/data')
assert output.parent.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs')
filesystem = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(root)], text=True).strip()
assert filesystem in ('btrfs', 'xfs')
source = bytes((i*31+i//257) % 251 for i in range(262144))
counts = collections.Counter()
files = {}
for p in root.iterdir():
    if p.name == 'seed':
        assert p.read_bytes() == b'kernel RPC-with-TLS fixture\n'
        continue
    if p.name == 'readonly':
        assert p.read_bytes() == b'immutable-space-fixture\n' and p.stat().st_mode & 0o7777 == 0o444
        continue
    if p.name == 'link':
        assert p.is_symlink() and os.readlink(p) == 'readonly'
        continue
    match = re.fullmatch(r'clone-(api|cli)-(windows|linux)-(?:(false|true)-)?\d+-(src|dst|part)', p.name)
    assert match, p
    kind, platform, locked, role = match.groups()
    counts[kind, platform, locked, role] += 1
    expected = bytearray(source)
    if role == 'src' and kind == 'api':
        expected[:7] = b'changed'
    if role == 'part':
        expected = bytearray(b'D'*262144)
        expected[131072:196608] = source[65536:131072]
    s = p.lstat()
    assert p.is_file() and not p.is_symlink()
    assert (s.st_uid, s.st_gid, s.st_mode & 0o7777, s.st_size) == (25001, 25000, 0o644, 262144)
    assert p.read_bytes() == expected, p
    with p.open('rb') as f:
        mapping = bytearray(32+56*128)
        struct.pack_into('=QQIIII', mapping, 0, 0, 2**64-1, 1, 0, 128, 0)
        fcntl.ioctl(f.fileno(), 0xC020660B, mapping, True)
        count = struct.unpack_from('=I', mapping, 20)[0]
        assert 1 <= count <= 128
        extents = []
        for i in range(count):
            logical, physical, length, _, _, flags, _, _, _ = struct.unpack_from('=QQQQQIIII', mapping, 32+56*i)
            assert not flags & (2|4|8), 'unresolved FIEMAP extent'
            extents.append(dict(offset=logical, physical=physical, length=length, shared=bool(flags & 0x2000)))
        assert flags & 1
    files[p.name] = dict(name=p.name, bytes=s.st_size, sha256=hashlib.sha256(expected).hexdigest(), uid=s.st_uid, gid=s.st_gid, mode=oct(s.st_mode & 0o7777), extents=extents)
wanted = {}
for platform in ('windows', 'linux'):
    for locked in ('false', 'true'):
        for role in ('src', 'dst', 'part'):
            wanted['api', platform, locked, role] = 1
    for role in ('src', 'dst'):
        wanted['cli', platform, None, role] = 2
assert dict(counts) == wanted, counts

def physical(name, offset):
    e = next(e for e in files[name]['extents'] if e['offset'] <= offset < e['offset']+e['length'])
    assert e['shared'], (name, offset, e)
    return e['physical']+offset-e['offset']

pairs = []
for name in files:
    if name.endswith('-dst'):
        src = name[:-4]+'-src'
        assert physical(src, 65536) == physical(name, 65536)
        pairs.append([src, name])
    if name.endswith('-part'):
        src = name[:-5]+'-src'
        assert physical(src, 65536) == physical(name, 131072)
        pairs.append([src, name])
output.write_text(json.dumps(dict(passed=True, filesystem=filesystem, files=list(files.values()), shared_pairs=pairs, native_shared_extents=True, copy_on_write_bytes=True), indent=2)+'\n')
print('NATIVE_CLONE_VERIFIED')
