#!/usr/bin/env python3
"""Check actual native extents, content and restored services after space tests."""
import collections
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
import subprocess
import struct
import sys

run=pathlib.Path(sys.argv[1]).resolve()
assert run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and run.name.startswith('tls-')
evidence=json.loads((run/'evidence.json').read_text())
assert evidence['passed'] and evidence['domain_preserved']
assert evidence['before']==evidence['after'] and evidence['services_before']==evidence['services_after']
expected=bytearray(393216)
expected[:65536]=b'Z'*65536
expected[131072:262144]=b'Z'*131072
counts=collections.Counter()
files=[]
for p in (run/'tree/data').iterdir():
    if p.name=='seed':
        assert p.read_bytes()==b'kernel RPC-with-TLS fixture\n'
        continue
    if p.name=='readonly':
        assert p.read_bytes()==b'immutable-space-fixture\n' and p.stat().st_mode & 0o7777 == 0o444
        continue
    if p.name=='link':
        assert p.is_symlink() and os.readlink(p)=='readonly'
        continue
    match=re.fullmatch(r'space-(api|cli)-(windows|linux)-(?:(false|true)-)?\d+',p.name)
    assert match,p
    kind,platform,locked=match.groups()
    counts[kind,platform,locked]+=1
    s=p.lstat()
    assert p.is_file() and not p.is_symlink()
    assert (s.st_uid,s.st_gid,s.st_mode & 0o7777,s.st_size)==(25001,25000,0o644,393216)
    assert p.read_bytes()==expected
    # Unwritten allocated tail occupies storage despite reading as zero.
    assert 327680 <= s.st_blocks*512 < 393216
    with p.open('rb') as f:
        assert os.lseek(f.fileno(),0,os.SEEK_HOLE)==65536
        assert os.lseek(f.fileno(),65536,os.SEEK_DATA)==131072
        tail_hole=os.lseek(f.fileno(),262144,os.SEEK_HOLE)
        assert 262144 <= tail_hole <= 393216
        try:
            tail_data=os.lseek(f.fileno(),262144,os.SEEK_DATA)
            assert 262144 <= tail_data < 393216
        except OSError as exc:
            assert exc.errno==errno.ENXIO
            tail_data=None
        # SEEK can classify cached zero pages in an unwritten extent as DATA.
        # FIEMAP independently distinguishes reservation from initialized data.
        mapping=bytearray(32+56*16)
        struct.pack_into('=QQIIII',mapping,0,0,2**64-1,1,0,16,0)
        fcntl.ioctl(f.fileno(),0xC020660B,mapping,True)
        count=struct.unpack_from('=I',mapping,20)[0]
        assert 1 <= count <= 16
        extents=[]
        for i in range(count):
            logical,_,length,_,_,flags,_,_,_=struct.unpack_from('=QQQQQIIII',mapping,32+56*i)
            assert logical+length <= 393216
            assert logical+length <= 65536 or logical >= 131072
            extents.append(dict(offset=logical,length=length,unwritten=bool(flags&0x800)))
        assert flags&1
        assert sum(max(0,min(e['offset']+e['length'],393216)-max(e['offset'],262144)) for e in extents if e['unwritten'])==131072
    files.append(dict(name=p.name,bytes=s.st_size,allocated_bytes=s.st_blocks*512,sha256=hashlib.sha256(expected).hexdigest(),uid=s.st_uid,gid=s.st_gid,mode=oct(s.st_mode&0o7777),extents=extents,native_tail_hole=tail_hole,native_tail_data=tail_data))
wanted={}
for platform in ('windows','linux'):
    wanted['api',platform,'false']=1
    wanted['api',platform,'true']=1
    wanted['cli',platform,None]=2
assert dict(counts)==wanted
assert not subprocess.check_output(['exportfs','-v']).strip()
assert not pathlib.Path('/srv/nfs-viewer-tls').exists()
assert not pathlib.Path('/etc/nfs.conf.d/99-nfs-viewer-tls.conf').exists()
assert not pathlib.Path('/etc/exports.d/nfs-viewer-tls.exports').exists()
print(json.dumps(dict(passed=True,files=files,native_extents_verified=True,allocated_tail_verified=True,domain_preserved=True,services_restored=True),indent=2))
