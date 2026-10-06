"""Independent Flex WRITE durability, mirror data and native file audit."""
import collections
import hashlib
import json
import ipaddress
import pathlib
import sys

from audit_writes import XDR, operations, expected_file
from audit_uploads import payload


def validate_durability(writes, layouts, commits):
    expected = collections.Counter((fh, offset, len(data)) for fh, offset, data, stable, verifier in writes)
    assert expected == collections.Counter(layouts), 'unmatched Flex LAYOUTCOMMIT'
    required = collections.Counter((fh, offset, len(data), verifier) for fh, offset, data, stable, verifier in writes if stable < 2)
    assert required == collections.Counter(commits), 'missing or extraneous Flex COMMIT'
    by_file = collections.defaultdict(dict)
    for fh, offset, data, stable, verifier in writes:
        assert data and stable in (0, 1, 2) and len(verifier) == 8
        for i, value in enumerate(data):
            assert offset+i not in by_file[fh], 'overlapping native WRITE'
            by_file[fh][offset+i] = value
    return by_file



def validate_mirrors(writes_by_server, layouts, commits_by_server):
    assert writes_by_server and writes_by_server.keys()==commits_by_server.keys()
    replicas=[validate_durability(writes,layouts,commits_by_server[server]) for server,writes in writes_by_server.items()]
    assert all(replica==replicas[0] for replica in replicas), 'native mirror data differs'
    return replicas[0]


def audit(root, servers=('192.168.116.131',)):
    servers=tuple(str(ipaddress.IPv4Address(s)) for s in servers)
    assert 1<=len(servers)<=2 and len(set(servers))==len(servers)
    mapping, states, sizes, components, devices = {}, {}, {}, {}, {}
    layouts, seeds = [], collections.defaultdict(dict)
    grants = returns = 0
    capture = root/'ds-wire.pcap'
    for minor, fh, code, c, r in operations(capture,include_devices=True):
        if code == 50:
            assert c.u32() == 0 and c.u32() == 4 and c.u32() == 2
            assert c.u64() == 0 and c.u64() == 2**64-1 and c.u64() == 1
            c.take(16); assert c.u32() == 32768; c.done()
            r.u32(); r.take(16); assert r.u32() == 1
            assert r.u64() == 0 and r.u64() == 2**64-1
            assert r.u32() == 2 and r.u32() == 4
            b = XDR(r.opaque())
            assert b.u64() == 0 and b.u32() == len(servers)
            for _ in servers:
                assert b.u32()==1
                device=b.take(16); b.u32(); state=b.take(16)
                assert b.u32()==1; dsfh=b.opaque()
                b.opaque(); b.opaque()
                key=(device,dsfh)
                assert key not in components or components[key]==(fh,state)
                components[key]=(fh,state)
            assert b.u32()==0; b.u32(); b.done(); r.done()
            grants += 1
        elif code == 47:
            device=c.take(16); assert c.u32()==4; c.u32(); assert c.u32()==0; c.done()
            assert r.u32()==4; b=XDR(r.opaque()); addresses=[]
            for _ in range(b.u32()):
                assert b.opaque()==b'tcp'
                address,p1,p2=b.opaque().decode('ascii').rsplit('.',2)
                assert int(p1)*256+int(p2)==2049
                addresses.append(str(ipaddress.IPv4Address(address)))
            assert b.u32()==2
            for expected_minor in (2,1):
                assert b.u32()==4 and b.u32()==expected_minor
                assert b.u32()>0 and b.u32()>0 and b.u32()==1
            b.done(); assert r.u32()==0; r.done()
            assert device not in devices or devices[device]==addresses
            devices[device]=addresses
        elif code == 49:
            offset, length = c.u64(), c.u64()
            assert length > 0 and c.u32() == 0
            c.take(16); assert c.u32() == 1 and c.u64() == offset+length-1
            assert c.u32() == 0 and c.u32() == 4 and c.opaque() == b''
            c.done()
            sizes[fh] = max(sizes.get(fh,0),offset+length)
            if r.u32():
                assert r.u64() == sizes[fh]
            r.done(); layouts.append((fh, offset, length))
        elif code == 51:
            assert tuple(c.u32() for _ in range(4)) == (0, 4, 3, 1)
            assert c.u64() == 0 and c.u64() == 2**64-1
            c.take(16); assert c.opaque() == bytes(8); c.done()
            if r.u32(): r.take(16)
            r.done(); returns += 1
        elif code == 38:
            # Ordinary writes are permitted only for the eight initial range
            # test sources, independently matched below against the seed.
            c.take(16); offset = c.u64(); c.u32(); data = c.opaque(); c.done()
            accepted, stable, verifier = r.u32(), r.u32(), r.take(8); r.done()
            assert accepted == len(data) and stable in (0, 1, 2)
            for i, value in enumerate(data):
                assert offset+i not in seeds[fh], 'duplicate MDS seed/fallback WRITE'
                seeds[fh][offset+i] = value
            sizes[fh] = max(sizes.get(fh,0),offset+len(data))
        elif code == 5:
            # Ordinary MDS seed writes may need COMMIT; Flex data never uses it.
            c.u64(); c.u32(); c.done(); r.take(8); r.done()
    for (device,dsfh),(fh,state) in components.items():
        addresses=set(devices[device]) & set(servers)
        assert len(addresses)==1, 'device does not select one approved native DS'
        server=addresses.pop(); key=(server,dsfh)
        assert key not in mapping or mapping[key]==fh
        mapping[key],states[key]=fh,state
    writes_by_server,commits_by_server={},{}
    for server in servers:
        writes_by_server[server],commits_by_server[server]=[],[]
        for minor,dsfh,code,c,r in operations(capture,ds_only=True,server=server):
            assert minor==2
            fh=mapping[server,dsfh]
            if code==38:
                assert c.take(16)==states[server,dsfh]
                offset=c.u64(); assert c.u32()==2
                data=c.opaque(); c.done()
                accepted,stable,verifier=r.u32(),r.u32(),r.take(8); r.done()
                assert accepted==len(data)>0
                writes_by_server[server].append((fh,offset,data,stable,verifier))
            elif code==5:
                commits_by_server[server].append((fh,c.u64(),c.u32(),r.take(8))); c.done(); r.done()
            else: raise AssertionError('metadata operation sent to Flex DS')
    assert grants==returns==48 and len(mapping)==24*len(servers)
    by_file=validate_mirrors(writes_by_server,layouts,commits_by_server)
    writes=[w for items in writes_by_server.values() for w in items]
    commits=[c for items in commits_by_server.values() for c in items]
    source = payload()
    complete = source+bytes(257)+bytes([0xd3])*32785
    full_map = dict(enumerate(source))
    full_map.update({len(source)+257+i:0xd3 for i in range(32785)})
    partial_map = dict(enumerate(source[:32768]))
    range_map = {17+attempt*65571+i:0xa1+attempt for attempt in range(3) for i in range(65553)}
    kinds = collections.Counter()
    for fh, data in by_file.items():
        if data == full_map:
            kinds['complete'] += 1; assert fh not in seeds
        elif data == partial_map:
            kinds['partial'] += 1; assert fh not in seeds
        else:
            assert data == range_map
            assert seeds[fh] == dict(enumerate(source))
            kinds['range'] += 1
    assert kinds == {'complete':8,'partial':8,'range':8} and len(seeds) == 8
    native = {}
    for line in (root/'native-mds.txt').read_text().splitlines():
        name, address, obj = line.split('\t')
        assert address in servers
        name = pathlib.PurePosixPath(name.rstrip(':')).name
        assert (name,address) not in native
        native[name,address] = obj
    objects = {}
    for line in (root/'native-ds.txt').read_text().splitlines():
        fields=line.split('\t')
        if len(fields)==3:
            assert len(servers)==1
            fields=[servers[0]]+fields
        address,path,size,digest=fields
        assert address in servers
        key=(address,path.split('/storage/')[1])
        assert key not in objects
        objects[key]=(int(size),digest)
    profiles = [json.loads(p.read_text()) for p in (root/'upload-evidence').glob('*.json')]
    ranges = [json.loads(p.read_text()) for p in (root/'write-evidence').glob('*.json')]
    expected_profiles = {(os,v,m) for os in ('windows','linux') for v in ('4.1','4.2') for m in ('api','cli')}
    assert len(profiles) == len(ranges) == 8
    for items in (profiles,ranges):
        assert {(p['platform'],p['version'],p['mode']) for p in items} == expected_profiles
    files = []
    for profile in profiles:
        assert profile['partial'] == 32768
        files.extend(profile['files'])
    files.extend(ranges)
    assert len(files)==32 and len(native)==len(objects)==32*len(servers)
    assert len({(address,obj) for (name,address),obj in native.items()})==32*len(servers)
    for entry in files:
        name = entry['remote']
        data = expected_file() if name.startswith('pnfs-flex-write-') else b'' if name.endswith('-empty') else source[:32768] if name.endswith('-partial') else complete
        expected = (len(data),hashlib.sha256(data).hexdigest())
        for address in servers:
            assert (entry['size'],entry['sha256']) == objects[address,native[name,address]] == expected
    return dict(passed=True,native_profiles=16,native_files=32*len(servers),logical_files=32,mirrors=len(servers),layouts=grants,
                writes=len(writes),layoutcommits=len(layouts),ds_commits=len(commits),
                written_bytes=sum(len(w[2]) for w in writes),file_kinds=dict(kinds),
                empty_files=8,capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest())


if __name__ == '__main__':
    result = audit(pathlib.Path(sys.argv[1]),tuple(sys.argv[3:]) or ('192.168.116.131',))
    pathlib.Path(sys.argv[2]).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
