"""Independent capture/native-file checks for the bounded FreeBSD write matrix."""
import collections
import hashlib
import ipaddress
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'nlm/freebsd'))
from audit import XDR as BaseXDR, messages


class XDR(BaseXDR):
    def opaque(self):
        size = self.u32()
        assert size <= 2**20, 'oversized XDR field'
        data = self.take(size)
        self.take(-size % 4)
        return data


def operations(path, ds_only=False, server='192.168.116.130', include_devices=False):
    pairs = collections.defaultdict(dict)
    destinations={}
    for transport, key, data in messages(path):
        if transport != 'tcp' or 2049 not in (key[1], key[3]):
            continue
        xid, direction = struct.unpack('!II', data[:8])
        flow = tuple(sorted(((key[0], key[1]), (key[2], key[3]))))
        pair = pairs[flow, xid]
        if direction==0:destinations[flow,xid]=key[2]
        assert direction not in pair or pair[direction] == data, 'changed RPC replay'
        pair[direction] = data
    data_flows=set()
    for (flow,xid),pair in pairs.items():
        if 0 not in pair:
            continue
        if destinations[flow,xid]!=ipaddress.ip_address(server).packed.hex():continue
        c = XDR(pair[0]); c.take(8)
        if tuple(c.u32() for _ in range(4)) != (2, 100003, 4, 1):
            continue
        flavor, cred = c.u32(), XDR(c.opaque())
        if flavor != 1:
            continue
        cred.u32()
        if cred.opaque() != b'nfs-viewer':
            continue
        assert (cred.u32(), cred.u32(), cred.u32()) == (25001, 25000, 0)
        cred.done(); assert c.u32() == 0 and c.opaque() == b''
        c.opaque(); minor, total = c.u32(), c.u32()
        assert minor in (1, 2)
        prefix=[]; fh=None
        for index in range(total):
            code=c.u32()
            if code==53:
                c.take(32);prefix.append(code)
            elif code==22:
                fh=c.opaque();prefix.append(code)
            else:
                break
        else:
            continue
        if ds_only and code==42:
            c.take(8);owner=c.opaque();role=c.u32()
            if owner.startswith(b'nfs-viewer-') and role==0x40000:data_flows.add(flow)
            continue
        if ds_only and flow not in data_flows:
            continue
        if code not in ((5,38,47,49,50,51) if include_devices else (5,38,49,50,51)):
            continue
        assert (fh or code==47) and index==total-1 and 1 in pair, 'incomplete target operation'
        r=XDR(pair[1]);r.take(8)
        assert r.u32()==0;r.u32();r.opaque();assert r.u32()==0
        assert r.u32()==0, 'target operation failed'
        r.opaque();assert r.u32()==total
        for op in prefix:
            assert r.u32()==op and r.u32()==0
            if op==53:r.take(36)
        assert r.u32()==code and r.u32()==0
        yield minor,fh,code,c,r


def expected_file():
    data=bytearray((i*31+i//251)%256 for i in range((1<<20)+17))
    for attempt in range(3):
        offset=17+attempt*65571
        data[offset:offset+65553]=bytes([0xa1+attempt])*65553
    return bytes(data)


def validate_writes(writes, layouts, commits):
    by_file=collections.defaultdict(list)
    for fh,offset,data,stable,verifier in writes:
        assert len(verifier)==8 and stable in (0,1,2) and data
        by_file[fh].append((offset,data))
    assert len(by_file)==8, 'expected eight distinct files'
    expected=collections.Counter()
    for fh,chunks in by_file.items():
        offsets={}
        for offset,data in chunks:
            expected[fh,offset,len(data)]+=1
            for i,value in enumerate(data):
                assert offset+i not in offsets,'duplicate/overlapping write'
                offsets[offset+i]=value
        wanted={17+attempt*65571+i:0xa1+attempt for attempt in range(3) for i in range(65553)}
        assert offsets==wanted,'wrong write range or payload'
    assert collections.Counter(layouts)==expected, 'missing/duplicate/misplaced LAYOUTCOMMIT'
    for fh,offset,size,verifier in commits:
        assert any(f==fh and o==offset and len(d)==size and v==verifier for f,o,d,_,v in writes), 'unmatched COMMIT verifier/range'
    return sum(len(w[2]) for w in writes)


def audit(root):
    mappings={};layouts=[];mds_commits=[];returns=0;grants=0
    for minor,fh,code,c,r in operations(root/'mds-wire.pcap'):
        if code==50:
            assert c.u32()==0 and c.u32()==1 and c.u32()==2
            c.u64();c.u64();c.u64();c.take(16);c.u32();c.done()
            r.u32();r.take(16);assert r.u32()==1
            r.u64();r.u64();assert r.u32()==2 and r.u32()==1
            body=XDR(r.opaque());body.take(16);flags=body.u32();body.u32();body.u64()
            assert not flags&1 and body.u32()==1, 'native fixture must grant one sparse handle'
            dsfh=body.opaque();body.done();r.done()
            assert dsfh not in mappings or mappings[dsfh]==(fh,flags)
            mappings[dsfh]=(fh,flags);grants+=1
        elif code==49:
            offset,length=c.u64(),c.u64();assert c.u32()==0;c.take(16)
            assert c.u32()==1 and c.u64()==offset+length-1
            assert c.u32()==0 and c.u32()==1 and c.opaque()==b'';c.done()
            if r.u32():assert r.u64()==(1<<20)+17
            r.done();layouts.append((fh,offset,length))
        elif code==51:
            returns+=1
        elif code==5:
            mds_commits.append((fh,c.u64(),c.u32(),r.take(8)));c.done();r.done()
    writes=[];ds_commits=[]
    for minor,dsfh,code,c,r in operations(root/'ds-wire.pcap',ds_only=True,server='192.168.116.131'):
        if code==38:
            assert c.u32()==0;c.take(12);offset=c.u64();assert c.u32()==0
            data=c.opaque();c.done()
            n,stable,verifier=r.u32(),r.u32(),r.take(8);r.done()
            assert n==len(data)>0,'native short/unknown write'
            fh,flags=mappings[dsfh]
            writes.append((fh,offset,data,stable,verifier))
        elif code==5:
            fh,flags=mappings[dsfh];assert not flags&2
            ds_commits.append((fh,c.u64(),c.u32(),r.take(8)));c.done();r.done()
        else:
            raise AssertionError('metadata operation sent to DS')
    assert grants==returns==24
    commits=mds_commits+ds_commits
    size=validate_writes(writes,layouts,commits)
    for fh,offset,data,stable,verifier in writes:
        flags=next(flags for mapped,flags in mappings.values() if mapped==fh)
        needed=stable<2 and (stable==0 or flags&2)
        match=(fh,offset,len(data),verifier)
        assert (match in commits)==needed, 'missing or unnecessary data COMMIT'
        if needed:assert match in (mds_commits if flags&2 else ds_commits)
    native={}
    for line in (root/'native-mds.txt').read_text().splitlines():
        if '\t' not in line:continue
        path,ip,obj=line.split('\t');assert ip=='192.168.116.131'
        native[pathlib.PurePosixPath(path.rstrip(':')).name]=obj
    objects={}
    for line in (root/'native-ds.txt').read_text().splitlines():
        path,length,digest=line.split('\t');objects[path.split('/storage/')[1]]=(int(length),digest)
    profiles=[json.loads(p.read_text()) for p in (root/'native').glob('*.json')]
    assert len(profiles)==len(native)==len(objects)==8
    assert {(p['platform'],p['version'],p['mode']) for p in profiles}=={(os,v,m) for os in ('windows','linux') for v in ('4.1','4.2') for m in ('api','cli')}
    digest=hashlib.sha256(expected_file()).hexdigest()
    assert len({native[p['remote']] for p in profiles})==8
    for p in profiles:
        assert p['writes']==3 and p['size']==(1<<20)+17 and p['sha256']==digest
        assert objects[native[p['remote']]]==(p['size'],digest)
    return dict(passed=True,profiles=8,native_files=8,writes=len(writes),written_bytes=size,
                layoutcommits=len(layouts),layoutgets=grants,layoutreturns=returns,
                ds_commits=len(ds_commits),mds_commits=len(mds_commits),native_sha256=digest)


if __name__=='__main__':
    print(json.dumps(audit(pathlib.Path(sys.argv[1])),indent=2))
