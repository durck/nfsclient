"""Independently verify new-file pNFS uploads, growth, partial and empty files."""
import collections
import hashlib
import json
import pathlib
import sys

from audit_writes import XDR, operations


def payload():
    return bytes((i*31+i//251)%256 for i in range((1<<20)+17))


def validate_writes(writes,layouts,mds_commits,ds_commits):
    source=payload();complete=source+bytes(257)+bytes([0xd3])*32785
    expected=collections.Counter((f,o,len(d)) for f,o,d,_,_,_ in writes)
    assert collections.Counter(layouts)==expected,'unmatched layout durability'
    commits=collections.Counter(mds_commits+ds_commits)
    required=collections.Counter()
    by_file=collections.defaultdict(dict)
    for fh,offset,data,stable,verifier,flags in writes:
        if stable<2 and (stable==0 or flags&2):
            item=(fh,offset,len(data),verifier);required[item]+=1
            assert item in (mds_commits if flags&2 else ds_commits)
        for i,value in enumerate(data):
            assert offset+i not in by_file[fh],'write replay/overlap'
            by_file[fh][offset+i]=value
    assert commits==required
    full=partial=0
    for offsets in by_file.values():
        size=max(offsets)+1
        if size==len(complete):
            expected_offsets=set(range(len(source)))|set(range(len(source)+257,len(complete)))
            assert set(offsets)==expected_offsets
            actual=bytearray(size)
            for offset,value in offsets.items():actual[offset]=value
            assert bytes(actual)==complete;full+=1
        else:
            assert size==32768 and set(offsets)==set(range(size))
            assert bytes(offsets[i] for i in range(size))==source[:size];partial+=1
    assert (full,partial)==(8,8)
    return full,partial


def audit(root):
    source=payload();complete=source+bytes(257)+bytes([0xd3])*32785
    mapping={};layouts=[];mds_commits=[];grants=returns=0
    for _,fh,op,c,r in operations(root/'mds-wire.pcap'):
        assert op!=38,'upload fell back to MDS WRITE'
        if op==50:
            assert c.u32()==0 and c.u32()==1 and c.u32()==2
            c.u64();c.u64();c.u64();c.take(16);c.u32();c.done()
            r.u32();r.take(16);assert r.u32()==1;r.u64();r.u64()
            assert r.u32()==2 and r.u32()==1
            body=XDR(r.opaque());body.take(16);flags=body.u32();body.u32();body.u64()
            assert not flags&1 and body.u32()==1
            dsfh=body.opaque();body.done();r.done()
            assert dsfh not in mapping or mapping[dsfh]==(fh,flags)
            mapping[dsfh]=(fh,flags);grants+=1
        elif op==49:
            offset,length=c.u64(),c.u64();assert c.u32()==0;c.take(16)
            assert c.u32()==1 and c.u64()==offset+length-1
            assert c.u32()==0 and c.u32()==1 and c.opaque()==b'';c.done()
            if r.u32():assert r.u64()==offset+length
            r.done();layouts.append((fh,offset,length))
        elif op==51:returns+=1
        elif op==5:mds_commits.append((fh,c.u64(),c.u32(),r.take(8)));c.done();r.done()
    writes=[];ds_commits=[]
    for _,dsfh,op,c,r in operations(root/'ds-wire.pcap',ds_only=True,server='192.168.116.131'):
        fh,flags=mapping[dsfh]
        if op==38:
            assert c.u32()==0;c.take(12);offset=c.u64();assert c.u32()==0
            data=c.opaque();c.done();n,stable,verifier=r.u32(),r.u32(),r.take(8);r.done()
            assert n==len(data)>0 and stable in (0,1,2)
            writes.append((fh,offset,data,stable,verifier,flags))
        elif op==5:
            assert not flags&2
            ds_commits.append((fh,c.u64(),c.u32(),r.take(8)));c.done();r.done()
        else:raise AssertionError('metadata operation sent to DS')
    assert grants==returns==24 and len(mapping)==16
    full,partial=validate_writes(writes,layouts,mds_commits,ds_commits)
    native={}
    for line in (root/'native-mds.txt').read_text().splitlines():
        if '\t' not in line:continue
        name,ip,obj=line.split('\t');assert ip=='192.168.116.131'
        name=pathlib.PurePosixPath(name.rstrip(':')).name
        assert name not in native;native[name]=obj
    objects={}
    for line in (root/'native-ds.txt').read_text().splitlines():
        path,size,digest=line.split('\t');objects[path.split('/storage/')[1]]=(int(size),digest)
    profiles=[json.loads(p.read_text()) for p in (root/'native').glob('*.json')]
    assert len(profiles)==8 and len(native)==len(objects)==24
    assert {(p['platform'],p['version'],p['mode']) for p in profiles}=={(os,v,m) for os in ('windows','linux') for v in ('4.1','4.2') for m in ('api','cli')}
    names=set();paths=set()
    for p in profiles:
        assert p['partial']==32768 and len(p['files'])==3
        for f in p['files']:
            name=f['remote'];assert name not in names;names.add(name)
            data=b'' if name.endswith('-empty') else source[:32768] if name.endswith('-partial') else complete
            expected=(len(data),hashlib.sha256(data).hexdigest())
            assert (f['size'],f['sha256'])==expected
            obj=native[name];assert obj not in paths;paths.add(obj)
            assert objects[obj]==expected
    return dict(passed=True,profiles=8,native_files=24,complete=full,partial=partial,empty=8,
                writes=len(writes),written_bytes=sum(len(w[2]) for w in writes),layoutcommits=len(layouts),
                layouts=grants,ds_commits=len(ds_commits),mds_commits=len(mds_commits),
                complete_sha256=hashlib.sha256(complete).hexdigest(),partial_sha256=hashlib.sha256(source[:32768]).hexdigest())


if __name__=='__main__':print(json.dumps(audit(pathlib.Path(sys.argv[1])),indent=2))
