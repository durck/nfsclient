"""Verify transparent native multi-DS write observations and native C oracles."""
import hashlib
import json
import pathlib
import sys

SIZE=(128<<20)+17
DIGEST='2dfba67fdaff5c1e412ff9482149bb56b3849737e8983f6edc32974e725a64f1'
RANGES=[((64<<20)-64,64),(64<<20,64),((128<<20)-64,64),(128<<20,17)]


def validate_profile(p):
    assert p['size']==SIZE and p['sha256']==DIGEST
    s=p['snapshot'];assert not s['Errors'] and s['BarrierMatched'] and not s['BarrierTimedOut']
    writes=sorted(s['Reads'],key=lambda r:r['Offset'])
    assert len(writes)==4 and {r['ServerID'] for r in writes}=={0,1}
    for r,(offset,n) in zip(writes,RANGES):
        data=bytes((i*31+i//251)%256 for i in range(offset,offset+n))
        assert (r['Opcode'],r['Offset'],r['Count'],r['ReturnedBytes'],r['WireStatus'])==(38,offset,n,n,0)
        assert r['PayloadSHA256']==hashlib.sha256(data).hexdigest()
        assert 0<r['RequestedNS']<=r['ForwardedNS']<=r['RepliedNS']
    boundary=p['boundary'];assert boundary in (64<<20,128<<20)
    pair=[r for r in writes if r['Offset'] in (boundary-64,boundary)]
    assert len(pair)==2 and pair[0]['ServerID']!=pair[1]['ServerID']
    assert max(r['RequestedNS'] for r in pair)<=min(r['ForwardedNS'] for r in pair)
    assert max(r['ForwardedNS'] for r in pair)<=min(r['RepliedNS'] for r in pair)
    return sum(r['Count'] for r in writes)


def audit(root):
    profiles=[json.loads(p.read_text()) for p in (root/'native').glob('*.json')]
    assert len(profiles)==8
    assert {(p['platform'],p['version'],p['mode']) for p in profiles}=={(os,v,m) for os in ('windows','linux') for v in ('4.1','4.2') for m in ('api','cli')}
    names={p['remote'] for p in profiles};assert len(names)==8
    written=sum(validate_profile(p) for p in profiles)
    oracle=json.loads((root/'native-oracle.json').read_text())
    assert oracle['ok'] and oracle['operation']=='oracle' and len(oracle['files'])==8
    assert {f['name'] for f in oracle['files']}==names
    for f in oracle['files']:
        assert f['size']==SIZE and f['sha256']==DIGEST and f['pattern_verified']
        assert f['distinct_chunkserver_ips']==2 and len(f['chunks'])==3
    return dict(passed=True,profiles=8,native_files=8,overlap_barriers=8,writes=32,written_bytes=written,complete_bytes=8*SIZE,complete_sha256=DIGEST)


if __name__=='__main__':print(json.dumps(audit(pathlib.Path(sys.argv[1])),indent=2))
