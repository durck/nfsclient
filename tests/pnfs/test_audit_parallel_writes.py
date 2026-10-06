import copy
import hashlib
import unittest
from audit_parallel_writes import validate_profile,RANGES,SIZE,DIGEST

class ParallelWriteEvidenceTest(unittest.TestCase):
    def test_payload_and_overlap_refusals(self):
        writes=[]
        for i,(off,n) in enumerate(RANGES):
            writes.append(dict(Opcode=38,Offset=off,Count=n,ReturnedBytes=n,WireStatus=0,ServerID=i%2,
                PayloadSHA256=hashlib.sha256(bytes((v*31+v//251)%256 for v in range(off,off+n))).hexdigest(),
                RequestedNS=10+i,ForwardedNS=20,RepliedNS=30))
        p=dict(size=SIZE,sha256=DIGEST,boundary=64<<20,snapshot=dict(Errors=[],BarrierMatched=True,BarrierTimedOut=False,Reads=writes))
        self.assertEqual(validate_profile(p),209)
        coarse=copy.deepcopy(p)
        for r in coarse['snapshot']['Reads']:r['RepliedNS']=r['ForwardedNS']
        self.assertEqual(validate_profile(coarse),209)
        for mode in ('payload','ack','opcode','replay','same-server','serial','early-forward','timeout','file-hash'):
            with self.subTest(mode=mode):
                q=copy.deepcopy(p);r=q['snapshot']['Reads']
                if mode=='payload':r[0]['PayloadSHA256']='bad'
                if mode=='ack':r[0]['ReturnedBytes']=1
                if mode=='opcode':r[0]['Opcode']=25
                if mode=='replay':r.append(r[0])
                if mode=='same-server':r[1]['ServerID']=r[0]['ServerID']
                if mode=='serial':r[1]['RequestedNS']=31;r[1]['ForwardedNS']=32;r[1]['RepliedNS']=40
                if mode=='early-forward':r[0]['ForwardedNS']=10
                if mode=='timeout':q['snapshot']['BarrierTimedOut']=True
                if mode=='file-hash':q['sha256']='bad'
                with self.assertRaises(AssertionError):validate_profile(q)

if __name__=='__main__':unittest.main()
