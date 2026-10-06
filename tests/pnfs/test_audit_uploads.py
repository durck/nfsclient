import unittest
from audit_uploads import payload,validate_writes

class UploadEvidenceTest(unittest.TestCase):
    def test_payload_gap_and_durability(self):
        source=payload()
        writes=[]
        for i in range(8):
            writes.extend([(bytes([i]),0,source,0,b'verifier',0),
                           (bytes([i]),len(source)+257,bytes([0xd3])*32785,0,b'verifier',0),
                           (bytes([i+8]),0,source[:32768],0,b'verifier',0)])
        layouts=[(f,o,len(d)) for f,o,d,_,_,_ in writes]
        commits=[(f,o,len(d),v) for f,o,d,_,v,_ in writes]
        self.assertEqual(validate_writes(writes,layouts,[],commits),(8,8))
        for mode in ('payload','gap','overlap','missing-file','layout','verifier','commit-route'):
            with self.subTest(mode=mode):
                w,l,c=list(writes),list(layouts),list(commits)
                f,o,d,s,v,flags=w[0]
                if mode=='payload':w[0]=(f,o,b'X'+d[1:],s,v,flags)
                if mode=='gap':
                    f,o,d,s,v,flags=w[1];w[1]=(f,o-1,d,s,v,flags)
                    l[1]=(f,o-1,len(d));c[1]=(f,o-1,len(d),v)
                if mode=='overlap':w.append(w[0]);l.append(l[0]);c.append(c[0])
                if mode=='missing-file':w=w[3:];l=l[3:];c=c[3:]
                if mode=='layout':l.pop()
                if mode=='verifier':c[0]=(f,o,len(d),b'changed!')
                if mode=='commit-route':w[0]=(f,o,d,s,v,2)
                with self.assertRaises(AssertionError):validate_writes(w,l,[],c)

if __name__=='__main__':unittest.main()
