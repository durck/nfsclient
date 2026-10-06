import unittest
from audit_writes import XDR, validate_writes


class WriteEvidenceTest(unittest.TestCase):
    def test_complete_matrix_and_mutations(self):
        writes=[(bytes([file]),17+attempt*65571,bytes([0xa1+attempt])*65553,0,b'verifier')
                for file in range(8) for attempt in range(3)]
        layouts=[(f,o,len(d)) for f,o,d,_,_ in writes]
        commits=[(f,o,len(d),v) for f,o,d,_,v in writes]
        self.assertEqual(validate_writes(writes,layouts,commits),1573272)
        for mode in ('range','payload','duplicate','missing-file','missing-layout','duplicate-layout','bad-commit','empty'):
            with self.subTest(mode=mode):
                w,l,c=list(writes),list(layouts),list(commits)
                f,o,d,s,v=w[0]
                if mode=='range':w[0]=(f,o+1,d,s,v)
                if mode=='payload':w[0]=(f,o,b'X'+d[1:],s,v)
                if mode=='duplicate':w.append(w[0])
                if mode=='missing-file':w=w[3:]
                if mode=='missing-layout':l.pop()
                if mode=='duplicate-layout':l.append(l[0])
                if mode=='bad-commit':c[0]=(f,o,len(d),b'changed!')
                if mode=='empty':w[0]=(f,o,b'',s,v)
                with self.assertRaises(AssertionError):validate_writes(w,l,c)

    def test_xdr_rejects_truncated_or_oversized_fields(self):
        for data in (b'\0',b'\0\0\0\4abc',b'\0\x10\0\1'):
            with self.subTest(data=data),self.assertRaises(AssertionError):XDR(data).opaque()
        d=XDR(b'\0\0\0\3abc\0')
        self.assertEqual(d.opaque(),b'abc');d.done()


if __name__=='__main__':unittest.main()
