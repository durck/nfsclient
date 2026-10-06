import unittest
from audit_flex_write import validate_durability, validate_mirrors


class FlexWriteAuditTests(unittest.TestCase):
    def test_independent_mirror_verifiers(self):
        writes = {'a':[(b'f',17,b'abc',0,b'a'*8)], 'b':[(b'f',17,b'abc',1,b'b'*8)]}
        commits = {'a':[(b'f',17,3,b'a'*8)], 'b':[(b'f',17,3,b'b'*8)]}
        self.assertEqual(validate_mirrors(writes,[(b'f',17,3)],commits),{b'f':{17:97,18:98,19:99}})

    def test_missing_or_divergent_mirror(self):
        good = [(b'f',17,b'abc',2,b'v'*8)]
        for other in ([],good*2,[(b'f',17,b'abd',2,b'w'*8)]):
            with self.assertRaises(AssertionError):
                validate_mirrors({'a':good,'b':other},[(b'f',17,3)],{'a':[],'b':[]})

    def test_stability_levels(self):
        for stable in (0,1,2):
            writes = [(b'f',17,b'abc',stable,b'v'*8)]
            commits = [(b'f',17,3,b'v'*8)] if stable<2 else []
            self.assertEqual(validate_durability(writes,[(b'f',17,3)],commits),{b'f':{17:97,18:98,19:99}})

    def test_missing_or_changed_commit(self):
        for commits in ([],[(b'f',17,3,b'x'*8)],[(b'f',18,3,b'v'*8)],[(b'f',17,3,b'v'*8)]*2):
            with self.assertRaises(AssertionError):
                validate_durability([(b'f',17,b'abc',1,b'v'*8)],[(b'f',17,3)],commits)

    def test_layout_and_overlap(self):
        writes = [(b'f',17,b'abc',2,b'v'*8)]
        for layouts in ([],[(b'f',18,3)],[(b'f',17,3)]*2):
            with self.assertRaises(AssertionError):
                validate_durability(writes,layouts,[])
        with self.assertRaisesRegex(AssertionError,'overlapping'):
            validate_durability(writes*2,[(b'f',17,3)]*2,[])


if __name__ == '__main__':
    unittest.main()
