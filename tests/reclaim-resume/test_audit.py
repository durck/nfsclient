import unittest

from audit import check_reclaim


class ReclaimOracleTests(unittest.TestCase):
    def test_confirmed_original_lock(self):
        check_reclaim((1, 0, 2**64-1, 123), (1, 0, 2**64-1, 456))

    def test_rejects_missing_changed_or_unrestarted_lock(self):
        original = (1, 0, 2**64-1, 123)
        for previous, current in (
            (None, (1, 0, 2**64-1, 456)),
            (original, original),
            (original, (2, 0, 2**64-1, 456)),
            (original, (1, 10, 2**64-1, 456)),
            ((1, 0, 10, 123), (1, 0, 10, 456)),
        ):
            with self.subTest(previous=previous, current=current):
                with self.assertRaises(AssertionError):
                    check_reclaim(previous, current)


if __name__ == '__main__':
    unittest.main()
