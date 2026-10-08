"""Privacy regressions for public terminal recordings."""

import unittest

from record_demo import check_public_transcript


class PrivacyTests(unittest.TestCase):
    def test_rejects_profile_name_and_escaped_path(self):
        for text, values in (("Local cwd: C:\\Users\\ExampleUser\\project", ["ExampleUser"]),
                             (r'Local cwd: C:\\Users\\ExampleUser\\project',
                              [r"C:\Users\ExampleUser"]),
                             ("HOST: PRIVATE-PC", ["private-pc"])):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                check_public_transcript(text, values)

    def test_rejects_absolute_windows_paths_even_without_private_names(self):
        for text in (r"C:\nfsclient-demo\files", "D:/work/files", r"\\server\share\file"):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                check_public_transcript(text, [])

    def test_accepts_relative_paths_remote_paths_and_public_author(self):
        check_public_transcript("release-notes.txt /docs / copyright durck",
                                ["ExampleUser", "PRIVATE-PC", None])


if __name__ == "__main__":
    unittest.main()
