"""Artifact cleanup preserves history and only moves previewed candidates."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import archive_artifacts


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "project"
        self.bin = self.root / "bin"
        self.bin.mkdir(parents=True)
        self.pointer = self.bin / "ARCHIVE_LOCATION.json"
        self.pointer.write_bytes(b'{"archive": "previous-evidence"}\n')
        self.original_pointer = self.pointer.read_bytes()
        self.archive_parent = self.base / "project-artifacts"

    def invoke(self, *arguments):
        output = io.StringIO()
        with patch.object(archive_artifacts, "ROOT", self.root), \
                patch("sys.argv", ["archive_artifacts.py", *arguments]), \
                contextlib.redirect_stdout(output):
            archive_artifacts.main()
        return json.loads(output.getvalue())

    def test_empty_apply_preserves_existing_archive_pointer(self):
        result = self.invoke("--apply")
        self.assertEqual(result["files"], 0)
        self.assertFalse(result["applied"])
        self.assertEqual(self.pointer.read_bytes(), self.original_pointer)
        self.assertFalse(self.archive_parent.exists())

    def test_preview_lists_candidates_without_changing_files(self):
        candidate = self.bin / "old-output.txt"
        candidate.write_bytes(b"historical output")
        result = self.invoke()
        self.assertEqual([entry["name"] for entry in result["entries"]], [candidate.name])
        self.assertEqual(candidate.read_bytes(), b"historical output")
        self.assertEqual(self.pointer.read_bytes(), self.original_pointer)
        self.assertFalse(self.archive_parent.exists())

    def test_repeated_apply_in_same_second_is_noop(self):
        self.bin.joinpath("old-output.txt").write_bytes(b"historical output")
        with patch.object(archive_artifacts, "datetime") as clock:
            clock.now.return_value.strftime.return_value = "2026-10-05-120000"
            self.invoke("--apply")
            pointer = self.pointer.read_bytes()
            result = self.invoke("--apply")
        self.assertFalse(result["applied"])
        self.assertEqual(self.pointer.read_bytes(), pointer)
        self.assertEqual(len(list(self.archive_parent.iterdir())), 1)

    def test_apply_moves_candidates_and_retains_current_outputs(self):
        candidate = self.bin / "old-output.txt"
        candidate.write_bytes(b"historical output")
        retained = self.bin / "verification"
        retained.mkdir()
        retained.joinpath("result.json").write_bytes(b"{}")
        helper = self.bin / "nfs-viewer-as-helper"
        helper.write_bytes(b"current trusted helper")
        binaries = [self.bin / name for name in
                    ("nfsclient-windows-amd64.exe", "nfsclient-linux-amd64")]
        for binary in binaries:
            binary.write_bytes(b"current client")
        self.invoke("--apply")
        pointer = json.loads(self.pointer.read_text(encoding="utf-8"))
        destination = Path(pointer["archive"])
        self.assertTrue(destination.is_relative_to(self.archive_parent))
        self.assertEqual(destination.joinpath("runtime-bin", candidate.name).read_bytes(), b"historical output")
        self.assertFalse(candidate.exists())
        self.assertEqual(retained.joinpath("result.json").read_bytes(), b"{}")
        self.assertEqual(helper.read_bytes(), b"current trusted helper")
        for binary in binaries:
            self.assertEqual(binary.read_bytes(), b"current client")
        manifest = json.loads(Path(pointer["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["moved"], [candidate.name])


if __name__ == "__main__":
    unittest.main()
