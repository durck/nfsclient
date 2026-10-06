#!/usr/bin/python3
"""Integration checks against disposable copies of the authenticated artifacts."""
import json
import pathlib
import shutil
import subprocess
import tempfile
import argparse

BUNDLE = pathlib.Path("/bundle")
SCRIPT = "/scripts/verify-linux-bundle.py"
parser = argparse.ArgumentParser()
parser.add_argument("--profile", choices=("nfs-ad", "posix-acl", "kernel-gss", "kernel-gssproxy"), default="nfs-ad")
PROFILE = parser.parse_args().profile


def rejected(root, expected):
    result = subprocess.run(["python3", SCRIPT, "check", str(root), "--profile", PROFILE], text=True, capture_output=True)
    if result.returncode == 0 or expected not in result.stdout + result.stderr:
        raise AssertionError("Tampering was not rejected for the expected reason: " + result.stderr)
    print("Rejected: " + expected)


with tempfile.TemporaryDirectory(prefix="nfs-lab-package-negative-") as directory:
    root = pathlib.Path(directory) / "bundle"
    shutil.copytree(BUNDLE, root)
    proof = json.loads((root / "provenance.json").read_text())
    release = root / proof["indexes"][0]["release"]
    original = release.read_bytes()
    release.write_bytes(original.replace(b"Origin: Ubuntu", b"Origin: Ubuntx", 1))
    rejected(root, "BAD signature")
    release.write_bytes(original)
    deb = min((root / "debs").glob("*.deb"), key=lambda path: path.stat().st_size)
    original = deb.read_bytes()
    deb.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    rejected(root, "Unauthenticated deb")
    deb.write_bytes(original)
    local_index = root / "Packages"
    original = local_index.read_text()
    local_index.write_text(original.replace("Filename: debs/", "Filename: ../outside/", 1))
    rejected(root, "Local repository differs")
print("Signature, payload and repository-path tampering checks passed")
