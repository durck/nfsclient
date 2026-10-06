"""Fetch Debian index bytes; apt must authenticate InRelease before planning.

Package downloads use the existing nfsv2/replacement/download-packages.py after
apt --print-uris produces a storage-package-plan.txt in this runtime directory.
"""
import hashlib
import pathlib
import re
import sys
import urllib.request

root = pathlib.Path(sys.argv[1])
root.mkdir(parents=True, exist_ok=True)
for name in ("InRelease", "main/binary-amd64/Packages.xz"):
    target = root / "dists/bookworm" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen("https://deb.debian.org/debian/dists/bookworm/" + name, timeout=120) as reply:
        data = reply.read()
    target.write_bytes(data)
release = (root / "dists/bookworm/InRelease").read_text()
expected = re.search(r"^ ([a-f0-9]{64})\s+(\d+) main/binary-amd64/Packages.xz$", release, re.M)
assert expected, "signed index digest missing"
index = (root / "dists/bookworm/main/binary-amd64/Packages.xz").read_bytes()
assert len(index) == int(expected[2]) and hashlib.sha256(index).hexdigest() == expected[1]
print("Downloaded release and matching package index; authenticate with apt next.")
