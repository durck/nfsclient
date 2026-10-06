"""Host-side Ubuntu package fetch for an offline, signature-checked fixture build.

Run indexes, then apt update and --print-uris inside the disposable base image,
then packages. The base image's Ubuntu keyring authenticates release metadata.
"""
import concurrent.futures
import hashlib
import lzma
from pathlib import Path, PurePosixPath
import re
import sys
import urllib.parse
import urllib.request

mode, directory = sys.argv[1:]
root = Path(directory)
root.mkdir(parents=True, exist_ok=True)
suites = ("noble", "noble-updates", "noble-security")

def download(name):
    with urllib.request.urlopen("https://archive.ubuntu.com/ubuntu/" + urllib.parse.quote(name, safe="/+"), timeout=120) as reply:
        return reply.read()

if mode == "indexes":
    def index(suite):
        prefix = f"dists/{suite}/"
        release = download(prefix + "InRelease")
        target = root / prefix
        target.mkdir(parents=True, exist_ok=True)
        (target / "InRelease").write_bytes(release)
        for component in ("main", "universe"):
            name = component + "/binary-amd64/Packages.xz"
            data = download(prefix + name)
            spec = re.search(r"^ ([a-f0-9]{64})\s+(\d+) " + re.escape(name) + r"$", release.decode(), re.M)
            assert spec and len(data) == int(spec[2]) and hashlib.sha256(data).hexdigest() == spec[1]
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(index, suites))
    print("Downloaded matching indexes; authenticate InRelease with apt before package planning.")
elif mode == "packages":
    index = {}
    for path in root.glob("dists/*/*/binary-amd64/Packages.xz"):
        for block in lzma.decompress(path.read_bytes()).decode().split("\n\n"):
            fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(" "))
            if "Filename" in fields:
                index[fields["Filename"]] = fields
    plans = "\n".join(path.read_text() for path in root.glob("*package-plan.txt"))
    paths = set(urllib.parse.unquote(name) for name in re.findall(r"'file:/repo/([^']+)'", plans))
    assert paths
    def package(name):
        assert name.startswith("pool/") and ".." not in PurePosixPath(name).parts
        spec = index[name]
        path = root / name
        data = path.read_bytes() if path.is_file() else download(name)
        assert len(data) == int(spec["Size"]) and hashlib.sha256(data).hexdigest() == spec["SHA256"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return len(data)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        sizes = list(pool.map(package, sorted(paths)))
    print(f"Downloaded {len(sizes)} hash-verified packages, {sum(sizes)} bytes.")
else:
    raise SystemExit("Use indexes or packages")
