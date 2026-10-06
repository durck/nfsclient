"""Correlate portable FAST/PKINIT test logs with independent kernel evidence."""
import hashlib
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
expected = hashlib.sha256(bytes((0, 255, 128, 80, 75, 70)) * 1500).hexdigest()
digests = {}
for line in (root / "native-sha256.txt").read_text().splitlines():
    digest, path = line.split(maxsplit=1)
    digests[path] = digest
policies = {}
for block in (root / "native-acl.txt").read_text().split("\n\n"):
    lines = block.splitlines()
    if lines and lines[0].startswith("# file: "):
        policies[lines[0].removeprefix("# file: ")] = lines[1:]
count = 0
for platform in ("windows", "linux"):
    log = (root / f"nfs-{platform}.log").read_text(encoding="utf-8-sig")
    assert "\nPASS\n" in log and "FAIL" not in log
    matches = re.findall(r"native file=(\S+) uid=(\d+) bytes=(\d+)", log)
    assert len(matches) == 42 and len({name for name, _, _ in matches}) == 42
    for name, uid, length in matches:
        assert name.startswith(f"purego-{platform}-") and length == "9000"
        path = "/data/" + name
        assert digests.get(path) == expected, path
        assert uid == ("20001" if f"-{platform}-fast-" in name else "0")
        assert policies[path] == [f"# owner: {uid}", f"# group: {uid}", "user::rw-", "group::---", "other::---"], path
        count += 1
    wire = (root / f"as-{platform}.log").read_text(encoding="utf-8-sig")
    assert "\nPASS\n" in wire and "FAIL" not in wire
    assert len(re.findall(r"--- PASS: TestPureGoASNativeWire/", wire)) == 40
print(json.dumps({"passed": True, "native_files": count, "bytes_each": 9000,
                  "sha256": expected, "native_as_cases": 80,
                  "platforms": ["windows", "linux"], "cgo": False}, indent=2))
