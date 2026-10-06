"""Check native FreeBSD bytes independently of the NFS client responses."""
import hashlib
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
original = bytes((i * 31 + i // 257) % 251 for i in range(131072))
patched = original[:16384] + bytes([0xa5]) * 65536 + original[81920:]
expected = {}
for platform in ("windows", "linux"):
    matrix = (root / f"{platform}-matrix.log").read_text(encoding="utf-8-sig")
    assert "FAIL" not in matrix and "SKIP" not in matrix
    names = re.findall(r"LEGACY_RANGE(?:_CLI)? platform=\w+ version=[23] transport=(?:tcp|udp) file=(\S+) bytes=131072", matrix)
    assert len(names) == len(set(names)) == 8, platform
    expected.update((name, hashlib.sha256(patched).hexdigest()) for name in names)
    loss = (root / f"{platform}-loss.log").read_text(encoding="utf-8-sig")
    assert "FAIL" not in loss and "fresh_range_verified" in loss
    expected[f"range-loss-{platform}"] = hashlib.sha256(original).hexdigest()
actual = {}
for line in (root / "native-files.txt").read_text(encoding="utf-8-sig").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64}) (.+)", line)
    if match:
        actual[Path(match[2]).name] = match[1]
assert actual == expected, "native file hashes differ"
report = {"passed": True, "api_profiles": 8, "standalone_cli_profiles": 8,
          "statd_restart_profiles": 2, "native_verified_files": len(actual),
          "file_bytes": len(original), "patch_offset": 16384, "patch_length": 65536,
          "original_sha256": hashlib.sha256(original).hexdigest(),
          "patched_sha256": hashlib.sha256(patched).hexdigest()}
(root / "native-verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
