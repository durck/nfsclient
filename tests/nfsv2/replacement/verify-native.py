"""Verify guest-native evidence independently of NFS replies."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
payload = bytes((i * 31 + i // 257) % 251 for i in range(262144)) + b"v2-replacement-end"
actual = {}
for line in (root / "native-sha256.txt").read_text().splitlines():
    digest, name = line.split(maxsplit=1)
    actual[Path(name).name] = digest
expected = {}
for platform in ("windows", "linux"):
    for transport in ("tcp", "udp"):
        for kind in ("api", "cli", "empty", "local-change", "hardlink", "hardlink-alias", "special"):
            data = payload if kind in ("api", "cli") else b"" if kind == "empty" else b"old-data\n"
            expected[f"{platform}-{transport}-{kind}"] = hashlib.sha256(data).hexdigest()
assert actual == expected, "native destination bytes differ"
assert (root / "acl-before.txt").read_bytes() == (root / "acl-after.txt").read_bytes(), "numeric ACL/mode/owner changed"
stages = []
for line in (root / "native-files.txt").read_text().splitlines():
    if not line.startswith(".nfs-replace-"):
        continue
    name, kind, size, uid, gid, mode = line.split()
    assert uid == gid == "20001", line
    assert (kind, mode) in (("d", "700"), ("f", "600")), line
    if kind == "d":
        stages.append(name)
expected_stages = int(sys.argv[2]) if len(sys.argv) > 2 else 4
assert len(stages) == expected_stages, stages
for platform in ("windows", "linux"):
    log = (root / f"{platform}-native.log").read_text(encoding="utf-8-sig")
    assert log.count("REPLACE2 platform=") == 4, platform
    assert log.count("REPLACE2_CLI platform=") == 2, platform
    assert "FAIL" not in log and "SKIP" not in log, platform
report = {"passed": True, "published_files": 12, "preserved_refusal_or_alias_files": 16,
          "unchanged_numeric_acl_files": 28, "retained_private_failure_stages": expected_stages,
          "api_profiles": 4, "standalone_cli_profiles": 4,
          "payload_bytes": len(payload), "payload_sha256": hashlib.sha256(payload).hexdigest()}
(root / "native-verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
