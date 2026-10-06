"""Audit kernel-local NFSv2 GSS results independently of RPC return values."""
import hashlib
import json
import re
from pathlib import Path
import sys

root = Path(sys.argv[1])
payload = bytes((i * 31 + i // 257) % 256 for i in range(9001))
want = hashlib.sha256(payload).hexdigest()
digests = {}
for line in (root / "native-sha256.txt").read_text().splitlines():
    digest, name = line.split(maxsplit=1)
    digests[name] = digest
policies = {}
for block in (root / "native-acl.txt").read_text().split("\n\n"):
    lines = block.splitlines()
    if lines and lines[0].startswith("# file: "):
        policies[lines[0].removeprefix("# file: ")] = lines[1:]
checked = []
for platform in ("windows", "linux"):
    for transport in ("tcp", "udp"):
        for security in ("krb5", "krb5i", "krb5p"):
            for credential in ("keytab", "ccache"):
                path = f"/data/{platform}-{transport}-{security}-{credential}/payload"
                assert digests.get(path) == want, path
                assert policies[path] == ["# owner: 20001", "# group: 20001", "user::rw-", "group::---", "other::---"], path
                checked.append(path)
assert "+2" in (root / "nfsd-versions.txt").read_text()
v4_checked = 0
if (root / "native-v4-sha256.txt").exists():
    expected_v4 = hashlib.sha256(b"native ACL management payload\n").hexdigest()
    v4_policies = {}
    for block in (root / "native-v4-acl.txt").read_text().split("\n\n"):
        lines = block.splitlines()
        if lines and lines[0].startswith("# file: "):
            v4_policies[lines[0].removeprefix("# file: ")] = lines[1:]
    paths = set()
    for platform in ("windows", "linux"):
        log = (root / f"native-acl-{platform}.log").read_text(encoding="utf-8-sig")
        matches = re.findall(r"NATIVE_ACL_MANAGEMENT path=(\S+) version=(4\.[012])", log)
        assert {version for _, version in matches} == {"4.0", "4.1", "4.2"}
        paths.update("/v4/data/" + path for path, _ in matches)
    for line in (root / "native-v4-sha256.txt").read_text().splitlines():
        digest, path = line.split(maxsplit=1)
        assert path in paths and digest == expected_v4, path
        assert v4_policies[path] == ["# owner: 20001", "# group: 20001", "user::rw-", "user:20002:---", "group::---", "mask::---", "other::---"], path
        paths.remove(path)
        v4_checked += 1
    assert not paths and v4_checked == 6
print(json.dumps({"passed": True, "native_payloads": len(checked), "bytes_each": len(payload), "sha256": want, "uid": 20001, "gid": 20001, "mode": "0600", "native_v4_acl_files": v4_checked}, indent=2))
