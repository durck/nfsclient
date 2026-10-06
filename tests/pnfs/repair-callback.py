"""Disposable Ganesha 4.3 fixture: copy the full referring session ID.

The original sizeof(NFS4_SESSIONID_SIZE) copies the size of an integer (4),
not the 16-byte session ID. Preserve the original; never patch a host service.
"""
from pathlib import Path
import hashlib
import json
import sys

source = Path(sys.argv[1])
backup = source.with_name(source.name + ".recall-original")
original = source.read_text()
old = "memcpy(list->rcl_sessionid, refer->session,\n\t\t       sizeof(NFS4_SESSIONID_SIZE));"
new = "memcpy(list->rcl_sessionid, refer->session,\n\t\t       sizeof(list->rcl_sessionid));"
assert original.count(old) == 1, "unexpected source or already repaired"
assert not backup.exists(), "original already retained"
backup.write_bytes(source.read_bytes())
source.write_text(original.replace(old, new))
print(json.dumps({"original_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(),
                  "repaired_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}, indent=2))
