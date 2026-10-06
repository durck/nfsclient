"""Independent native oracle for retained files named by successful test logs."""
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import sys
import uuid

names = json.loads(Path(sys.argv[1]).read_text())
assert len(sys.argv) == 2 or sys.argv[2:] == ["--recall"], "unknown oracle mode"
recall = len(sys.argv) == 3
assert len(names) == len(set(names)) == (8 if recall else 12), "unexpected manifest cardinality"
expected = bytes((i * 31 + i // 251) % 256 for i in range((1 << 20) + 17))
result = []
for name in names:
    pattern = (r"pnfs-recall-(windows|linux)-4\.[12]-(true|false)-\d+" if recall
               else r"pnfs-(api|cli)-(windows|linux)-4\.[12]-\d+")
    assert re.fullmatch(pattern, name), name
    for suffix in (["", "-empty"] if name.startswith("pnfs-api-") else [""]):
        path = Path("/brick/data") / (name + suffix)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 2, str(path)
        # A Gluster brick retains an internal GFID hardlink, unlike the
        # logical NFS namespace. Verify that link instead of assuming nlink=1.
        gfid = uuid.UUID(bytes=os.getxattr(path, "trusted.gfid"))
        hidden = path.parent / ".glusterfs" / gfid.hex[:2] / gfid.hex[2:4] / str(gfid)
        assert os.path.samefile(path, hidden), str(path)
        assert (info.st_uid, info.st_gid) == (25001, 25000), str(path)
        content = path.read_bytes()
        assert content == (b"" if suffix else expected), str(path)
        mode = stat.S_IMODE(info.st_mode)
        if name.startswith("pnfs-api-") and not suffix:
            assert mode == 0o640, (str(path), mode)
        result.append({"file": path.name, "size": len(content), "uid": info.st_uid,
                       "gid": info.st_gid, "mode": oct(mode),
                       "sha256": hashlib.sha256(content).hexdigest()})
assert len(result) == (8 if recall else 16)
print(json.dumps({"verified": True, "files": result}, indent=2))
