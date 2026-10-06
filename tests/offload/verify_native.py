"""Check native file hashes independently of NFS readback."""
import hashlib
import json
import pathlib
import re
import sys


def verify(path):
    source = bytes((i * 31 + i // 257) % 251 for i in range(262144))
    destination = bytearray(327680)
    destination[:32768] = b'D' * 32768
    destination[32768:163840] = source[65536:196608]
    destination[262144:] = source[:65536]
    expected = {'src': hashlib.sha256(source).hexdigest(), 'dst': hashlib.sha256(destination).hexdigest()}
    names = {f'offload-{prefix}-{kind}' for prefix in
             ('cli-windows', 'cli-linux', 'windows-false', 'windows-true', 'linux-false', 'linux-true')
             for kind in ('src', 'dst')}
    seen = set()
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})\s+(.+)', line)
        if not match:
            continue
        name = pathlib.PurePosixPath(match[2]).name
        assert name in names and name not in seen, name
        assert match[1] == expected[name.rsplit('-', 1)[1]], name
        seen.add(name)
    assert seen == names, names - seen
    return {'passed': True, 'native_files': len(seen), 'sha256': expected}


if __name__ == '__main__':
    print(json.dumps(verify(pathlib.Path(sys.argv[1])), indent=2))
