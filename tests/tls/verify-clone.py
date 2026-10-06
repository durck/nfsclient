#!/usr/bin/env python3
"""Validate captured native COW evidence, retained archive and mount cleanup."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile

run = pathlib.Path(sys.argv[1]).resolve()
assert run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and run.name.startswith('tls-')
evidence = json.loads((run/'evidence.json').read_text())
native = json.loads((run/'native-clone.json').read_text())
assert evidence['passed'] and evidence['domain_preserved'] and evidence['private_loop_detached']
assert evidence['before'] == evidence['after'] and evidence['services_before'] == evidence['services_after']
assert evidence['filesystem'] == native['filesystem'] and native['filesystem'] in ('btrfs', 'xfs')
assert native['passed'] and native['native_shared_extents'] and native['copy_on_write_bytes']
assert len(native['files']) == 20 and len(native['shared_pairs']) == 12
expected = {f['name']: f for f in native['files']}
seen = set()
with tarfile.open(run/'filesystem-data.tar') as archive:
    for member in archive:
        name = member.name.removeprefix('./')
        if name in ('.', 'seed', 'readonly', 'link'):
            continue
        assert name in expected and member.isfile() and name not in seen
        seen.add(name)
        f = expected[name]
        assert (member.uid, member.gid, member.mode, member.size) == (25001, 25000, 0o644, 262144)
        assert hashlib.sha256(archive.extractfile(member).read()).hexdigest() == f['sha256']
assert seen == set(expected)
assert not subprocess.check_output(['exportfs', '-v']).strip()
assert not subprocess.check_output(['losetup', '-j', str(run/'filesystem.img')]).strip()
for p in ('/srv/nfs-viewer-tls', '/etc/nfs.conf.d/99-nfs-viewer-tls.conf', '/etc/exports.d/nfs-viewer-tls.exports'):
    assert not pathlib.Path(p).exists()
print(json.dumps(dict(passed=True, filesystem=native['filesystem'], files=native['files'], shared_pairs=native['shared_pairs'], native_shared_extents=True, copy_on_write_bytes=True, domain_preserved=True, services_restored=True, private_loop_detached=True), indent=2))
