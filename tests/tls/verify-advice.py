#!/usr/bin/env python3
"""Check that unsupported advice did not alter data or leave fixture services."""
import json
import os
import pathlib
import subprocess
import sys

run = pathlib.Path(sys.argv[1]).resolve()
assert run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and run.name.startswith('tls-')
evidence = json.loads((run/'evidence.json').read_text())
assert evidence['passed'] and evidence['domain_preserved']
assert evidence['before'] == evidence['after'] and evidence['services_before'] == evidence['services_after']
tree = run/'tree/data'
assert sorted(p.name for p in tree.iterdir()) == ['link', 'readonly', 'seed']
assert (tree/'seed').read_bytes() == b'kernel RPC-with-TLS fixture\n'
assert (tree/'readonly').read_bytes() == b'immutable-space-fixture\n'
assert (tree/'readonly').stat().st_mode & 0o7777 == 0o444
assert (tree/'link').is_symlink() and os.readlink(tree/'link') == 'readonly'
assert not subprocess.check_output(['exportfs', '-v']).strip()
for p in ('/srv/nfs-viewer-tls', '/etc/nfs.conf.d/99-nfs-viewer-tls.conf', '/etc/exports.d/nfs-viewer-tls.exports'):
    assert not pathlib.Path(p).exists()
print(json.dumps(dict(passed=True, real_server_advice_supported=False, retained_bytes_unchanged=True, domain_preserved=True, services_restored=True), indent=2))
