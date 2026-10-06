#!/usr/bin/env python3
"""Native AD reclaim audit, without reading any credential material."""
import hashlib
import json
import pathlib
import subprocess
import sys

run = pathlib.Path(sys.argv[1]).resolve()
assert run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and run.name.startswith('interop-')
e = json.loads((run/'evidence.json').read_text())
assert e['passed'] and e['reclaim_passed'] and e['domain_preserved'] and e['before'] == e['after']
assert e['reclaim_restart_tokens'] == list('123456')
if 'idmap_before_sha256' in e:
    assert e['idmap_before_sha256'] == e['idmap_after_sha256']
    assert hashlib.sha256(pathlib.Path('/etc/idmapd.conf').read_bytes()).hexdigest() == e['idmap_before_sha256']
for name, expected in e['services_before'].items():
    active = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True).stdout.strip() == 'active'
    assert active == expected, name
assert not subprocess.check_output(['exportfs', '-v']).strip()
for p in ('/srv/nfs-viewer-msad-interop','/etc/nfs.conf.d/99-nfs-viewer-msad.conf','/etc/exports.d/nfs-viewer-msad.exports','/run/systemd/system/gssproxy.service'):
    assert not pathlib.Path(p).exists() and not pathlib.Path(p).is_symlink()
for name, digest in e['artifacts'].items():
    assert hashlib.sha256((run/name).read_bytes()).hexdigest() == digest
platform = e['nfs_client_platform']
log = (run/'reclaim.log').read_text(encoding='utf-8-sig')
assert log.rstrip().endswith('PASS') and '--- FAIL:' not in log and '--- SKIP:' not in log
for kind in ('API', 'CLI'):
    for version in ('4.0', '4.1', '4.2'):
        assert log.count('RECLAIM_'+kind+' os='+platform+' version='+version) == 1
kerberos = (run/'kerberos.log').read_text()
assert kerberos.rstrip().endswith('PASS') and '--- FAIL:' not in kerberos and '--- SKIP:' not in kerberos
if platform == 'windows':
    client = e['windows_client']
    assert client['passed'] and client['credentials_removed'] and client['acl_protected'] and e['staged_credentials_removed']
    for name, digest in client['artifacts'].items():
        assert e['artifacts'][name] == digest.lower()
expected = {'reclaim-'+platform+'-'+v+suffix for v in ('4.0','4.1','4.2') for suffix in ('','-range')}
expected.update('reclaim-cli-'+platform+'-'+v for v in ('4.0','4.1','4.2'))
payload = b'reclaimed state\0'*4096
files = []
for p in (run/'tree/data').iterdir():
    assert p.name in expected
    expected.remove(p.name)
    s = p.lstat()
    assert p.is_file() and not p.is_symlink() and p.read_bytes() == payload
    assert (s.st_uid,s.st_gid,s.st_mode & 0o7777) == (25001,25000,0o644)
    files.append(dict(name=p.name,bytes=s.st_size,sha256=hashlib.sha256(payload).hexdigest()))
assert not expected
assert (run/'tree/readers.txt').read_bytes() == b'domain-reader-seed\n'
print(json.dumps(dict(passed=True,platform=platform,security='krb5p',real_server_restarts=6,files=files,services_domain_preserved=True,artifacts=e['artifacts']),indent=2))
