"""Resolve a complete KDC dependency closure from existing signed Ubuntu indexes."""
import argparse
import hashlib
import json
import pathlib
import runpy
import shlex
import shutil
import subprocess
import tempfile
import urllib.parse

BASE = pathlib.Path('/base')
BUNDLE = pathlib.Path('/bundle')
SCRIPT = '/scripts/verify-linux-bundle.py'
TARGETS = ['krb5-kdc', 'krb5-admin-server', 'acl', 'nfs-kernel-server', 'krb5-user']
parser = argparse.ArgumentParser()
parser.add_argument('--profile', choices=('kernel-gss', 'kernel-gssproxy'), default='kernel-gss')
profile = parser.parse_args().profile
base_profile = 'kernel-gss' if profile == 'kernel-gssproxy' else 'posix-acl'
if profile == 'kernel-gssproxy':
    TARGETS.append('gssproxy')
if not pathlib.Path('/.dockerenv').is_file() or (BUNDLE / 'verified.json').exists():
    raise SystemExit('Requires an isolated preparation container and unfinished bundle')
subprocess.run(['python3', SCRIPT, 'check', str(BASE), '--profile', base_profile], check=True)
verifier = runpy.run_path(SCRIPT)
proof = json.loads((BASE / 'provenance.json').read_text())
for directory in ('debs', 'provenance'):
    shutil.copytree(BASE / directory, BUNDLE / directory, dirs_exist_ok=True)

with tempfile.TemporaryDirectory(prefix='nfs-gss-resolver-') as temporary:
    work = pathlib.Path(temporary)
    lists = work / 'lists'
    (lists / 'partial').mkdir(parents=True)
    for record in proof['indexes']:
        for key in ('index', 'release'):
            source = BASE / record[key]
            shutil.copyfile(source, lists / source.name)
    (work / 'status').write_text('')
    (work / 'sources.list').write_text(
        'deb http://archive.ubuntu.com/ubuntu noble main universe\n'
        'deb http://archive.ubuntu.com/ubuntu noble-updates main universe\n'
        'deb http://security.ubuntu.com/ubuntu noble-security main universe\n')
    args = ['apt-get', '-o', 'Dir::Etc::sourcelist=' + str(work / 'sources.list'),
            '-o', 'Dir::Etc::sourceparts=-', '-o', 'Dir::State::lists=' + str(lists),
            '-o', 'Dir::State::status=' + str(work / 'status'),
            '--print-uris', '--download-only', '--no-install-recommends', '-y', 'install', *TARGETS]
    resolved = subprocess.check_output(args, text=True)
(BUNDLE / 'dependency-plan.txt').write_text(resolved)
uris = [shlex.split(line) for line in resolved.splitlines() if line.startswith("'")]
if not uris:
    raise SystemExit('APT returned no dependency download plan')
wanted_names = {urllib.parse.unquote(pathlib.PurePosixPath(item[0]).name) for item in uris}
signed = {}
for record in proof['indexes']:
    index = subprocess.check_output(['/usr/lib/apt/apt-helper', 'cat-file', str(BASE / record['index'])]).decode()
    wanted = {item['SHA256'] for item in verifier['paragraphs'](index)
              if pathlib.PurePosixPath(item.get('Filename', '')).name in wanted_names}
    signed.update(verifier['authenticate_index'](BASE, record, wanted))
by_name = {pathlib.PurePosixPath(item['Filename']).name: item for item in signed.values()}
existing_hashes = {hashlib.sha256(path.read_bytes()).hexdigest() for path in (BUNDLE / 'debs').glob('*.deb')}
plan = []
for uri in uris:
    basename = urllib.parse.unquote(pathlib.PurePosixPath(uri[0]).name)
    package = by_name.get(basename)
    if package is None or package['Architecture'] not in ('amd64', 'all'):
        raise SystemExit('APT selected a package absent from the authenticated snapshot: ' + basename)
    pool = pathlib.PurePosixPath(package['Filename'])
    if not str(pool).startswith('pool/') or '..' in pool.parts or int(package['Size']) != int(uri[2]):
        raise SystemExit('Unexpected signed pool path or size')
    # APT may percent-escape the epoch in its suggested local filename. Use the
    # signed upstream basename consistently for source, destination and evidence.
    target = BUNDLE / 'debs' / pool.name
    record = {'source': 'https://archive.ubuntu.com/ubuntu/' + str(pool), 'filename': pool.name,
              'bytes': int(package['Size']), 'sha256': package['SHA256'],
              'package': package['Package'], 'version': package['Version']}
    if record['sha256'] in existing_hashes:
        continue
    if target.exists():
        if target.stat().st_size != record['bytes'] or hashlib.sha256(target.read_bytes()).hexdigest() != record['sha256']:
            raise SystemExit('Existing dependency bytes differ from signed snapshot')
    else:
        plan.append(record)
proof['requested'] = TARGETS
proof['snapshot_reuse'] = 'Authenticated ' + base_profile + ' bundle plus empty-state APT ' + profile + ' dependency closure from the same signed indexes'
(BUNDLE / 'provenance.json').write_text(json.dumps(proof, indent=2) + '\n')
(BUNDLE / 'gss-download-plan.json').write_text(json.dumps(plan, indent=2) + '\n')
print(json.dumps({'additional_downloads': len(plan), 'bytes': sum(item['bytes'] for item in plan), 'targets': TARGETS}))
