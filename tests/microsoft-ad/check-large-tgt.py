"""Network-isolated MIT smoke for the fixture-only public-API TGT helper.

Run in the existing nfs-viewer-vfs-acl-build image with --network none and
--tmpfs /run:rw,nosuid,nodev,mode=755,
the repository's scripts at /scripts:ro and a new ignored output at /output.
No credentials, ticket bytes or daemon log bodies leave the container.
"""
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import subprocess
import tempfile
import time

if not pathlib.Path('/.dockerenv').is_file():
    raise SystemExit('Requires a disposable Docker container')
runtime_fs = subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', '/run'], text=True).strip()
if runtime_fs != 'tmpfs':
    raise SystemExit('Requires explicit /run tmpfs to reproduce the guest cache semantics')
os.umask(0o077)
out = pathlib.Path('/output')
binary = out / 'gss-large-tgt'
if binary.exists():
    raise SystemExit('Requires a new output directory')
source = pathlib.Path('/scripts/gss-large-tgt.c')
flags = shlex.split(subprocess.check_output(['krb5-config', '--cflags', '--libs'], text=True))
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-o',
                str(binary), str(source), *flags], check=True)
evidence = {'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'helper_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'credential_filesystem': runtime_fs,
            'versions': subprocess.check_output(['dpkg-query', '-W', 'gcc', 'libkrb5-dev',
                                                 'libkrb5-3', 'krb5-kdc'], text=True)}

with tempfile.TemporaryDirectory(prefix='large-tgt-', dir='/run') as temporary:
    root = pathlib.Path(temporary)
    config = root / 'krb5.conf'
    config.write_text('''[libdefaults]
default_realm = NFS.TEST
dns_lookup_kdc = false
dns_lookup_realm = false
rdns = false
udp_preference_limit = 1
[realms]
NFS.TEST = {
 kdc = 127.0.0.1:10088
}
''')
    kdc_config = root / 'kdc.conf'
    kdc_config.write_text(f'''[kdcdefaults]
kdc_listen = 127.0.0.1:10088
kdc_tcp_listen = 127.0.0.1:10088
[realms]
NFS.TEST = {{
 database_name = {root}/principal
 key_stash_file = {root}/stash
 acl_file = {root}/kadm5.acl
 max_life = 1h
 max_renewable_life = 0
 default_principal_flags = +preauth
 supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 disable_pac = true
}}
''')
    env = dict(os.environ, KRB5_CONFIG=str(config), KRB5_KDC_PROFILE=str(kdc_config),
               KRB5CCNAME='FILE:' + str(root / 'alice.ccache'))
    master = secrets.token_urlsafe(48)
    create = subprocess.run(['kdb5_util', 'create', '-s', '-r', 'NFS.TEST'],
                            input=master + '\n' + master + '\n', text=True,
                            capture_output=True, env=env)
    del master
    if create.returncode:
        raise RuntimeError('Dedicated KDC creation failed')
    for principal, name in [('alice@NFS.TEST', 'alice'),
                            ('nfs/server.nfs.test@NFS.TEST', 'server')]:
        for query in ['addprinc -randkey ' + principal,
                      f'ktadd -norandkey -k {root}/{name}.keytab {principal}']:
            subprocess.run(['kadmin.local', '-r', 'NFS.TEST', '-q', query],
                           env=env, check=True, capture_output=True)
    with (root / 'kdc.log').open('w') as log:
        process = subprocess.Popen(['krb5kdc', '-n', '-r', 'NFS.TEST', '-P',
                                    str(root / 'kdc.pid')], env=env,
                                   stdout=log, stderr=subprocess.STDOUT)
    try:
        for attempt in range(50):
            if process.poll() is not None:
                raise RuntimeError('Dedicated KDC exited')
            login = subprocess.run(['kinit', '-k', '-t', str(root / 'alice.keytab'),
                                    'alice@NFS.TEST'], env=env, capture_output=True,
                                   timeout=3)
            if login.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError('Dedicated KDC readiness deadline')
        original_hash = hashlib.sha256((root / 'alice.ccache').read_bytes()).hexdigest()
        target = root / 'large.ccache'
        args = [str(binary), env['KRB5CCNAME'], str(target), str(root / 'server.keytab')]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise RuntimeError('Large-TGT helper failed: ' + result.stderr.strip())
        evidence['positive'] = json.loads(result.stdout)
        assert evidence['positive']['service_ticket_bytes'] > 2048
        assert target.stat().st_mode & 0o777 == 0o600 and target.stat().st_nlink == 1
        assert not list(root.glob('.gss-large-tgt-*'))
        assert original_hash == hashlib.sha256((root / 'alice.ccache').read_bytes()).hexdigest()
        target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        repeated = subprocess.run(args, env=env, capture_output=True, text=True, timeout=15)
        assert repeated.returncode != 0 and not repeated.stdout
        assert target_hash == hashlib.sha256(target.read_bytes()).hexdigest()
        link = root / 'collision.ccache'
        link.symlink_to(target)
        collision = subprocess.run([str(binary), env['KRB5CCNAME'], str(link),
                                    str(root / 'server.keytab')], env=env,
                                   capture_output=True, text=True, timeout=15)
        assert collision.returncode != 0 and not collision.stdout and link.is_symlink()
        assert link.readlink() == target and target_hash == hashlib.sha256(target.read_bytes()).hexdigest()
        missing = root / 'failed.ccache'
        failure = subprocess.run([str(binary), env['KRB5CCNAME'], str(missing),
                                  str(root / 'missing.keytab')], env=env,
                                 capture_output=True, text=True, timeout=15)
        assert failure.returncode != 0 and not failure.stdout and not missing.exists()
        assert not list(root.glob('.gss-large-tgt-*'))
        assert original_hash == hashlib.sha256((root / 'alice.ccache').read_bytes()).hexdigest()
        evidence['negative'] = {'existing_output_unchanged': True,
                                'symlink_output_unchanged': True,
                                'failed_verification_removed_output': True,
                                'no_staging_remnants': True,
                                'input_cache_unchanged': True}
    finally:
        process.terminate()
        process.wait(timeout=5)
    evidence['kdc_exited'] = process.returncode is not None
evidence['credential_runtime_removed'] = not root.exists()
(out / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
print(json.dumps(evidence, indent=2))
