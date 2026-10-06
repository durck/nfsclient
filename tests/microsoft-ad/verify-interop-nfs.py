#!/usr/bin/env python3
"""Read-only independent checks of one completed, retained interop run."""
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    return result.returncode, result.stdout.strip()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(len(sys.argv) == 2, 'One absolute completed run directory required')
    run = pathlib.Path(sys.argv[1])
    require(run.is_absolute() and run.parent == pathlib.Path('/var/lib/nfs-viewer-msad/runs') and not run.is_symlink(), 'Unexpected run path')
    report = json.loads((run/'evidence.json').read_text())
    for key in ('passed', 'ordinary_user_kerberos_passed', 'nfs_passed', 'server_restart_passed', 'domain_preserved'):
        require(report.get(key) is True, 'Missing success: '+key)
    require('error' not in report and 'cleanup_error' not in report, 'Run contains errors')
    require(report['before'] == report['after'], 'Reported domain metadata changed')
    for name, expected in report['before'].items():
        if name == 'sssd_pid':
            require(command('systemctl', 'show', 'sssd', '-p', 'MainPID', '--value') == (0, expected), 'SSSD process changed')
            continue
        p = pathlib.Path(name)
        require(not p.is_symlink(), 'Redirected domain file')
        a = p.stat()
        actual = dict(inode=a.st_ino, bytes=a.st_size, uid=a.st_uid, gid=a.st_gid, mode=a.st_mode, mtime=a.st_mtime_ns, ctime=a.st_ctime_ns)
        require(actual == expected, 'Current domain metadata differs: '+name)
    for service, active in report['services_before'].items():
        code, status = command('systemctl', 'is-active', service)
        require((code == 0 and status == 'active') == active, 'Service restoration mismatch: '+service)
    require(command('exportfs', '-v') == (0, ''), 'Exports remain')
    for name in ('/srv/nfs-viewer-msad-interop', '/etc/nfs.conf.d/99-nfs-viewer-msad.conf', '/etc/exports.d/nfs-viewer-msad.exports', '/run/systemd/system/gssproxy.service'):
        require(not os.path.lexists(name), 'Fixture path remains: '+name)
    for name, digest in report['artifacts'].items():
        require(hashlib.sha256((run/name).read_bytes()).hexdigest() == digest, 'Test artifact differs: '+name)
    logs = {name: (run/(name+'.log')).read_text() for name in ('nfs', 'kerberos', 'restart', 'lock-readiness', 'lock-readiness-restart')}
    windows = report.get('nfs_client_platform') == 'windows'
    if windows:
        client = json.loads((run/'windows-client.json').read_text(encoding='utf-8-sig'))
        require(client['passed'] is True and client['credentials_removed'] is True and report.get('staged_credentials_removed') is True, 'Windows credentials not cleaned')
        require(client['os'] == 'windows' and client['host'] == '192.0.2.20', 'Windows endpoint evidence differs')
        for name in ('cli-windows.test.exe', 'nfs-viewer-windows-amd64.exe'):
            require(client['artifacts'][name] == report['artifacts'][name], 'Windows artifact mismatch')
        for name in ('nfs', 'restart'):
            require('MSAD_CLIENT os=windows arch=amd64 host=192.0.2.20' in logs[name], 'Windows execution marker missing')
        require(client.get('udp_size') == 1024 and 'MSAD_UDP_SIZE bytes=1024' in logs['nfs'], 'Windows UDP limit evidence missing')
    for name, log in logs.items():
        require('--- FAIL:' not in log and '--- SKIP:' not in log and log.endswith('PASS\n'), 'Incomplete/failing log: '+name)
    expected = {f'{v}/{transport}/{sec}/{cred}' for v, transport in [('3', 'tcp'), ('3', 'udp'), ('4.0', 'tcp'), ('4.1', 'tcp'), ('4.2', 'tcp')] for sec in ('krb5', 'krb5i', 'krb5p') for cred in ('keytab', 'ccache')}
    actual = re.findall(r'--- PASS: TestMicrosoftADNFS/([^ ]+) ', logs['nfs'])
    require(len(actual) == 30 and set(actual) == expected, 'NFS leaf matrix differs')
    lock_profiles = {f'{v}/{sec}/{cred}' for v in ('4.0', '4.1', '4.2') for sec in ('krb5', 'krb5i', 'krb5p') for cred in ('keytab', 'ccache')}
    lock_actual = re.findall(r'--- PASS: TestMicrosoftADNFSLocks/([^ ]+) ', logs['nfs'])
    require(len(lock_actual) == 18 and set(lock_actual) == lock_profiles and logs['nfs'].count('LOCK_INTEROP shared_readers conflict owner_read_write unlock_handoff close_release') == 18, 'Lock matrix differs')
    require(logs['nfs'].count('LOCK_RANGE_INTEROP adjacent_writers overlapping_conflicts shared_readers future_eof whole_io_refused') == 18, 'Range lock matrix differs')
    require('MSAD_LOCK_RESTART uncertain protected_io_refused explicit_discard fresh_lock' in logs['restart'], 'Lock restart contract not verified')
    require(re.search(r'MSAD_AUTO_RESUME version=4\.1 security=krb5p bytes=458752 interrupted_at=32768 attempts=2 real_restart source_pinned prefix_verified', logs['restart']), 'Automatic in-flight download recovery not verified')
    require(re.search(r'MSAD_UPLOAD_RESUME version=4\.1 security=krb5p bytes=458752 interrupted_at=98304 real_restart prefix_verified fresh_write_lock', logs['restart']), 'AD upload resume across restart not verified')
    users = re.findall(r'--- PASS: TestMicrosoftADKerberosClient/((?:tcp|udp-preferred)/aes(?:128|256)/(?:alice|bob)/(?:keytab|ccache)) ', logs['kerberos'])
    require(len(set(users)) == 16 and logs['kerberos'].count('--- PASS: TestMicrosoftADKerberosClient/tcp/cache-principal-mismatch ') == 1 and logs['kerberos'].count('--- PASS: TestMicrosoftADKerberosClient/udp-preferred/cache-principal-mismatch ') == 1, 'Kerberos leaf matrix differs')
    require('--- PASS: TestMicrosoftADNFSServerRestart ' in logs['restart'], 'Restart not verified')
    tree = run/'tree'
    payload = b'Microsoft AD NFS binary\x00\n' * 32768
    replacement = b'replacement-with-hidden-ACL-rights\x00' * 32768
    for profile in expected:
        p = tree/'data'/profile.replace('/', '-')
        require(p.is_file() and not p.is_symlink(), 'Missing regular transfer file')
        attr = p.stat()
        require((attr.st_uid, attr.st_gid, attr.st_mode & 0o7777) == (25001, 25000, 0o640), 'Numeric ownership/mode mismatch')
        require(p.read_bytes() == (replacement if profile.startswith('3/') else payload), 'Retained payload mismatch')
        if profile.startswith('3/'):
            code, acl = command('getfacl', '-c', '-n', str(p))
            require(code == 0 and 'user:25002:rwx' in acl and 'mask::r--' in acl and 'group::---' in acl and 'other::---' in acl, 'Raw masked ACL differs')
    require((tree/'data/tree/sub/binary').read_bytes() == payload and (tree/'data/tree/sub/empty').is_dir(), 'Recursive evidence differs')
    require((tree/'data/restart.bin').read_bytes() == b'restart-and-verified-resume\x00' * 16384, 'Restart payload differs')
    upload = tree/'data/restart-upload.bin'
    require(upload.is_file() and not upload.is_symlink() and upload.read_bytes() == b'restart-and-verified-resume\x00' * 16384, 'Restart upload differs')
    st = upload.stat()
    require((st.st_uid,st.st_gid,st.st_mode & 0o7777)==(25001,25000,0o644), 'Restart upload ownership/mode differs')
    require((tree/'readers.txt').read_bytes() == b'domain-reader-seed\n', 'Seed changed')
    for profile in lock_profiles:
        p = tree/'data'/('locks-'+profile.replace('/', '-'))
        require(p.is_file() and not p.is_symlink() and p.read_bytes() == b'lock-updated\n', 'Lock handoff content differs')
        a = p.stat()
        require((a.st_uid, a.st_gid, a.st_mode & 0o7777) == (25001, 25000, 0o666), 'Lock file ownership differs')
    require(not list(tree.rglob('.nfs-upload-*')), 'Successful replacement left staging')
    require(not list(tree.rglob('lock-readiness-*')), 'Lock readiness probe left files')
    if windows:
        for cred in ('keytab', 'ccache'):
            p = tree/'data'/('windows-release-'+cred+'.bin')
            require(p.read_bytes() == bytes(range(256)) and p.stat().st_uid == 25001 and p.stat().st_gid == 25000, 'Windows release output differs')
    large_bytes = 0
    if report.get('large_restart_passed'):
        large = json.loads((run/'large.json').read_text())
        log = (run/'large.log').read_text()
        require(large == report['windows_client']['large'] and large['passed'] is True and large['server_restart'] is True, 'Large report differs')
        require('--- FAIL:' not in log and '--- SKIP:' not in log and log.endswith('PASS\n') and 'MSAD_LARGE replacement interrupted_download real_restart verified_resume' in log, 'Large test incomplete')
        require(large['bytes'] == (1 << 32) + 17 and 64 << 20 <= large['retained_prefix'] < large['bytes'], 'Large boundary/prefix differs')
        p = tree/'data/large.bin'
        a = p.stat()
        require(a.st_size == large['bytes'] and (a.st_uid, a.st_gid, a.st_mode & 0o7777) == (25001, 25000, 0o640), 'Large metadata differs')
        pattern = bytearray(i % 251 for i in range(1 << 20))
        pattern[8:16] = b'NFSBIG01'
        h = hashlib.sha256()
        with p.open('rb') as f:
            for index in range(4097):
                pattern[:8] = struct.pack('<Q', index)
                expected = pattern if index < 4096 else pattern[:17]
                got = f.read(len(expected))
                require(got == expected, 'Large block differs: '+str(index))
                h.update(got)
            require(f.read(1) == b'', 'Large trailing data')
        require(h.hexdigest() == large['sha256'], 'Large hash differs')
        code, acl = command('getfacl', '-c', '-n', str(p))
        require(code == 0 and 'user:25002:rwx' in acl and 'mask::r--' in acl and 'group::---' in acl and 'other::---' in acl, 'Large masked ACL differs')
        large_bytes = a.st_size
    print(json.dumps(dict(passed=True, nfs_client_platform=report.get('nfs_client_platform', 'linux'), nfs_leaves=30, lock_leaves=18, range_lock_profiles=18, lock_restart=True, automatic_download_restart=True, upload_resume_restart=True, kerberos_leaves=18, raw_acl_files=12, recursive=True, server_restart=True, domain_preserved=True, cleanup_verified=True, windows_release_profiles=2 if windows else 0, large_bytes=large_bytes, artifacts=report['artifacts']), indent=2))


if __name__ == '__main__':
    main()
