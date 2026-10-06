#!/usr/bin/python3
"""Verify synthetic runners refuse a joined lab without cleanup or poweroff."""
import hashlib
import json
import os
import pathlib
import subprocess


def output(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def snapshot():
    result = {'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'sssd': output('systemctl', 'show', 'sssd.service', '--property=ActiveState,SubState,MainPID')}
    for name in ('/etc/krb5.keytab', '/etc/sssd/sssd.conf', '/etc/krb5.conf', '/etc/idmapd.conf',
                 '/var/lib/nfs-viewer-msad/domain-joined.json', '/var/lib/nfs-lab-kernel.json',
                 '/var/lib/nfs-lab-kernel-gss.json'):
        path = pathlib.Path(name)
        info = path.lstat()
        # Keytab existence/inode/size/timestamps only; never open its contents.
        value = {'inode': info.st_ino, 'bytes': info.st_size, 'mode': info.st_mode,
                 'uid': info.st_uid, 'gid': info.st_gid, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
        if name != '/etc/krb5.keytab':
            value['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        result[name] = value
    return result


if __name__ == '__main__':
    if os.geteuid() != 0 or output('hostname', '-f') != 'nfs.msad.nfs.test':
        raise SystemExit('Expected root inside the joined lab guest')
    state = json.loads(pathlib.Path('/var/lib/nfs-viewer-msad/domain-joined.json').read_text())
    if state.get('domain') != 'msad.nfs.test' or state.get('phase') != 'verified':
        raise SystemExit('Domain identity verification must pass first')
    before = snapshot()
    if 'ActiveState=active' not in before['sssd']:
        raise SystemExit('SSSD must already be active')
    checks = []
    for script, args in (('run-kernel-nfs.py', []), ('run-kernel-gss.py', []), ('run-kernel-gss.py', ['--auth-sys'])):
        path = pathlib.Path(__file__).with_name(script)
        # -B prevents import bytecode as well as fixture mutations.
        process = subprocess.run(['/usr/bin/python3', '-B', str(path), *args], text=True, capture_output=True, timeout=15)
        expected = 'Refusing synthetic kernel fixture: domain indicator exists at /etc/krb5.keytab'
        if process.returncode != 1 or process.stdout or process.stderr.strip() != expected:
            raise RuntimeError('Unexpected guard result: ' + script + '\n' + process.stdout + process.stderr)
        checks.append({'script': script, 'args': args, 'exit': process.returncode,
                       'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'refusal': process.stderr.strip()})
    after = snapshot()
    if before != after:
        raise RuntimeError('Domain/fixture evidence or service state changed during refusal')
    testjoin = output('adcli', 'testjoin', '--domain=msad.nfs.test', '--host-keytab=/etc/krb5.keytab')
    print(json.dumps({'passed': True, 'checks': checks, 'before': before, 'after': after, 'testjoin': testjoin}, sort_keys=True))
