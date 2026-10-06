#!/usr/bin/env python3
"""Bounded RPC-with-TLS fixture on the existing isolated Linux guest."""
import hashlib
import argparse
import importlib.util
import json
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path('/srv/nfs-viewer-tls')
CONFIG = pathlib.Path('/etc/nfs.conf.d/99-nfs-viewer-tls.conf')
EXPORT = pathlib.Path('/etc/exports.d/nfs-viewer-tls.exports')
SERVICES = ['nfs-server', 'nfs-mountd', 'nfs-idmapd', 'rpc-statd', 'rpcbind', 'rpcbind.socket']


def command(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr[-1500:]}')
    return p.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run_id')
    parser.add_argument('--space', action='store_true')
    parser.add_argument('--filesystem', choices=('ext4', 'btrfs', 'xfs'), default='ext4')
    parser.add_argument('--noatime', action='store_true')
    parser.add_argument('--mtls', action='store_true')
    args = parser.parse_args()
    if args.noatime and args.filesystem == 'ext4':
        raise ValueError('noatime is limited to a private filesystem image')
    if not args.run_id.startswith('tls-') or not all(c.isalnum() or c == '-' for c in args.run_id):
        raise ValueError('Fresh tls-RUN-ID required')
    if os.geteuid() != 0 or socket.gethostname() != 'nfs':
        raise ValueError('Dedicated guest only')
    if command('ip', 'route', 'show', 'default') or command('ip', '-6', 'route', 'show', 'default'):
        raise ValueError('Isolated guest only')
    if command('exportfs', '-v') or command('systemctl', 'is-active', 'nfs-server', check=False) == 'active' or command('pgrep', '-x', 'tlshd', check=False):
        raise ValueError('NFS/TLS service already owned')
    spec = importlib.util.spec_from_file_location('interop', pathlib.Path(__file__).with_name('run-interop-nfs.py'))
    interop = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(interop)
    before = interop.domain_state()
    states = {s: command('systemctl', 'is-active', s, check=False) == 'active' for s in SERVICES}
    for p in (ROOT, CONFIG, EXPORT):
        if p.exists() or p.is_symlink():
            raise ValueError('Existing fixture path: '+str(p))
    run = pathlib.Path('/var/lib/nfs-viewer-msad/runs')/args.run_id
    run.mkdir(mode=0o700)
    control = pathlib.Path(__file__).parent/'tls-control'
    control.mkdir(mode=0o700)
    command('chown', 'labadmin:labadmin', str(control))
    evidence = dict(run=str(run), before=before, services_before=states, passed=False)
    evidence['system_trust_before'] = hashlib.sha256(pathlib.Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()).hexdigest()
    process = None
    changed = False
    loop = None
    mounted = False
    try:
        package = pathlib.Path(__file__).with_name('ktls-utils_0.9-2build2_amd64.deb')
        if hashlib.sha256(package.read_bytes()).hexdigest() != '1c7cce0e0ada0bd5b6d5a64918f755e295486cbe435ade0c09b2171e9c5a6968':
            raise ValueError('Authenticated package digest differs')
        command('dpkg-deb', '-x', str(package), str(run/'package'))
        executable = run/'package/usr/sbin/tlshd'
        repaired = pathlib.Path(__file__).with_name('tlshd-alpn')
        if repaired.is_file():
            executable = repaired
            executable.chmod(0o755)
        evidence['executable_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
        evidence['alpn_fixture_build'] = repaired.is_file()
        evidence['tlshd'] = command(str(executable), '-v', check=False)
        # Generate fixture-only credentials in the guest; no existing key read.
        private = run/'private'
        private.mkdir(mode=0o700)
        command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=nfs-tls.test', '-keyout', str(private/'server.key'), '-out', str(private/'server.csr'))
        (private/'server.key').chmod(0o600)
        (private/'index').touch()
        (private/'serial').write_text('01\n')
        (private/'ca.conf').write_text(f'''[ca]
default_ca=local
[local]
database={private}/index
serial={private}/serial
new_certs_dir={private}
private_key={private}/server.key
default_md=sha256
policy=policy
x509_extensions=server
[policy]
commonName=supplied
[server]
subjectAltName=DNS:nfs-tls.test,IP:127.0.0.1,IP:192.0.2.20
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,1.3.6.1.5.5.7.3.34
''')
        command('openssl', 'ca', '-batch', '-selfsign', '-config', str(private/'ca.conf'), '-in', str(private/'server.csr'), '-out', str(run/'server.crt'), '-startdate', '20200101000000Z', '-enddate', '20400101000000Z')
        command('install', '-m', '644', str(run/'server.crt'), str(control/'server.crt'))
        (run/'tlshd.conf').write_text(f'[main]\ndebug=1\n[authenticate.server]\nx509.certificate={run}/server.crt\nx509.private_key={private}/server.key\n')
        if args.mtls:
            # Only fresh fixture keys. The server trust override stays in its
            # private mount namespace; neither system trust nor AD is modified.
            command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=NFS fixture client CA', '-keyout', str(private/'client-ca.key'), '-out', str(private/'client-ca.csr'))
            (private/'client-ca.key').chmod(0o600)
            ca_config = private/'client-ca.conf'
            ca_config.write_text(f'''[ca]
default_ca=local
[local]
database={private}/client-index
serial={private}/client-serial
new_certs_dir={private}
private_key={private}/client-ca.key
certificate={private}/client-ca.crt
default_md=sha256
policy=policy
unique_subject=no
[policy]
commonName=supplied
[root]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
[client]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth,1.3.6.1.5.5.7.3.34
''')
            (private/'client-index').touch()
            (private/'client-serial').write_text('1000\n')
            command('openssl', 'ca', '-batch', '-selfsign', '-config', str(ca_config), '-extensions', 'root', '-in', str(private/'client-ca.csr'), '-out', str(private/'client-ca.crt'), '-startdate', '20200101000000Z', '-enddate', '20400101000000Z')
            for name, start, end in (('client', '20200101000000Z', '20400101000000Z'), ('expired', '20000101000000Z', '20010101000000Z')):
                command('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=NFS fixture '+name, '-keyout', str(private/(name+'.key')), '-out', str(private/(name+'.csr')))
                (private/(name+'.key')).chmod(0o600)
                command('openssl', 'ca', '-batch', '-config', str(ca_config), '-extensions', 'client', '-in', str(private/(name+'.csr')), '-out', str(private/(name+'.crt')), '-startdate', start, '-enddate', end)
                for suffix in ('.crt', '.key'):
                    command('install', '-o', 'labadmin', '-g', 'labadmin', '-m', '600', str(private/(name+suffix)), str(control/(name+suffix)))
            # ktls-utils 0.9 server code uses system trust, even when a server
            # truststore is configured. Overlay its namespace-local bundle.
            (run/'client-trust.pem').write_bytes(pathlib.Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()+b'\n'+(private/'client-ca.crt').read_bytes())
            evidence['mutual_tls'] = True
        # Give only the daemon's mount namespace deterministic reverse lookup.
        # Global guest hosts/DNS and domain configuration remain untouched.
        (run/'hosts').write_text(pathlib.Path('/etc/hosts').read_text()+'\n192.0.2.10 tls-windows-client.test\n')
        launcher = run/'launch.sh'
        trust_mount = f'mount --bind {run}/client-trust.pem /etc/ssl/certs/ca-certificates.crt\n' if args.mtls else ''
        launcher.write_text(f'#!/bin/sh\nset -eu\nmount --bind {run}/hosts /etc/hosts\n{trust_mount}exec {executable} -s -c {run}/tlshd.conf\n')
        with (run/'tlshd.log').open('x') as log:
            process = subprocess.Popen(['unshare', '--mount', '--propagation', 'private', 'sh', str(launcher)], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        time.sleep(1)
        if process.poll() is not None:
            raise RuntimeError('tlshd startup failed')
        changed = True
        ROOT.mkdir(mode=0o755)
        (ROOT/'data').mkdir(mode=0o777)
        if args.filesystem != 'ext4':
            image = run/'filesystem.img'
            # Format only a fresh regular file in this run, never a disk device.
            with image.open('xb') as f:
                f.truncate(512*1024*1024)
            command('mkfs.'+args.filesystem, '-q', str(image))
            loop = command('losetup', '--find', '--show', '--nooverlap', str(image))
            if not re.fullmatch(r'/dev/loop\d+', loop):
                raise RuntimeError('Unexpected private loop device')
            if pathlib.Path(command('losetup', '--noheadings', '--output', 'BACK-FILE', loop)).resolve() != image:
                raise RuntimeError('Loop device does not belong to this run')
            mount_options = 'nodev,nosuid,noexec'+(',noatime' if args.noatime else '')
            command('mount', '-t', args.filesystem, '-o', mount_options, loop, str(ROOT/'data'))
            mounted = True
            evidence['private_loop_device'] = loop
        evidence['filesystem'] = command('findmnt', '--noheadings', '--output', 'FSTYPE', '--target', str(ROOT/'data'))
        evidence['mount_options'] = command('findmnt', '--noheadings', '--output', 'OPTIONS', '--target', str(ROOT/'data'))
        if evidence['filesystem'] != args.filesystem:
            raise RuntimeError('Unexpected export filesystem')
        (ROOT/'data').chmod(0o777)
        (ROOT/'data/seed').write_bytes(b'kernel RPC-with-TLS fixture\n')
        if args.space:
            (ROOT/'data/readonly').write_bytes(b'immutable-space-fixture\n')
            (ROOT/'data/readonly').chmod(0o444)
            (ROOT/'data/link').symlink_to('readonly')
        CONFIG.write_text('[nfsd]\nvers3=n\nvers4=y\nvers4.0=y\nvers4.1=y\nvers4.2=y\nthreads=4\ngrace-time=10\nlease-time=30\n')
        options = 'rw,sync,fsid=0,no_subtree_check,root_squash,insecure,sec=sys,xprtsec=tls'
        if args.mtls:
            options = options.replace('xprtsec=tls', 'xprtsec=mtls')
        lines = str(ROOT)+' '+ ' '.join(host+'('+options+')' for host in ('127.0.0.1', '192.0.2.10'))+'\n'
        if mounted:
            lines += str(ROOT/'data')+' '+' '.join(host+'('+options.replace('fsid=0', 'fsid=1')+')' for host in ('127.0.0.1', '192.0.2.10'))+'\n'
        EXPORT.write_text(lines)
        command('systemctl', 'start', 'nfs-server')
        interop.wait_grace()
        evidence['exports'] = command('exportfs', '-v')
        evidence['kernel'] = command('uname', '-r')
        command('modprobe', 'tls')
        evidence['tls_before'] = pathlib.Path('/proc/net/tls_stat').read_text()
        (control/'ready').write_text('TLS export ready\n')
        deadline = time.monotonic()+1800
        while not (control/'complete').exists():
            if (control/'failed').exists():
                raise RuntimeError('Client stage failed')
            if process.poll() is not None or time.monotonic() > deadline:
                raise TimeoutError('TLS fixture timed out or daemon exited')
            time.sleep(.25)
        evidence['tls_after'] = pathlib.Path('/proc/net/tls_stat').read_text()
        evidence['passed'] = True
    except Exception as exc:
        evidence['error'] = str(exc)
    finally:
        try:
            if changed:
                command('systemctl', 'stop', 'nfs-server')
                for client in ('127.0.0.1', '192.0.2.10'):
                    if mounted:
                        command('exportfs', '-u', client+':'+str(ROOT/'data'), check=False)
                    command('exportfs', '-u', client+':'+str(ROOT), check=False)
                for p in (CONFIG, EXPORT):
                    p.unlink(missing_ok=True)
                for service in SERVICES:
                    command('systemctl', 'start' if states[service] else 'stop', service)
                if command('exportfs', '-v'):
                    raise RuntimeError('Exports remain')
                if mounted:
                    capture = pathlib.Path(__file__).with_name('capture-clone.py')
                    if capture.is_file():
                        evidence['native_clone_capture'] = command('python3', str(capture), str(ROOT/'data'), str(run/'native-clone.json'), check=False)
                    command('tar', '--sparse', '-cpf', str(run/'filesystem-data.tar'), '-C', str(ROOT/'data'), '.')
                    command('umount', str(ROOT/'data'))
                    mounted = False
                if loop:
                    if pathlib.Path(command('losetup', '--noheadings', '--output', 'BACK-FILE', loop)).resolve() != run/'filesystem.img':
                        raise RuntimeError('Private loop ownership changed; detach withheld')
                    command('losetup', '-d', loop)
                    evidence['private_loop_detached'] = True
                    loop = None
                ROOT.rename(run/'tree')
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=15)
            if args.mtls:
                for name in ('client.crt', 'client.key', 'expired.crt', 'expired.key'):
                    (control/name).unlink(missing_ok=True)
                evidence['client_credential_copies_removed'] = all(not (control/name).exists() for name in ('client.crt', 'client.key', 'expired.crt', 'expired.key'))
            evidence['after'] = interop.domain_state()
            evidence['system_trust_after'] = hashlib.sha256(pathlib.Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()).hexdigest()
            if evidence['system_trust_before'] != evidence['system_trust_after']:
                raise RuntimeError('Global trust store changed')
            evidence['domain_preserved'] = before == evidence['after']
            evidence['services_after'] = {s: command('systemctl', 'is-active', s, check=False) == 'active' for s in SERVICES}
            evidence['passed'] &= evidence['domain_preserved'] and states == evidence['services_after']
        except Exception as exc:
            evidence['cleanup_error'] = str(exc)
            evidence['passed'] = False
        (run/'evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
        (control/'finished').write_text(json.dumps(dict(passed=evidence['passed'], error=evidence.get('error'))))
    return 0 if evidence['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
