#!/usr/bin/env python3
"""Disposable software-iWARP NFS fixture; no package or network reconfiguration."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path('/srv/nfs-viewer-rdma')
CONFIG = pathlib.Path('/etc/nfs.conf.d/99-nfs-viewer-rdma.conf')
EXPORT = pathlib.Path('/etc/exports.d/nfs-viewer-rdma.exports')
DEVICE = 'nvfs-siw'
SERVICES = ['nfs-server', 'nfs-mountd', 'nfs-idmapd', 'rpc-statd', 'rpcbind', 'rpcbind.socket']
PACKAGE = 'linux-modules-extra-6.8.0-139-generic_6.8.0-139.139_amd64.deb'
DIGEST = '16eb3067d7ef3d25f275663c6710f6531c525ba1aeef6eeb07e5186238d5f17c'

def command(*args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if check and p.returncode:
        raise RuntimeError(args[0]+' failed: '+p.stderr[-1200:])
    return p.stdout.strip()

def loaded_modules():
    return {line.split()[0] for line in pathlib.Path('/proc/modules').read_text().splitlines()}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run_id')
    parser.add_argument('--reclaim', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch(r'rdma-[a-zA-Z0-9-]+', args.run_id):
        raise ValueError('Fresh RDMA run id required')
    if os.geteuid() != 0 or platform.node() != 'nfs' or platform.release() != '6.8.0-139-generic':
        raise ValueError('Dedicated matching-kernel guest required')
    if command('ip', 'route', 'show', 'default') or command('ip', '-6', 'route', 'show', 'default'):
        raise ValueError('Isolated guest required')
    if command('exportfs', '-v') or command('systemctl', 'is-active', 'nfs-server', check=False) == 'active':
        raise ValueError('Existing NFS owner')
    for p in (ROOT, CONFIG, EXPORT):
        if p.exists() or p.is_symlink():
            raise ValueError('Existing fixture path: '+str(p))
    if pathlib.Path('/sys/class/infiniband/'+DEVICE).exists():
        raise ValueError('Existing RDMA device')
    spec = importlib.util.spec_from_file_location('interop', pathlib.Path(__file__).with_name('run-interop-nfs.py'))
    interop = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(interop)
    before = interop.domain_state()
    states = {s: command('systemctl', 'is-active', s, check=False) == 'active' for s in SERVICES}
    run = pathlib.Path('/var/lib/nfs-viewer-msad/runs')/args.run_id
    run.mkdir(mode=0o700)
    control = pathlib.Path(__file__).parent/'rdma-control'
    control.mkdir(mode=0o700)
    command('chown', 'labadmin:labadmin', str(control))
    evidence = dict(run=str(run), before=before, services_before=states, passed=False, modules_before=sorted(loaded_modules()))
    installed = []
    linked = False
    changed = False
    try:
        package = pathlib.Path(__file__).with_name(PACKAGE)
        if hashlib.sha256(package.read_bytes()).hexdigest() != DIGEST:
            raise ValueError('Authenticated module package digest differs')
        command('dpkg-deb', '-x', str(package), str(run/'package'))
        module_files = list((run/'package').rglob('*.ko*'))
        visiting = set()

        def load(name):
            name = name.replace('-', '_')
            if name in loaded_modules():
                return
            if name in visiting:
                raise ValueError('Module dependency cycle')
            visiting.add(name)
            path = command('modinfo', '-n', name, check=False)
            if path == '(builtin)':
                visiting.remove(name)
                return
            if not path or not pathlib.Path(path).is_file():
                found = [p for p in module_files if p.name.split('.ko')[0].replace('-', '_') == name]
                if len(found) != 1:
                    raise ValueError('Missing or ambiguous module '+name)
                path = str(found[0])
            if not command('modinfo', '-F', 'vermagic', path).startswith(platform.release()+' '):
                raise ValueError('Module kernel differs')
            for dependency in command('modinfo', '-F', 'depends', path).split(','):
                if dependency:
                    load(dependency)
            command('insmod', path)
            installed.append(name)
            visiting.remove(name)

        load('siw')
        load('rpcrdma')
        routes = json.loads(command('ip', '-j', 'route', 'get', '192.0.2.10'))
        interface = routes[0]['dev']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', interface) or routes[0].get('gateway'):
            raise ValueError('Direct isolated adapter required')
        command('rdma', 'link', 'add', DEVICE, 'type', 'siw', 'netdev', interface)
        linked = True
        evidence['rdma_link'] = command('rdma', 'link', 'show', DEVICE+'/1')
        changed = True
        ROOT.mkdir(mode=0o755)
        (ROOT/'data').mkdir(mode=0o777)
        (ROOT/'data').chmod(0o777)
        (ROOT/'data/seed').write_bytes(b'real software-iWARP NFS fixture\n')
        CONFIG.write_text('[nfsd]\nvers3=n\nvers4=y\nvers4.0=y\nvers4.1=y\nvers4.2=y\nthreads=4\ngrace-time=10\nlease-time=30\n')
        options = 'rw,sync,fsid=0,no_subtree_check,root_squash,insecure,sec=sys'
        EXPORT.write_text(str(ROOT)+' '+' '.join(host+'('+options+')' for host in ('192.0.2.20', '192.0.2.10'))+'\n')
        command('systemctl', 'start', 'nfs-server')
        pathlib.Path('/proc/fs/nfsd/portlist').write_text('rdma 20049\n')
        interop.wait_grace()
        evidence['listeners'] = pathlib.Path('/proc/fs/nfsd/portlist').read_text()
        if 'rdma 20049' not in evidence['listeners']:
            raise ValueError('RDMA listener missing')
        evidence['exports'] = command('exportfs', '-v')
        evidence['modules_loaded'] = installed.copy()
        (control/'ready').write_text('RDMA fixture ready\n')
        deadline = time.monotonic()+1800
        restart_token = ''
        evidence['restart_tokens'] = []
        while not (control/'complete').exists():
            if (control/'failed').exists():
                raise RuntimeError('Client stage failed')
            if time.monotonic() > deadline:
                raise TimeoutError('RDMA fixture deadline')
            request = control/'restart-request'
            if args.reclaim and request.exists():
                token = request.read_text().strip()
                if not re.fullmatch(r'[1-9][0-9]?', token):
                    raise ValueError('Invalid restart token')
                if token != restart_token:
                    command('systemctl', 'restart', 'nfs-server')
                    pathlib.Path('/proc/fs/nfsd/portlist').write_text('rdma 20049\n')
                    restart_token = token
                    evidence['restart_tokens'].append(token)
                    (control/'restart-done').write_text(token+'\n')
            time.sleep(.25)
        evidence['passed'] = True
    except Exception as exc:
        evidence['error'] = str(exc)
    finally:
        try:
            if changed:
                command('systemctl', 'stop', 'nfs-server')
                for host in ('192.0.2.20', '192.0.2.10'):
                    command('exportfs', '-u', host+':'+str(ROOT), check=False)
                for p in (CONFIG, EXPORT):
                    p.unlink(missing_ok=True)
                ROOT.rename(run/'tree')
                for service in SERVICES:
                    command('systemctl', 'start' if states[service] else 'stop', service)
                if command('exportfs', '-v'):
                    raise RuntimeError('Exports remain')
            if linked:
                command('rdma', 'link', 'delete', DEVICE)
            for name in reversed(installed):
                command('rmmod', name)
            evidence['owned_modules_removed'] = not set(installed).intersection(loaded_modules())
            evidence['rdma_device_removed'] = not pathlib.Path('/sys/class/infiniband/'+DEVICE).exists()
            evidence['after'] = interop.domain_state()
            evidence['domain_preserved'] = evidence['before'] == evidence['after']
            evidence['services_after'] = {s: command('systemctl', 'is-active', s, check=False) == 'active' for s in SERVICES}
            evidence['passed'] &= evidence['domain_preserved'] and states == evidence['services_after'] and evidence['owned_modules_removed'] and evidence['rdma_device_removed']
        except Exception as exc:
            evidence['cleanup_error'] = str(exc)
            evidence['passed'] = False
        (run/'evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
        (control/'finished').write_text(json.dumps(dict(passed=evidence['passed'], error=evidence.get('error'))))
    return 0 if evidence['passed'] else 1

if __name__ == '__main__':
    sys.exit(main())
