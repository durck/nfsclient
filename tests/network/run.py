"""Run native UDP/port checks in one disposable UNFS3 network namespace."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]


def command(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, text=True, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=('windows', 'linux', 'both'), default=platform.system().lower())
    parser.add_argument('--nfs-port', type=int, default=19449)
    parser.add_argument('--mount-port', type=int, default=19448)
    parser.add_argument('--control-port', type=int, default=19477)
    parser.add_argument('--windows-tcp-exhausted', action='store_true',
                        help='Require refusal of an independently inventoried occupied 900-1023 TCP range')
    args = parser.parse_args()
    ports = (args.nfs_port, args.mount_port, args.control_port)
    if len(set(ports)) != 3 or any(p < 1024 or p > 65535 for p in ports):
        parser.error('three distinct unprivileged host ports are required')
    if args.target in ('windows', 'both') and platform.system() != 'Windows':
        parser.error('Windows execution requires Windows host')
    output = ROOT / 'bin/verification/network'
    output.mkdir(parents=True, exist_ok=True)
    name = 'nfs-network-' + uuid.uuid4().hex[:12]
    launch = ['docker', 'run', '-d', '--rm', '--name', name, '--cap-add', 'NET_ADMIN']
    for path in ('data', 'squashed', 'readonly', 'secure'):
        launch += ['--tmpfs', '/' + path]
    for host, guest in ((args.nfs_port, 2049), (args.mount_port, 20048)):
        for transport in ('tcp', 'udp'):
            launch += ['-p', f'127.0.0.1:{host}:{guest}/{transport}']
    launch += ['-p', f'127.0.0.1:{args.control_port}:19877', 'nfs-viewer-network-test']
    command(launch)
    results = []
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(50):
            try:
                with opener.open(f'http://127.0.0.1:{args.control_port}/status', timeout=1) as response:
                    json.load(response)
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError('network fixture did not become ready')
        server = json.loads(command(['docker', 'inspect', name]))[0]
        address = server['NetworkSettings']['Networks']['bridge']['IPAddress']
        env = {k: v for k, v in os.environ.items() if not k.startswith(('NFS_', 'KRB5_'))}
        pattern = '^(TestNativeUDPNetwork|TestNativeReservedSourcePorts|TestWindowsReservedPortCollision)$'
        for target in (('windows', 'linux') if args.target == 'both' else (args.target,)):
            values = dict(NFS_VIEWER_NETWORK_NATIVE='1',
                          NFS_VIEWER_NETWORK_HOST='127.0.0.1' if target == 'windows' else address,
                          NFS_VIEWER_NETWORK_PORT=str(args.nfs_port) if target == 'windows' else '2049',
                          NFS_VIEWER_NETWORK_MOUNT_PORT=str(args.mount_port) if target == 'windows' else '20048',
                          NFS_VIEWER_NETWORK_CONTROL=str(args.control_port) if target == 'windows' else '19877')
            test = ['go', 'test', '-race', '-count=1', './internal/nfs', '-run', pattern, '-v']
            if target == 'windows':
                if args.windows_tcp_exhausted:
                    values['NFS_VIEWER_NETWORK_TCP_EXHAUSTED'] = '1'
                run = test
            else:
                cache = command(['go', 'env', 'GOMODCACHE'], env=env)
                run = ['docker', 'run', '--rm', '--name', name + '-client',
                       '-v', str(ROOT) + ':/work:ro', '-v', cache + ':/go/pkg/mod:ro',
                       '-v', 'nfs-viewer-go-build:/root/.cache/go-build', '-w', '/work']
                for key, value in values.items():
                    run += ['-e', key + '=' + value]
                run += ['golang:1.26.8', *test]
            log = output / (target + '-native.log')
            with log.open('w', encoding='utf-8') as stream:
                result = subprocess.run(run, cwd=ROOT, env={**env, **values}, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=600)
            results.append(dict(target=target, exit_code=result.returncode, log=log.name))
            print(json.dumps(results[-1]), flush=True)
            if result.returncode:
                raise RuntimeError('native network test failed; inspect ' + str(log))
        audit = command(['docker', 'exec', name, 'python3', '-c',
                         "import pathlib,hashlib,json; print(json.dumps([dict(name=p.name,size=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in pathlib.Path('/data').iterdir() if p.is_file() and p.name.startswith(('network-','firewall-','mtu-write-'))],indent=2))"])
        (output / 'native-files.json').write_text(audit + '\n', encoding='utf-8')
        files = json.loads(audit)
        for item in files:
            if item['name'].startswith('network-'):
                expected = b'native-fragmentation-' * 901
            elif item['name'].startswith('firewall-'):
                expected = b'one native write' if '-true-' in item['name'] else b''
            else:
                expected = b'MTU' * 700 if item['size'] else b''
            if item['size'] != len(expected) or item['sha256'] != hashlib.sha256(expected).hexdigest():
                raise RuntimeError('independent native byte audit failed: ' + item['name'])
        if len(files) != len(results)*9:
            raise RuntimeError('native audit has missing or unexpected files')
        (output / 'summary.json').write_text(json.dumps(dict(results=results,
            image=server['Image'], windows_tcp_exhausted=args.windows_tcp_exhausted,
            native_files_verified=len(files),
            scope='UNFS3 AUTH_SYS; packet-observed NFS UDP egress fragmentation; container-only reply firewall'), indent=2)+'\n', encoding='utf-8')
    finally:
        failed = sys.exc_info()[0] is not None
        cleanup_errors = []
        # Killing a timed-out docker CLI does not stop its container. Stop the
        # independently named client first, then the server; --rm removes both.
        for owned in (name + '-client', name):
            try:
                stopped = subprocess.run(['docker', 'stop', '--time', '3', owned],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                if stopped.returncode:
                    exists = subprocess.run(['docker', 'inspect', owned],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=10)
                    if exists.returncode == 0 or not any(message in exists.stderr for message in ('No such object', 'No such container')):
                        cleanup_errors.append(owned)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(owned + ': ' + type(error).__name__)
        if cleanup_errors:
            message = 'Network fixture cleanup incomplete: ' + ', '.join(cleanup_errors)
            if failed:
                print(message, file=sys.stderr)
            else:
                raise RuntimeError(message)


if __name__ == '__main__':
    main()
