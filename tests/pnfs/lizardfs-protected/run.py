"""Run a native protected-pNFS refusal probe; never claims successful DS I/O."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
IMAGE = 'nfs-viewer-pnfs10-lizard-final'


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, encoding='utf-8', **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--nfs-port', type=int, default=19592)
    parser.add_argument('--kdc-port', type=int, default=19588)
    args = parser.parse_args()
    if sys.platform != 'win32':
        raise SystemExit('this runner performs native Windows plus container Linux tests')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = 'nfs-pnfs-gss-boundary-' + uuid.uuid4().hex[:12]
    env = {k: v for k, v in os.environ.items() if not k.startswith(('NFS_', 'KRB5_'))}
    results = []
    with tempfile.TemporaryDirectory(prefix='nfs-pnfs-gss-boundary-') as directory:
        private = Path(directory)
        for target in ('windows', 'linux'):
            binary = private / ('test.exe' if target == 'windows' else 'test-linux')
            subprocess.run(['go', 'test', '-c', '-o', str(binary), './internal/nfs'], cwd=ROOT,
                           env={**env, 'GOOS': target, 'GOARCH': 'amd64', 'CGO_ENABLED': '0'}, check=True, timeout=180)
        try:
            command(['docker', 'run', '--rm', '-d', '--name', name, '--hostname', 'server.nfs.test', '--entrypoint', 'python3',
                     '--tmpfs', '/lab', '--tmpfs', '/run/nfs-test',
                     '-v', str(ROOT) + ':/work:ro',
                     '-p', f'127.0.0.1:{args.nfs_port}:2049/tcp',
                     '-p', f'127.0.0.1:{args.kdc_port}:88/tcp',
                     IMAGE, '/work/tests/pnfs/lizardfs-protected/start.py'])
            deadline = time.monotonic() + 50
            while time.monotonic() < deadline:
                ready = subprocess.run(['docker', 'exec', name, 'test', '-f', '/run/nfs-test/ready'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError('native MDS/KDC readiness timeout')
            # Docker cp does not expose this daemon's tmpfs contents. Transfer
            # the test-only key directly to a private file, never a text log.
            with (private / 'client.keytab').open('wb') as key:
                subprocess.run(['docker', 'exec', name, 'cat', '/run/nfs-test/client.keytab'], stdout=key, check=True)
            command(['docker', 'cp', str(private / 'test-linux'), name + ':/tmp/test-linux'])
            command(['docker', 'exec', name, 'chmod', '700', '/tmp/test-linux'])
            conf = (ROOT / 'tests/kerberos/krb5.conf').read_text(encoding='utf-8').replace('127.0.0.1:88', f'127.0.0.1:{args.kdc_port}')
            (private / 'krb5.conf').write_text(conf, encoding='utf-8')
            for target in ('windows', 'linux'):
                values = dict(NFS_VIEWER_PNFS_GSS_NATIVE_BOUNDARY='1',
                              NFS_VIEWER_PNFS_GSS_NATIVE_PORT=str(args.nfs_port) if target == 'windows' else '2049',
                              NFS_VIEWER_PNFS_GSS_NATIVE_CONFIG=str(private / 'krb5.conf') if target == 'windows' else '/etc/krb5.conf',
                              NFS_VIEWER_PNFS_GSS_NATIVE_KEYTAB=str(private / 'client.keytab') if target == 'windows' else '/run/nfs-test/client.keytab')
                options = ['-test.run=^TestLizardProtectedPNFSNativeBoundary$', '-test.v', '-test.timeout=90s']
                if target == 'windows':
                    run = [str(private / 'test.exe'), *options]
                else:
                    run = ['docker', 'exec']
                    for key, value in values.items():
                        run += ['-e', key + '=' + value]
                    run += [name, '/tmp/test-linux', *options]
                with (output / (target + '-native.log')).open('w', encoding='utf-8') as log:
                    result = subprocess.run(run, env={**env, **values}, stdout=log, stderr=subprocess.STDOUT, timeout=100)
                results.append(dict(target=target, exit_code=result.returncode))
                print(json.dumps(results[-1]), flush=True)
                if result.returncode:
                    raise RuntimeError('native boundary test failed; inspect ' + target + '-native.log')
            server_log = command(['docker', 'exec', name, 'python3', '-c',
                                  "from pathlib import Path; print('\\n'.join(s for s in Path('/lab/ganesha.log').read_text().splitlines() if 'No working auth in sec_params' in s or 'can not create back channel' in s))"])
            (output / 'server-boundary.log').write_text(server_log + '\n', encoding='utf-8')
            if server_log.count('No working auth in sec_params') != 8:
                raise RuntimeError('native server did not independently confirm all eight GSS backchannel refusals')
            capabilities = command(['docker', 'exec', name, 'sh', '-c',
                                    'grep "^USE_GSS:" /build/CMakeCache.txt; sha256sum /usr/lib/libganesha_nfsd.so.4.3 /usr/lib/ganesha/libfsallizardfs.so; sed -n "770,776p" /source/nfs-ganesha-4.3/src/MainNFSD/nfs_rpc_callback.c'])
            (output / 'native-capabilities.txt').write_text(capabilities + '\n', encoding='utf-8')
        finally:
            failed = sys.exc_info()[0] is not None
            try:
                result = subprocess.run(['docker', 'stop', '--time', '3', name],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                if result.returncode:
                    exists = subprocess.run(['docker', 'inspect', name], stdout=subprocess.DEVNULL,
                                            stderr=subprocess.PIPE, text=True, timeout=10)
                    if exists.returncode == 0 or not any(message in exists.stderr for message in ('No such object', 'No such container')):
                        raise RuntimeError('owned native fixture cleanup could not be confirmed')
            except (OSError, subprocess.SubprocessError, RuntimeError) as error:
                if not failed:
                    raise
                print('Fixture cleanup failed: ' + type(error).__name__, file=sys.stderr)


if __name__ == '__main__':
    main()
