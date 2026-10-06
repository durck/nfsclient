#!/usr/bin/env python3
"""Run only inside the existing domain-enrolled, isolated Linux lab guest.

Consumes the manually provisioned interop keytabs without changing AD accounts,
machine credentials, SSSD, NSS or the domain reservation. The explicit Windows
lane stages only ordinary-user credentials for the pinned private lab bridge.
"""
import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time

KEYS = pathlib.Path('/var/lib/nfs-viewer-msad/kerberos-interop')
ROOT = pathlib.Path('/srv/nfs-viewer-msad-interop')
CONFIG = pathlib.Path('/etc/nfs.conf.d/99-nfs-viewer-msad.conf')
EXPORT = pathlib.Path('/etc/exports.d/nfs-viewer-msad.exports')
IDMAP = pathlib.Path('/etc/idmapd.conf')
SERVICES = ['nfs-server', 'nfs-mountd', 'nfs-idmapd', 'rpc-statd', 'rpcbind', 'rpcbind.socket', 'gssproxy']


def command(*args, check=True, env=None, timeout=40):
    result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr[-1500:]}')
    return result.stdout.strip()


def domain_state():
    result = {}
    for name in ('/etc/krb5.keytab', '/etc/sssd/sssd.conf', '/etc/krb5.conf', '/etc/nsswitch.conf', '/var/lib/nfs-viewer-msad/domain-joined.json'):
        p = pathlib.Path(name)
        if p.is_symlink():
            raise RuntimeError('Unexpected redirected domain path')
        a = p.stat()
        result[name] = dict(inode=a.st_ino, bytes=a.st_size, uid=a.st_uid, gid=a.st_gid, mode=a.st_mode, mtime=a.st_mtime_ns, ctime=a.st_ctime_ns)
    result['sssd_pid'] = command('systemctl', 'show', 'sssd', '-p', 'MainPID', '--value')
    return result


def run_test(binary, pattern, log, env):
    with log.open('x') as out:
        result = subprocess.run([str(binary), '-test.v', '-test.count=1', '-test.timeout=20m', '-test.run='+pattern], stdout=out, stderr=subprocess.STDOUT, env=env, timeout=1230)
    if result.returncode:
        raise RuntimeError('Test failed; inspect '+str(log))


def wait_grace():
    deadline = time.monotonic() + 125
    while pathlib.Path('/proc/fs/nfsd/v4_end_grace').read_text().strip() != 'Y':
        if time.monotonic() >= deadline:
            raise TimeoutError('NFSv4 grace period did not end')
        time.sleep(0.25)


def run_restart_test(run, env):
    control = run/'restart-control'
    control.mkdir(mode=0o700)
    with (run/'restart.log').open('x') as log:
        process = subprocess.Popen([str(run/'cli.test'), '-test.v', '-test.count=1', '-test.timeout=4m', '-test.run=^TestMicrosoftADNFSServerRestart$'], stdout=log, stderr=subprocess.STDOUT, env=dict(env, NFS_VIEWER_MSAD_RESTART_CONTROL=str(control)))
        try:
            deadline = time.monotonic() + 220
            restarted = False
            while process.poll() is None:
                if time.monotonic() > deadline:
                    raise TimeoutError('Server restart test timed out')
                if not restarted and (control/'request').is_file():
                    command('systemctl', 'restart', 'nfs-server')
                    wait_grace()
                    run_test(run/'cli.test', '^TestMicrosoftADNFSLockReadiness$', run/'lock-readiness-restart.log', dict(env, NFS_VIEWER_MSAD_LOCK_READINESS='1'))
                    (control/'done').write_text('server restarted and grace ended\n')
                    restarted = True
                time.sleep(0.25)
            if process.returncode or not restarted:
                raise RuntimeError('Server restart test failed')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)


def run_reclaim_tests(run, env, evidence):
    """Restart during grace; never wait it out before the client's reclaim."""
    control = run/'reclaim-control'
    control.mkdir(mode=0o700)
    reclaim_env = dict(env, NFS_RECLAIM_HOST=env['NFS_VIEWER_MSAD_NFS_HOST'], NFS_RECLAIM_CONTROL=str(control), NFS_RECLAIM_CREDENTIALS=env['NFS_VIEWER_MSAD_NFS_CREDENTIALS'], NFS_VIEWER_TEST_BINARY=str(run/'nfs-viewer-linux-amd64'))
    with (run/'reclaim.log').open('x') as log:
        process = subprocess.Popen([str(run/'cli.test'), '-test.v', '-test.count=1', '-test.timeout=8m', '-test.failfast', '-test.run=^TestKernelReclaim'], stdout=log, stderr=subprocess.STDOUT, env=reclaim_env)
        tokens = []
        try:
            deadline = time.monotonic()+500
            last = ''
            while process.poll() is None:
                if time.monotonic() > deadline:
                    raise TimeoutError('Reclaim client deadline')
                request = control/'restart-request'
                if request.exists():
                    token = request.read_text().strip()
                    if token and token not in list('123456'):
                        raise ValueError('Invalid reclaim token')
                    if token and token != last:
                        command('systemctl', 'restart', 'nfs-server')
                        (control/'restart-done').write_text(token+'\n')
                        tokens.append(token)
                        last = token
                time.sleep(.1)
            if process.returncode or tokens != list('123456'):
                raise RuntimeError('Reclaim tests failed; inspect reclaim.log')
            evidence['reclaim_restart_tokens'] = tokens
            evidence['reclaim_passed'] = True
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)


def windows_client(run, artifacts, creds, env, evidence):
    """Coordinate the dedicated Windows guest; never expose a general runner."""
    control = run/'windows-control'
    control.mkdir(mode=0o700)
    staged = artifacts/'windows-credentials'
    staged.mkdir(mode=0o700)
    try:
        for name in ('krb5.conf', 'nv-alice.keytab', 'nv-bob.keytab', 'nv-alice.ccache', 'nv-bob.ccache'):
            command('install', '-m', '600', '-o', 'labadmin', '-g', 'labadmin', str(creds/name), str(staged/name))
        command('chown', 'labadmin:labadmin', str(staged))
        (control/'ready').write_text('ready\n')
        deadline = time.monotonic() + 1800
        restarted = False
        large_restarted = False
        while not (control/'complete').exists():
            if (control/'failed').exists() or (artifacts/'windows-abort').exists():
                raise RuntimeError('Windows client failed; inspect its retained logs')
            if time.monotonic() >= deadline:
                raise TimeoutError('Windows client exceeded fixture deadline')
            if (control/'restart-request').exists() and not restarted:
                command('systemctl', 'restart', 'nfs-server')
                wait_grace()
                run_test(run/'cli.test', '^TestMicrosoftADNFSLockReadiness$', run/'lock-readiness-restart.log', dict(env, NFS_VIEWER_MSAD_LOCK_READINESS='1'))
                (control/'restart-done').write_text('restarted\n')
                restarted = True
            if (control/'large-request').exists() and not large_restarted:
                command('systemctl', 'restart', 'nfs-server')
                wait_grace()
                run_test(run/'cli.test', '^TestMicrosoftADNFSLockReadiness$', run/'lock-readiness-large-restart.log', dict(env, NFS_VIEWER_MSAD_LOCK_READINESS='1'))
                (control/'large-done').write_text('restarted\n')
                large_restarted = True
            time.sleep(0.25)
        if not restarted:
            raise RuntimeError('Windows client did not exercise server restart')
        for name in ('nfs.log', 'restart.log', 'windows-client.json', 'release.log'):
            shutil.copyfile(artifacts/name, run/name)
        client = json.loads((run/'windows-client.json').read_text(encoding='utf-8-sig'))
        if client.get('passed') is not True or client.get('credentials_removed') is not True or client.get('os') != 'windows':
            raise RuntimeError('Windows client report is incomplete')
        for name in ('nfs.log', 'restart.log'):
            log = (run/name).read_text(encoding='utf-8-sig')
            if not log.rstrip().endswith('PASS') or '--- FAIL:' in log or '--- SKIP:' in log or 'MSAD_CLIENT os=windows arch=amd64 host=192.0.2.20' not in log:
                raise RuntimeError('Windows client test log is incomplete: '+name)
        evidence['windows_client'] = client
        if client.get('large'):
            if not large_restarted or client['large'].get('passed') is not True:
                raise RuntimeError('Large transfer did not complete a real restart')
            for name in ('large.log', 'large.json'):
                shutil.copyfile(artifacts/name, run/name)
            evidence['large_restart_passed'] = True
    finally:
        for p in staged.iterdir():
            p.unlink()
        staged.rmdir()
        evidence['staged_credentials_removed'] = not staged.exists()


def windows_reclaim_client(run, artifacts, creds, evidence):
    control = run/'windows-control'
    control.mkdir(mode=0o700)
    staged = artifacts/'windows-credentials'
    staged.mkdir(mode=0o700)
    tokens = []
    try:
        for name in ('krb5.conf', 'nv-alice.keytab'):
            command('install', '-m', '600', '-o', 'labadmin', '-g', 'labadmin', str(creds/name), str(staged/name))
        command('chown', 'labadmin:labadmin', str(staged))
        (control/'ready').write_text('ready\n')
        deadline = time.monotonic()+600
        last = ''
        while not (control/'complete').exists():
            if (artifacts/'windows-abort').exists():
                raise RuntimeError('Windows reclaim aborted')
            if time.monotonic() > deadline:
                raise TimeoutError('Windows reclaim deadline')
            request = control/'restart-request'
            if request.exists():
                token = request.read_text().strip()
                if token and token not in list('123456'):
                    raise ValueError('Invalid Windows reclaim token')
                if token and token != last:
                    command('systemctl', 'restart', 'nfs-server')
                    (control/'restart-done').write_text(token+'\n')
                    tokens.append(token)
                    last = token
            time.sleep(.1)
        if tokens != list('123456'):
            raise RuntimeError('Incomplete Windows restart matrix')
        for name in ('reclaim.log', 'windows-client.json'):
            shutil.copyfile(artifacts/name, run/name)
        client = json.loads((run/'windows-client.json').read_text(encoding='utf-8-sig'))
        if not client.get('passed') or not client.get('credentials_removed') or not client.get('acl_protected'):
            raise RuntimeError('Windows reclaim report or credential cleanup failed')
        evidence['windows_client'] = client
        evidence['reclaim_restart_tokens'] = tokens
        evidence['reclaim_passed'] = True
    finally:
        for p in staged.iterdir():
            p.unlink()
        staged.rmdir()
        evidence['staged_credentials_removed'] = not staged.exists()


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] not in ('--windows-client', '--reclaim', '--reclaim-windows')) or not sys.argv[1].startswith('interop-') or not all(c.isalnum() or c == '-' for c in sys.argv[1]):
        raise ValueError('A fresh interop-RUN-ID is required')
    windows = len(sys.argv) == 3 and sys.argv[2] in ('--windows-client', '--reclaim-windows')
    reclaim = len(sys.argv) == 3 and sys.argv[2] in ('--reclaim', '--reclaim-windows')
    host = '192.0.2.20' if windows else '127.0.0.1'
    clients = ['192.0.2.10', '192.0.2.20'] if windows else ['127.0.0.1']
    if os.geteuid() != 0 or socket.gethostname() != 'nfs':
        raise ValueError('Dedicated Linux guest/root only')
    if command('ip', '-4', 'route', 'show', 'default') or command('ip', '-6', 'route', 'show', 'default'):
        raise ValueError('Guest must have no default route')
    addresses = json.loads(command('ip', '-j', '-4', 'addr'))
    ips = [a['local'] for dev in addresses for a in dev.get('addr_info', []) if a.get('scope') == 'global']
    if ips != ['192.0.2.20']:
        raise ValueError('Guest is not on the expected private network')
    for user, uid, groups in [('nv-alice', '25001', {'25000', '25003'}), ('nv-bob', '25002', {'25000'})]:
        if command('id', '-u', user) != uid or set(command('id', '-G', user).split()) != groups:
            raise ValueError('Unexpected domain identity: '+user)
    if command('systemctl', 'is-active', 'sssd') != 'active' or command('exportfs', '-v'):
        raise ValueError('SSSD must be active and all exports absent')
    if command('systemctl', 'is-active', 'nfs-server', check=False) == 'active':
        raise ValueError('An NFS server already owns this guest')
    if not (KEYS/'nfs.keytab').is_file():
        raise ValueError('Manual interop service keys are missing; do not reprovision')
    mask = pathlib.Path('/run/systemd/system/gssproxy.service')
    for p in (ROOT, CONFIG, EXPORT, mask):
        if p.exists() or p.is_symlink():
            raise ValueError('Refusing existing fixture path: '+str(p))
    before = domain_state()
    states = {s: command('systemctl', 'is-active', s, check=False) == 'active' for s in SERVICES}
    run = pathlib.Path('/var/lib/nfs-viewer-msad/runs') / sys.argv[1]
    run.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence = {'run': sys.argv[1], 'before': before, 'services_before': states, 'passed': False, 'nfs_client_platform': 'windows' if windows else 'linux'}
    proxy = None
    changed = False
    if IDMAP.is_symlink() or not IDMAP.is_file():
        raise ValueError('Expected an ordinary idmapd configuration file')
    backup = IDMAP.read_bytes()
    evidence['idmap_before_sha256'] = hashlib.sha256(backup).hexdigest()
    mode = IDMAP.stat().st_mode & 0o777
    try:
        creds = run/'credentials'
        creds.mkdir(mode=0o700)
        for name in ('krb5.conf', 'nv-alice.keytab', 'nv-bob.keytab', 'nfs.keytab'):
            (creds/name).symlink_to(KEYS/name)
        env = dict(os.environ, KRB5_CONFIG=str(creds/'krb5.conf'), LC_ALL='C')
        # Use the synchronized guest clock for native acquisition. MIT's default
        # kdc_timesync can persist even a sub-second correction; the application
        # deliberately rejects FILE caches requiring that unsupported correction.
        # This affects only these kinit processes, not SSSD or the domain config.
        kinit_config = creds/'kinit.conf'
        kinit_config.write_text('[libdefaults]\n kdc_timesync = 0\n')
        evidence['native_cache_clock_policy'] = 'system clock; kdc_timesync=0 for kinit only'
        for user in ('nv-alice', 'nv-bob'):
            command('kinit', '-k', '-t', str(creds/(user+'.keytab')), user+'@MSAD.NFS.TEST', env=dict(env, KRB5_CONFIG=str(kinit_config)+os.pathsep+env['KRB5_CONFIG'], KRB5CCNAME='FILE:'+str(creds/(user+'.ccache'))))
        # Let freshly issued second-granularity start times become valid.
        time.sleep(2)
        artifacts = pathlib.Path(__file__).resolve().parent
        binary_names = ['krb.test', 'cli.test']
        if reclaim and not windows:
            binary_names += ['nfs-viewer-linux-amd64']
        if windows:
            binary_names += ['cli-windows.test.exe', 'nfs-viewer-windows-amd64.exe']
        for name in binary_names:
            shutil.copyfile(artifacts/name, run/name)
            (run/name).chmod(0o700)
        evidence['artifacts'] = {n: hashlib.sha256((run/n).read_bytes()).hexdigest() for n in binary_names}
        krbenv = dict(env, NFS_VIEWER_MSAD_KRBCLIENT='1', NFS_VIEWER_MSAD_PROFILE='interop', NFS_VIEWER_MSAD_KRB5_CONFIG=str(creds/'krb5.conf'), NFS_VIEWER_MSAD_KRB5_SERVICE_KEYTAB=str(creds/'nfs.keytab'))
        for alias in ('ALICE', 'BOB'):
            for source in ('KEYTAB', 'CCACHE'):
                krbenv['NFS_VIEWER_MSAD_KRB5_'+alias+'_'+source] = str(creds/('nv-'+alias.lower()+'.'+source.lower()))
        run_test(run/'krb.test', '^TestMicrosoftADKerberosClient$', run/'kerberos.log', krbenv)
        evidence['ordinary_user_kerberos_passed'] = True
        # The rest of this lane owns only these temporary service/config paths.
        changed = True
        ROOT.mkdir(mode=0o755)
        (ROOT/'data').mkdir(mode=0o777)
        (ROOT/'data').chmod(0o1777)
        seed = ROOT/'readers.txt'
        seed.write_text('domain-reader-seed\n')
        os.chown(seed, 0, 25003)
        seed.chmod(0o640)
        CONFIG.write_text(f'[nfsd]\nhost={host}\nport=2049\nthreads=8\nvers3=y\nvers4=y\nvers4.0=y\nvers4.1=y\nvers4.2=y\nudp=y\ntcp=y\n[mountd]\nport=20048\nmanage-gids=y\n')
        if reclaim:
            CONFIG.write_text(CONFIG.read_text().replace('[nfsd]\n', '[nfsd]\ngrace-time=10\nlease-time=30\n'))
        EXPORT.write_text(str(ROOT)+' '+ ' '.join(c+'(rw,fsid=0,insecure,root_squash,no_subtree_check,sec=krb5:krb5i:krb5p,sync)' for c in clients)+'\n')
        IDMAP.write_text('[General]\nDomain = msad.nfs.test\nLocal-Realms = MSAD.NFS.TEST\n[Mapping]\nNobody-User = nobody\nNobody-Group = nogroup\n[Translation]\nMethod = nsswitch\nGSS-Methods = nsswitch\n')
        command('systemctl', 'stop', 'gssproxy')
        if command('pgrep', '-x', 'gssproxy', check=False):
            raise RuntimeError('Unexpected remaining gssproxy process')
        command('systemctl', 'mask', '--runtime', 'gssproxy')
        command('systemctl', 'start', 'proc-fs-nfsd.mount')
        command('modprobe', 'rpcsec_gss_krb5')
        cfg = run/'gssproxy.conf'
        cfg.write_text(f'[gssproxy]\ndebug=false\n[service/nfs-viewer-msad]\nmechs=krb5\nsocket=/run/gssproxy.sock\ncred_store=keytab:{KEYS}/nfs.keytab\ncred_usage=accept\nkrb5_principal=nfs/nfs-interop.msad.nfs.test@MSAD.NFS.TEST\ntrusted=yes\nkernel_nfsd=yes\neuid=0\nallow_any_uid=no\nallow_protocol_transition=no\nallow_constrained_delegation=no\nimpersonate=no\n')
        with (run/'gssproxy.log').open('x') as log:
            proxy = subprocess.Popen(['gssproxy', '-i', '-c', str(cfg), '-s', str(run/'default.sock')], stdout=log, stderr=subprocess.STDOUT, env=env)
        time.sleep(1)
        if proxy.poll() is not None:
            raise RuntimeError('Fixture gssproxy exited')
        if pathlib.Path('/proc/net/rpc/use-gss-proxy').read_text().strip() != '1':
            raise RuntimeError('Kernel has not registered the fixture GSS proxy')
        command('systemctl', 'start', 'nfs-server')
        command('exportfs', '-ra')

        wait_grace()
        evidence['exports'] = command('exportfs', '-v')
        evidence['listeners'] = command('ss', '-H', '-lntu')
        nfslisteners = [line.split()[4] for line in evidence['listeners'].splitlines() if line.split()[4].rsplit(':', 1)[-1] == '2049']
        if not nfslisteners or any(addr != host+':2049' for addr in nfslisteners):
            raise RuntimeError('NFS listener differs from the selected isolated fixture host')
        nfsenv = dict(env, NFS_VIEWER_MSAD_NFS='1', NFS_VIEWER_MSAD_NFS_CREDENTIALS=str(creds), NFS_VIEWER_MSAD_NFS_HOST=host)
        run_test(run/'cli.test', '^TestMicrosoftADNFSLockReadiness$', run/'lock-readiness.log', dict(nfsenv, NFS_VIEWER_MSAD_LOCK_READINESS='1'))
        if reclaim and windows:
            windows_reclaim_client(run, artifacts, creds, evidence)
        elif reclaim:
            run_reclaim_tests(run, nfsenv, evidence)
        elif windows:
            windows_client(run, artifacts, creds, nfsenv, evidence)
        else:
            run_test(run/'cli.test', '^TestMicrosoftADNFS(Locks)?$', run/'nfs.log', nfsenv)
            run_restart_test(run, nfsenv)
        evidence['nfs_passed'] = True
        evidence['server_restart_passed'] = True
        evidence['objects'] = {str(p.relative_to(ROOT)): dict(uid=p.stat().st_uid, gid=p.stat().st_gid, bytes=p.stat().st_size, mode=oct(p.stat().st_mode & 0o7777)) for p in (ROOT/'data').iterdir()}
        evidence['passed'] = True
    except Exception as exc:
        evidence['error'] = str(exc)
    finally:
        try:
            if changed:
                command('systemctl', 'stop', 'nfs-server')
                for client in clients:
                    command('exportfs', '-u', client+':'+str(ROOT), check=False)
                if proxy is not None:
                    proxy.terminate()
                    proxy.wait(timeout=15)
                for p in (CONFIG, EXPORT):
                    p.unlink(missing_ok=True)
                IDMAP.write_bytes(backup)
                IDMAP.chmod(mode)
                if mask.is_symlink() and os.readlink(mask) == '/dev/null':
                    command('systemctl', 'unmask', '--runtime', 'gssproxy')
                for service in SERVICES:
                    command('systemctl', 'start' if states[service] else 'stop', service)
                if command('exportfs', '-v'):
                    raise RuntimeError('Exports remain after cleanup')
                # Keep the bounded test files for independent ownership review,
                # outside the export pathname so a fresh invocation can proceed.
                if ROOT.is_dir() and not ROOT.is_symlink():
                    ROOT.rename(run/'tree')
            evidence['after'] = domain_state()
            evidence['services_after'] = {s: command('systemctl', 'is-active', s, check=False) == 'active' for s in SERVICES}
            evidence['idmap_after_sha256'] = hashlib.sha256(IDMAP.read_bytes()).hexdigest()
            if evidence['services_after'] != states or evidence['idmap_after_sha256'] != evidence['idmap_before_sha256']:
                evidence['passed'] = False
            evidence['domain_preserved'] = before == evidence['after']
            if not evidence['domain_preserved']:
                evidence['passed'] = False
        except Exception as exc:
            evidence['cleanup_error'] = str(exc)
            evidence['passed'] = False
        (run/'evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
    print(json.dumps({'run': str(run), 'passed': evidence['passed'], 'error': evidence.get('error'), 'cleanup_error': evidence.get('cleanup_error')}))
    return 0 if evidence['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
