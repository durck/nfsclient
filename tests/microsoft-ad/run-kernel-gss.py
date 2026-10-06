#!/usr/bin/python3
"""Isolated MIT KDC and kernel NFSv4 GSS ACL check; credentials stay in guest tmpfs."""
import grp
import hashlib
import importlib.util
import json
import os
import pathlib
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import traceback

spec = importlib.util.spec_from_file_location('kernel_base', pathlib.Path(__file__).with_name('run-kernel-nfs.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
command = base.command
SECRET = pathlib.Path('/run/nfs-viewer-kernel-gss')
IDMAP = pathlib.Path('/etc/idmapd.conf')
REALM = 'NFS.TEST'
SPN = 'nfs/server.nfs.test@' + REALM
PROCESSES = []
CREATED_USERS = []
CREATED_GROUPS = []
IDMAP_BACKUP = None
SECRET_OWNED = False
PROXY_PATHS = (pathlib.Path('/run/gssproxy.sock'), pathlib.Path('/run/gssproxy.pid'))
PROXY_OWNED = {}
PACKAGED_PROXY_OWNED = {}
PROXY_MASK = pathlib.Path('/run/systemd/system/gssproxy.service')
PROXY_MASK_OWNED = False
EXTRA_SERVICES = ['krb5-kdc.service', 'krb5-admin-server.service', 'rpc-svcgssd.service', 'rpc-gssd.service', 'gssproxy.service']
base.SERVICES.extend(EXTRA_SERVICES + ['nfs-blkmap.service'])


def ensure_packages(run_output, bundle, verifier, proxy=False):
    profile = 'kernel-gssproxy' if proxy else 'kernel-gss'
    result = {'authentication': command('python3', str(verifier), 'check', str(bundle), '--profile', profile, timeout=100)}
    state = run_output / 'gss-apt'
    (state / 'lists/partial').mkdir(parents=True)
    (state / 'archives/partial').mkdir(parents=True)
    (state / 'sources.list').write_text('deb [trusted=yes] file:' + str(bundle) + ' ./\n')
    options = ['apt-get', '-o', 'Dir::Etc::sourcelist=' + str(state / 'sources.list'),
               '-o', 'Dir::Etc::sourceparts=-', '-o', 'Dir::State::lists=' + str(state / 'lists'),
               '-o', 'Dir::Cache::archives=' + str(state / 'archives'), '-o', 'Acquire::Languages=none']
    policy = pathlib.Path('/usr/sbin/policy-rc.d')
    if policy.exists():
        raise ValueError('Refusing an existing guest package service policy')
    policy.write_text('#!/bin/sh\nexit 101\n')
    policy.chmod(0o755)
    try:
        result['update'] = command(*options, 'update')
        targets = ['krb5-kdc', 'krb5-admin-server', 'acl', 'nfs-kernel-server', 'krb5-user']
        if proxy:
            targets.append('gssproxy')
        result['simulation'] = command(*options, '--no-install-recommends', '--no-remove', '-s', 'install', *targets)
        result['installation'] = command('env', 'DEBIAN_FRONTEND=noninteractive', *options, '-y', '--no-install-recommends', '--no-remove', 'install', *targets, timeout=180)
        result['dependency_check'] = command(*options, 'check')
        result['audit'] = command('dpkg', '--audit')
        if result['audit']:
            raise ValueError('Unfinished offline package transaction')
        result['versions'] = command('dpkg-query', '-W', '-f=${Package}\t${Version}\t${db:Status-Status}\n', *targets)
    finally:
        policy.unlink()
    return result


def local_identities(groups=False):
    for name, gid in (('alice', 20001), ('bob', 20002), ('nfsshared', 20003), ('stranger', 20004)):
        try:
            existing = grp.getgrnam(name)
        except KeyError:
            existing = None
        if existing:
            if existing.gr_gid != gid:
                raise ValueError('Conflicting existing local group: ' + name)
        else:
            try:
                grp.getgrgid(gid)
            except KeyError:
                command('groupadd', '--gid', str(gid), name)
                CREATED_GROUPS.append(name)
            else:
                raise ValueError('Numeric fixture GID belongs to another group')
    for name, uid in (('alice', 20001), ('bob', 20002), ('stranger', 20004)):
        try:
            existing = pwd.getpwnam(name)
        except KeyError:
            existing = None
        if existing:
            if existing.pw_uid != uid or existing.pw_gid != uid:
                raise ValueError('Conflicting existing local user: ' + name)
        else:
            try:
                pwd.getpwuid(uid)
            except KeyError:
                command('useradd', '--uid', str(uid), '--gid', str(uid), '--no-create-home', '--no-user-group', '--shell', '/usr/sbin/nologin', name)
                CREATED_USERS.append(name)
            else:
                raise ValueError('Numeric fixture UID belongs to another user')
    if groups:
        if 'alice' not in CREATED_USERS:
            raise ValueError('Supplementary membership requires a newly owned Alice account')
        command('usermod', '--append', '--groups', 'nfsshared', 'alice')
    for name, primary in (('alice', 20001), ('bob', 20002), ('stranger', 20004)):
        expected = {primary, 20003} if groups and name == 'alice' else {primary}
        if set(os.getgrouplist(name, primary)) != expected:
            raise ValueError('Unexpected local supplementary membership: ' + name)
    return {name: {'passwd': command('getent', 'passwd', name), 'id': command('id', name),
                   'numeric_groups': os.getgrouplist(name, pwd.getpwnam(name).pw_gid)}
            for name in ('alice', 'bob', 'stranger')}


def prepare_groups():
    root = base.ROOT / 'data/gss-groups'
    base.directory(root, 0o770, 0, 20003)
    base.file(root / 'read.txt', 'gss supplementary fixture\n', 0o640, 0, 20003)
    return command('getfacl', '--numeric', '--absolute-names', '--recursive', str(root))


def mask_proxy_unit():
    global PROXY_MASK_OWNED
    if PROXY_MASK.exists() or PROXY_MASK.is_symlink():
        raise ValueError('Refusing an existing runtime proxy unit override')
    PROXY_MASK.symlink_to('/dev/null')
    PROXY_MASK_OWNED = True
    command('systemctl', 'daemon-reload')


def start_proxy(run_output, kernel=True):
    # gssproxy unlinks sockets and overwrites its PID even in foreground mode.
    # Refuse every external path before giving the daemon ownership.
    for path in PROXY_PATHS:
        if path.exists() or path.is_symlink():
            raise ValueError('Refusing existing gssproxy runtime: ' + str(path))
    (SECRET / 'rcache').mkdir(mode=0o700)
    config = SECRET / 'gssproxy.conf'
    config.write_text(f'''[gssproxy]
debug = false
debug_level = 0
syslog_status = false
[service/nfs-viewer-kernel]
mechs = krb5
socket = /run/gssproxy.sock
cred_store = keytab:{SECRET}/server.keytab
cred_usage = accept
krb5_principal = {SPN}
trusted = yes
kernel_nfsd = {'yes' if kernel else 'no'}
euid = 0
allow_any_uid = no
allow_protocol_transition = no
allow_constrained_delegation = no
impersonate = no
''')
    process = start_owned(['gssproxy', '-i', '-c', str(config), '-s', str(SECRET / 'default.sock'), '--debug-level=0'],
                          run_output / 'gssproxy.log', dict(kerberos_environment(), KRB5RCACHEDIR=str(SECRET / 'rcache')))
    deadline = time.monotonic() + 15
    waiter = threading.Event()
    while time.monotonic() < deadline:
        for path in PROXY_PATHS:
            if path.exists() and path not in PROXY_OWNED:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
                    raise ValueError('Unexpected proxy runtime ownership')
                PROXY_OWNED[path] = (info.st_dev, info.st_ino)
        if process.poll() is not None:
            raise RuntimeError('Owned gssproxy exited; inspect retained guest log metadata')
        if len(PROXY_OWNED) == len(PROXY_PATHS) and stat.S_ISSOCK(PROXY_PATHS[0].lstat().st_mode):
            if PROXY_PATHS[1].read_text().strip() != str(process.pid):
                raise ValueError('Proxy PID file does not identify the owned process')
            if not kernel or command('cat', '/proc/net/rpc/use-gss-proxy', timeout=3) == '1':
                return process
        waiter.wait(0.1)
    raise TimeoutError('Owned proxy socket/PID/kernel registration deadline expired')


def remove_proxy_runtime():
    for path, identity in [*PACKAGED_PROXY_OWNED.items(), *PROXY_OWNED.items()]:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (info.st_dev, info.st_ino) != identity or stat.S_ISLNK(info.st_mode):
                raise ValueError('Refusing changed proxy runtime cleanup target')
            path.unlink()
    if PROXY_MASK_OWNED:
        if not PROXY_MASK.is_symlink() or os.readlink(PROXY_MASK) != '/dev/null':
            raise ValueError('Refusing changed runtime proxy unit override')
        PROXY_MASK.unlink()
        command('systemctl', 'daemon-reload')


def stop_packaged_proxy(evidence):
    """Adopt only this verified package's boot-time daemon in the empty guest."""
    hashes = {
        '/etc/gssproxy/24-nfs-server.conf': '1bf3dc8e116852054b032bdda53b48c4ac6ef2611bbce9757becb3b2f39a0887',
        '/etc/gssproxy/gssproxy.conf': 'db5af5485c3f7b5c9fc5defc097e905c8c6dedb6b05e6df9bc3ef8844a119611',
        '/usr/sbin/gssproxy': 'd55b7eb9e8706bcebe05827f494091fc02053accede531b9cbbae5f50897ec08',
        '/usr/lib/systemd/system/gssproxy.service': 'bf18e03f8bcec2d9f49b612b1327b8dd2680741f51b888f276f67dee0ee0f5b9',
    }
    if sorted(path.name for path in pathlib.Path('/etc/gssproxy').iterdir()) != ['24-nfs-server.conf', 'gssproxy.conf']:
        raise ValueError('Unexpected packaged proxy configuration inventory')
    for name, digest in hashes.items():
        path = pathlib.Path(name)
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Packaged proxy differs from authenticated Ubuntu payload: ' + name)
    properties = command('systemctl', 'show', 'gssproxy.service', '--property=Id,MainPID,ActiveState,UnitFileState,FragmentPath,DropInPaths')
    fields = dict(line.split('=', 1) for line in properties.splitlines())
    if fields.get('ActiveState') != 'active' or fields.get('UnitFileState') != 'disabled' or fields.get('FragmentPath') != '/usr/lib/systemd/system/gssproxy.service' or fields.get('DropInPaths'):
        raise ValueError('Packaged proxy unit ownership differs from the prior fixture installation')
    pid = int(fields['MainPID'])
    process = pathlib.Path('/proc') / str(pid)
    args = process.joinpath('cmdline').read_bytes().split(b'\0')
    if pid <= 1 or process.joinpath('exe').resolve() != pathlib.Path('/usr/sbin/gssproxy') or args != [b'/usr/sbin/gssproxy', b'-D', b''] or process.stat().st_uid != 0:
        raise ValueError('Packaged proxy process identity differs from its system unit')
    paths = (*PROXY_PATHS, pathlib.Path('/var/lib/gssproxy/default.sock'))
    identities = {}
    for path in paths:
        info = path.lstat()
        expected = stat.S_ISREG if path.suffix == '.pid' else stat.S_ISSOCK
        if not expected(info.st_mode) or info.st_uid != 0:
            raise ValueError('Unexpected boot proxy runtime type/ownership')
        identities[path] = (info.st_dev, info.st_ino)
    if PROXY_PATHS[1].read_text().strip() != str(pid):
        raise ValueError('Packaged proxy PID file differs from MainPID')
    selector = pathlib.Path('/proc/net/rpc/use-gss-proxy')
    proof = {'unit_before': properties, 'verified_package_sha256': hashes, 'main_pid': pid,
             'selector_before': command('cat', str(selector), timeout=3) if selector.exists() else 'absent'}
    # Only after every identity check succeeds may finally clean this service.
    PACKAGED_PROXY_OWNED.update(identities)
    evidence['cleanup_authorized'] = True
    evidence['packaged_proxy_stopped'] = proof
    command('systemctl', 'stop', 'gssproxy.service')
    if command('pgrep', '-x', 'gssproxy', check=False):
        raise ValueError('Packaged proxy process remained after its unit stopped')
    for path, identity in identities.items():
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (info.st_dev, info.st_ino) != identity or stat.S_ISLNK(info.st_mode):
                raise ValueError('Refusing changed boot proxy cleanup target')
            path.unlink()
        PACKAGED_PROXY_OWNED.pop(path)
    proof['unit_after'] = command('systemctl', 'show', 'gssproxy.service', '--property=Id,MainPID,ActiveState,UnitFileState')
    proof['runtime_removed'] = all(not path.exists() and not path.is_symlink() for path in paths)
    proof['selector_after'] = command('cat', str(selector), timeout=3) if selector.exists() else 'absent'
    if 'ActiveState=inactive' not in proof['unit_after'] or not proof['runtime_removed']:
        raise ValueError('Packaged proxy did not stop cleanly')
    return proof


def kerberos_environment():
    return dict(os.environ, KRB5_CONFIG=str(SECRET / 'krb5.conf'), KRB5_KDC_PROFILE=str(SECRET / 'kdc.conf'),
                KRB5_KTNAME=str(SECRET / 'server.keytab'), KRB5CCNAME='FILE:' + str(SECRET / 'alice.ccache'))


def kcommand(*args, timeout=30):
    completed = subprocess.run(args, env=kerberos_environment(), text=True, capture_output=True, timeout=timeout)
    if completed.returncode:
        raise RuntimeError('Kerberos command failed: ' + repr(args) + '\n' + completed.stdout + completed.stderr)
    return (completed.stdout + completed.stderr).strip()


def start_owned(args, log, environment):
    with log.open('w') as output:
        process = subprocess.Popen(args, env=environment, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    PROCESSES.append(process)
    return process


def setup_credentials(run_output):
    global SECRET_OWNED
    if SECRET.exists() or SECRET.is_symlink() or SECRET.parent.resolve() != pathlib.Path('/run'):
        raise ValueError('Refusing existing credential runtime')
    SECRET.mkdir(mode=0o700)
    SECRET_OWNED = True
    (SECRET / 'krb5.conf').write_text('''[libdefaults]
 default_realm = NFS.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
 udp_preference_limit = 1
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 NFS.TEST = {
  kdc = 127.0.0.1:10088
 }
''')
    (SECRET / 'kdc.conf').write_text(f'''[kdcdefaults]
 kdc_listen = 127.0.0.1:10088
 kdc_tcp_listen = 127.0.0.1:10088
[realms]
 NFS.TEST = {{
  database_name = {SECRET}/principal
  key_stash_file = {SECRET}/stash
  acl_file = {SECRET}/kadm5.acl
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  default_principal_flags = +preauth
  max_life = 2h
  disable_pac = true
 }}
''')
    (SECRET / 'kadm5.acl').write_text('')
    master = secrets.token_urlsafe(40)
    creation = subprocess.run(['kdb5_util', '-r', REALM, 'create', '-s'], env=kerberos_environment(),
                              input=master + '\n' + master + '\n', text=True, capture_output=True, timeout=30)
    if creation.returncode:
        raise RuntimeError('Dedicated KDC database creation failed')
    del master
    for principal, filename in [(name + '@' + REALM, name + '.keytab') for name in ('alice', 'bob', 'stranger')] + [(SPN, 'server.keytab')]:
        kcommand('kadmin.local', '-r', REALM, '-q', 'addprinc -randkey ' + principal)
        kcommand('kadmin.local', '-r', REALM, '-q', 'ktadd -norandkey -k ' + str(SECRET / filename) + ' ' + principal)
        (SECRET / filename).chmod(0o600)
    process = start_owned(['krb5kdc', '-n', '-r', REALM, '-P', str(SECRET / 'kdc.pid')], run_output / 'kdc.log', kerberos_environment())
    deadline = time.monotonic() + 15
    waiter = threading.Event()
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Dedicated KDC exited; inspect retained guest kdc.log')
        result = subprocess.run(['kinit', '-k', '-t', str(SECRET / 'alice.keytab'), 'alice@' + REALM], env=kerberos_environment(), capture_output=True, timeout=5)
        if result.returncode == 0:
            break
        waiter.wait(0.2)
    else:
        raise TimeoutError('KDC did not issue an Alice TGT within deadline')
    service_ticket = kcommand('kvno', '-k', str(SECRET / 'server.keytab'), SPN)
    return {'realm': REALM, 'service_principal': SPN, 'pac_disabled': True,
            'service_ticket_decrypted_with_server_keytab': service_ticket,
            'cache_metadata': kcommand('klist', '-e'),
            'keytab_metadata': {name: kcommand('klist', '-k', '-e', str(SECRET / (name + '.keytab'))) for name in ('alice', 'bob', 'stranger', 'server')},
            'permissions': {path.name: oct(path.stat().st_mode & 0o777) for path in SECRET.iterdir() if path.is_file()}}


def configure_idmap():
    global IDMAP_BACKUP
    if IDMAP.is_symlink() or not IDMAP.is_file():
        raise ValueError('Expected an ordinary existing guest idmap configuration')
    original = IDMAP.stat()
    IDMAP_BACKUP = (IDMAP.read_bytes(), original.st_mode & 0o777, original.st_uid, original.st_gid)
    IDMAP.write_text('[General]\nDomain = nfs.test\nLocal-Realms = NFS.TEST\n[Mapping]\nNobody-User = nobody\nNobody-Group = nogroup\n[Translation]\nMethod = nsswitch\nGSS-Methods = nsswitch\n')
    IDMAP.chmod(0o644)
    return {'domain': 'nfs.test', 'local_realms': ['NFS.TEST'], 'method': 'nsswitch',
            'original_sha256': hashlib.sha256(IDMAP_BACKUP[0]).hexdigest(), 'fixture_sha256': hashlib.sha256(IDMAP.read_bytes()).hexdigest()}


def check_listeners():
    listeners = command('ss', '-H', '-lntu')
    for port in ('2049', '10088'):
        selected = [line.split()[4] for line in listeners.splitlines() if line.split()[4].rsplit(':', 1)[-1] == port]
        if not selected or any(address != '127.0.0.1:' + port for address in selected):
            raise ValueError('Non-loopback or missing fixture listener: ' + port)
    return listeners


def run_test(binary, release, mode, run_output, groups=False, large=False, nfs3=False, diagnostic=False, acl_read=False, acl_set=False):
    environment = kerberos_environment()
    environment.update({'NFS_VIEWER_KERNEL': '1', 'NFS_VIEWER_KERNEL_PORT': '2049', 'NFS_VIEWER_KERNEL_MOUNT_PORT': '20048',
                        'NFS_VIEWER_KERNEL_KRB5': '1', 'NFS_VIEWER_KERNEL_KRB5_CONFIG': str(SECRET / 'krb5.conf'),
                        'NFS_VIEWER_KERNEL_KRB5_SPN': 'nfs/server.nfs.test',
                        'NFS_VIEWER_KERNEL_KRB5_ALICE_KEYTAB': str(SECRET / 'alice.keytab'),
                        'NFS_VIEWER_KERNEL_KRB5_ALICE_CCACHE': 'FILE:' + str(SECRET / 'alice.ccache'),
                        'NFS_VIEWER_KERNEL_KRB5_BOB_KEYTAB': str(SECRET / 'bob.keytab'),
                        'NFS_VIEWER_KERNEL_KRB5_STRANGER_KEYTAB': str(SECRET / 'stranger.keytab')})
    environment.pop('NFS_VIEWER_TEST_BINARY', None)
    environment.pop('NFS_VIEWER_KERNEL_GSS_GROUPS', None)
    environment.pop('NFS_VIEWER_KERNEL_GSS_LARGE', None)
    environment.pop('NFS_VIEWER_KERNEL_GSS_LARGE_CCACHE', None)
    environment.pop('NFS_VIEWER_KERNEL_GSS_V3', None)
    environment.pop('NFS_VIEWER_KERNEL_GSS_V3_UDP_DIAGNOSTIC', None)
    environment.pop('NFS_VIEWER_KERNEL_NFSACL', None)
    environment.pop('NFS_VIEWER_KERNEL_NFSACL_SET', None)
    if groups:
        environment['NFS_VIEWER_KERNEL_GSS_GROUPS'] = '1'
    if large:
        environment['NFS_VIEWER_KERNEL_GSS_LARGE'] = '1'
        environment['NFS_VIEWER_KERNEL_GSS_LARGE_CCACHE'] = 'FILE:' + str(SECRET / 'alice-large.ccache')
    if mode == 'release':
        environment['NFS_VIEWER_TEST_BINARY'] = str(release)
    if nfs3:
        environment['NFS_VIEWER_KERNEL_GSS_V3'] = '1'
    if diagnostic:
        environment['NFS_VIEWER_KERNEL_GSS_V3_UDP_DIAGNOSTIC'] = '1'
    pattern = '^TestKernelNFSGSSACL$/^4.1$/^krb5$/^keytab$' if mode == 'readiness' else '^(TestKernelNFSGSSACL|TestKernelNFSGSSACLCLI)$'
    if groups and mode != 'readiness':
        pattern = '^(TestKernelNFSGSSACL|TestKernelNFSGSSACLCLI|TestKernelNFSGSSGroups)$'
        if large:
            pattern = '^(TestKernelNFSGSSACL|TestKernelNFSGSSACLCLI|TestKernelNFSGSSGroups|TestKernelNFSGSSLargeToken)$'
    if nfs3:
        pattern = '^TestKernelNFS3GSSBehavior$/^tcp$/^krb5$/^keytab$' if mode == 'readiness' else '^(TestKernelNFS3GSSBehavior|TestKernelNFS3GSSCLI)$'
    if diagnostic:
        pattern = '^TestKernelGSS3UDPProtectedDiagnostic$'
    if acl_read:
        environment['NFS_VIEWER_KERNEL_NFSACL'] = '1'
        pattern = '^TestKernelNFSACLRead$/^gss$/^tcp$/^krb5$/^keytab$' if mode == 'readiness' else '^TestKernelNFSACLRead$'
    if acl_set:
        environment['NFS_VIEWER_KERNEL_NFSACL_SET'] = '1'
        pattern = '^TestKernelNFSACLSet$/^gss$/^tcp$/^krb5$/^keytab$' if mode == 'readiness' else '^TestKernelNFSACLSet$'
    timeout = 180 if mode == 'readiness' else 600
    if diagnostic:
        timeout = 360
    process = subprocess.Popen([str(binary), '-test.v', '-test.run', pattern, '-test.timeout', str(timeout) + 's'], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True, cwd=run_output)
    timed_out = False
    try:
        output, _ = process.communicate(timeout=timeout + 30)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate(timeout=10)
    (run_output / (mode + '.log')).write_text(output)
    required = ['TestKernelNFSGSSACL'] if mode == 'readiness' else ['TestKernelNFSGSSACL', 'TestKernelNFSGSSACLCLI']
    if groups and mode != 'readiness':
        required.append('TestKernelNFSGSSGroups')
        if large:
            required.append('TestKernelNFSGSSLargeToken')
    if nfs3:
        required = ['TestKernelNFS3GSSBehavior'] if mode == 'readiness' else ['TestKernelNFS3GSSBehavior', 'TestKernelNFS3GSSCLI']
    if diagnostic:
        required = ['TestKernelGSS3UDPProtectedDiagnostic']
    if acl_read:
        required = ['TestKernelNFSACLRead']
    if acl_set:
        required = ['TestKernelNFSACLSet']
    return {'mode': mode, 'returncode': process.returncode, 'timed_out': timed_out,
            'matched_tests': all(re.search(r'(?m)^--- PASS: ' + re.escape(name) + r' \(', output) for name in required),
            'required_top_level_tests': required,
            'skipped_tests': bool(re.search(r'(?m)^\s*--- SKIP:', output)), 'output': output}


def stop_credentials():
    for process in reversed(PROCESSES):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    if SECRET_OWNED:
        if SECRET.is_symlink() or SECRET.parent.resolve() != pathlib.Path('/run'):
            raise ValueError('Refusing changed credential cleanup target')
        shutil.rmtree(SECRET)


def cleanup(run_output):
    errors = []
    try:
        result = base.cleanup()
    except Exception as error:
        errors.append('NFS cleanup: ' + str(error))
        result = {'passed': False}
    try:
        stop_credentials()
    except Exception as error:
        errors.append(str(error))
    try:
        remove_proxy_runtime()
    except Exception as error:
        errors.append('Proxy runtime cleanup: ' + str(error))
    try:
        command('systemctl', 'disable', 'krb5-kdc.service', 'krb5-admin-server.service', check=False)
        if PROXY_OWNED:
            command('systemctl', 'disable', 'gssproxy.service')
    except Exception as error:
        errors.append('KDC disable: ' + str(error))
    if IDMAP_BACKUP is not None:
        contents, mode, uid, gid = IDMAP_BACKUP
        try:
            if IDMAP.is_symlink():
                raise ValueError('Idmap path changed to a symlink')
            IDMAP.write_bytes(contents)
            os.chown(IDMAP, uid, gid)
            IDMAP.chmod(mode)
            result['idmap_restored'] = IDMAP.read_bytes() == contents
        except Exception as error:
            errors.append('Idmap restore: ' + str(error))
    for name in reversed(CREATED_USERS):
        try:
            command('userdel', name)
        except Exception as error:
            errors.append('User cleanup: ' + str(error))
    for name in reversed(CREATED_GROUPS):
        try:
            grp.getgrnam(name)
        except KeyError:
            continue
        try:
            command('groupdel', name)
        except Exception as error:
            errors.append('Group cleanup: ' + str(error))
    listeners = command('ss', '-H', '-lntu')
    result.update({'credential_runtime_removed': not SECRET.exists(), 'owned_processes_exited': all(process.poll() is not None for process in PROCESSES),
                   'proxy_runtime_removed': not PROXY_OWNED or all(not path.exists() and not path.is_symlink() for path in PROXY_PATHS),
                   'proxy_override_removed': not PROXY_MASK_OWNED or not PROXY_MASK.is_symlink(),
                   'remaining_created_users': [name for name in CREATED_USERS if subprocess.run(['getent', 'passwd', name], stdout=subprocess.DEVNULL).returncode == 0],
                   'remaining_created_groups': [name for name in CREATED_GROUPS if subprocess.run(['getent', 'group', name], stdout=subprocess.DEVNULL).returncode == 0],
                   'errors': errors, 'listeners_after_gss_cleanup': listeners,
                   'kdc_services': command('systemctl', 'show', 'krb5-kdc.service', 'krb5-admin-server.service', '--property=Id,ActiveState,UnitFileState', check=False)})
    if PROXY_MASK_OWNED:
        result['proxy_service_after'] = command('systemctl', 'show', 'gssproxy.service', '--property=Id,ActiveState,UnitFileState')
        if 'ActiveState=inactive' not in result['proxy_service_after'] or 'UnitFileState=disabled' not in result['proxy_service_after']:
            errors.append('Proxy service did not remain inactive and disabled')
    result['passed'] = result['passed'] and not errors and result['credential_runtime_removed'] and result['owned_processes_exited'] and result.get('idmap_restored', True) and not result['remaining_created_users'] and not result['remaining_created_groups'] and 'UnitFileState=enabled' not in result['kdc_services'] and 'ActiveState=active' not in result['kdc_services'] and not any(line.split()[4].rsplit(':', 1)[-1] in ('88', '749', '10088') for line in listeners.splitlines())
    result['passed'] = result['passed'] and result['proxy_runtime_removed'] and result['proxy_override_removed']
    if PROXY_OWNED:
        result['gss_upcall_until_poweroff'] = command('cat', '/proc/net/rpc/use-gss-proxy', timeout=3)
    return result


def inspect_empty_guest(evidence):
    base.reject_domain_state()
    evidence['before'] = base.isolation()
    if command('exportfs', '-v') or base.EXPORTS.exists() or base.CONFIG.exists() or SECRET.exists() or pathlib.Path('/etc/krb5.keytab').exists():
        raise ValueError('Existing exports, fixture configuration or server credentials prevent isolated GSS setup')
    evidence['services_before'] = command('systemctl', 'show', *base.SERVICES, '--property=Id,ActiveState,UnitFileState', check=False)
    evidence['nfs_client_mounts_before'] = command('findmnt', '-rn', '-t', 'nfs,nfs4', check=False)
    thread_file = pathlib.Path('/proc/fs/nfsd/threads')
    evidence['nfsd_threads_before'] = thread_file.read_text().strip() if thread_file.exists() else '0'


def claim_empty_guest(evidence, proxy):
    base.reject_domain_state()
    # Ubuntu's nfs-client.target starts blkmap and the statd-notify oneshot at
    # boot even without a client mount/export. Record and stop these owned-guest
    # auxiliaries; still reject a pre-existing server, acceptor, KDC or SSSD.
    exempt = ['rpc-statd-notify.service', 'nfs-blkmap.service']
    if proxy:
        exempt.append('gssproxy.service')
    guarded = [name for name in base.SERVICES if name not in exempt]
    active = command('systemctl', 'show', *guarded, '--property=ActiveState', check=False)
    if evidence['nfs_client_mounts_before'] or evidence['nfsd_threads_before'] != '0' or 'ActiveState=active' in active or any(command('pgrep', '-x', name, check=False) for name in ('krb5kdc', 'rpc.svcgssd')):
        raise ValueError('Existing NFS/KDC/SSSD service prevents fixture ownership')
    if proxy and command('systemctl', 'show', 'gssproxy.service', '--property=ActiveState', '--value') == 'active':
        evidence['packaged_proxy_stopped'] = stop_packaged_proxy(evidence)
    if command('pgrep', '-x', 'gssproxy', check=False) or any(path.exists() or path.is_symlink() for path in PROXY_PATHS):
        raise ValueError('Unowned proxy process or runtime prevents fixture ownership')
    evidence['cleanup_authorized'] = True
    command('systemctl', 'stop', 'rpc-statd-notify.service', 'nfs-blkmap.service')
    evidence['client_auxiliaries_stopped'] = command('systemctl', 'show', 'rpc-statd-notify.service', 'nfs-blkmap.service', '--property=Id,ActiveState')
    if 'ActiveState=active' in evidence['client_auxiliaries_stopped']:
        raise ValueError('Boot-time NFS client auxiliaries did not stop')


def execute_auth_sys(evidence):
    """Reuse strict package-daemon ownership without creating GSS credentials."""
    inspect_empty_guest(evidence)
    base.MEDIA.mkdir(exist_ok=True)
    command('mount', '-o', 'ro,nosuid,nodev,noexec', '/dev/disk/by-label/cidata', str(base.MEDIA))
    metadata = json.loads((base.MEDIA / 'run.json').read_text())
    if metadata.get('RunId') != evidence['run_id'] or metadata.get('Security') != 'kernel-auth-sys' or metadata.get('AuthSysOnGssGuest') is not True or metadata.get('GSSAcceptor') != 'none':
        raise ValueError('Unexpected AUTH_SYS adapter media identity')
    acl_read = metadata.get('NFS3ACLRead', False)
    acl_set = metadata.get('NFS3ACLSet', False)
    if type(acl_read) is not bool or type(acl_set) is not bool or (acl_read and acl_set):
        raise ValueError('Invalid AUTH_SYS NFSACL profile')
    # The base runner mounts and authenticates this same read-only medium.
    command('umount', str(base.MEDIA))
    claim_empty_guest(evidence, proxy=True)
    command('systemctl', 'disable', 'gssproxy.service')
    mask_proxy_unit()
    evidence['protocol_profile'] = 'auth-sys-on-gss-package-guest'
    evidence['kerberos_credentials_created'] = False
    evidence['temporary_identities_created'] = False
    # The base runner retains its original AUTH_SYS exports, ACL fixture and
    # default invocation modes, or the explicit focused NFSACL profile.
    # Wrapper cleanup also removes the owned unit mask.
    base.execute(evidence)


def execute(evidence):
    inspect_empty_guest(evidence)
    base.MEDIA.mkdir(exist_ok=True)
    command('mount', '-o', 'ro,nosuid,nodev,noexec', '/dev/disk/by-label/cidata', str(base.MEDIA))
    metadata = json.loads((base.MEDIA / 'run.json').read_text())
    run_id = metadata['RunId']
    if not re.fullmatch(r'[a-z0-9-]{1,64}', run_id) or run_id != evidence['run_id'] or metadata.get('Security') != 'kernel-gss':
        raise ValueError('Unexpected GSS run identity')
    acceptor = metadata.get('GSSAcceptor', 'svc-gssd')
    proxy = acceptor == 'gssproxy'
    groups = metadata.get('SupplementaryGroups', False)
    large = metadata.get('LargeToken', False)
    nfs3 = metadata.get('NFS3GSS', False)
    diagnostic = metadata.get('NFS3UDPDiagnostic', False)
    acl_read = metadata.get('NFS3ACLRead', False)
    acl_set = metadata.get('NFS3ACLSet', False)
    if acceptor not in ('svc-gssd', 'gssproxy') or groups is not proxy or type(large) is not bool or (large and not proxy) or type(nfs3) is not bool or (nfs3 and (not proxy or large)) or type(diagnostic) is not bool or (diagnostic and not nfs3):
        raise ValueError('Unexpected acceptor/group profile combination')
    if type(acl_read) is not bool or type(acl_set) is not bool or (acl_read and acl_set) or ((acl_read or acl_set) and (not nfs3 or diagnostic or large)):
        raise ValueError('Invalid GSS NFSv3 NFSACL profile')
    evidence['protocol_profile'] = 'nfs3-gss-supported' if nfs3 else 'nfs4-gss'
    if acl_read:
        evidence['protocol_profile'] = 'nfs3-acl-read-gss'
    if acl_set:
        evidence['protocol_profile'] = 'nfs3-acl-set-gss'
    claim_empty_guest(evidence, proxy)
    base.OUTPUT.mkdir(exist_ok=True)
    run_output = base.OUTPUT / run_id
    run_output.mkdir(mode=0o700)
    evidence.update({'run_id': run_id, 'artifacts': metadata})
    names = ['cli.test', 'nfs-viewer-linux-amd64'] + (['gss-large-tgt'] if large else []) + (['nfs.test'] if diagnostic else [])
    for name in names:
        source = base.MEDIA / name
        if hashlib.sha256(source.read_bytes()).hexdigest().upper() != metadata['Hashes'][name]:
            raise ValueError('Test artifact differs from the prepared hash')
        shutil.copyfile(source, run_output / name)
        (run_output / name).chmod(0o700)
    evidence['offline_packages'] = ensure_packages(run_output, base.MEDIA / 'gss-bundle', base.MEDIA / 'verify-linux-bundle.py', proxy)
    command('systemctl', 'disable', 'krb5-kdc.service', 'krb5-admin-server.service')
    if proxy:
        command('systemctl', 'disable', 'gssproxy.service')
        mask_proxy_unit()
    evidence['identities'] = local_identities(groups)
    evidence['idmap'] = configure_idmap()
    evidence['kerberos'] = setup_credentials(run_output)
    if large:
        proof = json.loads(kcommand(str(run_output / 'gss-large-tgt'), 'FILE:' + str(SECRET / 'alice.ccache'),
                                    str(SECRET / 'alice-large.ccache'), str(SECRET / 'server.keytab')))
        if proof.get('exact_authdata_verified') is not True or proof.get('pac_present') is not False or proof.get('fresh_service_ticket_verified') is not True or proof.get('service_ticket_bytes', 0) <= 2048:
            raise ValueError('Augmented TGT helper did not verify a large synthetic service ticket')
        proof['output_mode'] = oct((SECRET / 'alice-large.ccache').stat().st_mode & 0o777)
        if proof['output_mode'] != '0o600':
            raise ValueError('Large-token FILE cache permissions are not private')
        evidence['large_token_preparation'] = proof
    base.prepare_fixture(run_id)
    if acl_read:
        base.prepare_acl_read_fixture()
        evidence['acl_read_seed_initial'] = base.acl_read_seed_metadata()
    if acl_set:
        evidence['acl_set_seed_initial'] = base.acl_read_seed_metadata(include_masked=False)
        evidence['acl_set_initial'] = base.acl_set_snapshot()
    if nfs3:
        readonly = base.ROOT / 'readonly/read.txt'
        evidence['readonly_initial'] = {
            'uid': readonly.lstat().st_uid, 'gid': readonly.lstat().st_gid,
            'mode': oct(readonly.lstat().st_mode & 0o777), 'bytes': readonly.lstat().st_size,
            'sha256': hashlib.sha256(readonly.read_bytes()).hexdigest()}
    if groups:
        evidence['group_fixture_initial'] = prepare_groups()
    evidence['acl_initial'] = base.acl_snapshot()
    evidence['filesystem'] = json.loads(command('findmnt', '-J', '-T', str(base.ROOT), '-o', 'SOURCE,TARGET,FSTYPE,UUID,OPTIONS'))
    if evidence['filesystem']['filesystems'][0]['fstype'] != 'ext4':
        raise ValueError('The fixture requires existing guest ext4')
    child = base.ROOT / 'data'
    children = [child, base.ROOT / 'readonly'] if nfs3 else [child]
    for export in children:
        command('mount', '--bind', str(export), str(export))
        base.BIND_MOUNTS.append(export)
    base.CONFIG.parent.mkdir(exist_ok=True)
    base.CONFIG.write_text('[nfsd]\nhost=127.0.0.1\nport=2049\nthreads=8\nvers3=y\nvers4=y\nvers4.0=y\nvers4.1=y\nvers4.2=y\nudp=y\ntcp=y\n[mountd]\nport=20048\nmanage-gids=n\n[svcgssd]\nverbosity=0\nrpc-verbosity=0\nidmap-verbosity=0\n')
    base.EXPORTS.parent.mkdir(exist_ok=True)
    base.EXPORTS.write_text(f'{base.ROOT} 127.0.0.1(ro,fsid=0,insecure,root_squash,subtree_check,sec=krb5:krb5i:krb5p,sync)\n'
                            f'{child} 127.0.0.1(rw,fsid=101,insecure,no_root_squash,subtree_check,sec=krb5:krb5i:krb5p,sync)\n'
                            + (f'{base.ROOT / "readonly"} 127.0.0.1(ro,fsid=102,insecure,root_squash,subtree_check,sec=krb5:krb5i:krb5p,sync)\n' if nfs3 else ''))
    command('systemctl', 'start', 'proc-fs-nfsd.mount')
    command('modprobe', 'rpcsec_gss_krb5')
    upcall = pathlib.Path('/proc/net/rpc/use-gss-proxy')
    if upcall.exists():
        evidence['gss_upcall_before'] = command('cat', str(upcall), timeout=3)
        allowed = ('-1', '1') if proxy and evidence.get('packaged_proxy_stopped') else (('-1',) if proxy else ('-1', '0'))
        if evidence['gss_upcall_before'] not in allowed:
            raise ValueError('Kernel GSS upcalls already use an unexpected acceptor')
    elif proxy:
        raise ValueError('Kernel gssproxy registration interface is unavailable')
    svc = start_proxy(run_output) if proxy else start_owned(['rpc.svcgssd', '-f', '-p', SPN], run_output / 'svcgssd.log', kerberos_environment())
    if proxy:
        evidence['gss_upcall_before_nfsd'] = command('cat', str(upcall), timeout=3)
        if evidence['gss_upcall_before_nfsd'] != '1':
            raise ValueError('Proxy must be registered before nfsd starts')
        evidence['proxy_version'] = command('gssproxy', '--version')
    command('systemctl', 'start', 'nfs-server.service', timeout=60)
    base.ready()
    if nfs3:
        # These NULL probes establish transport availability only. The selected
        # Go readiness profile must also pass authenticated NFS operations.
        evidence['mount_transport_readiness'] = {
            transport: command('rpcinfo', '-n', '20048', '-T', transport, '127.0.0.1', '100005', '3')
            for transport in ('tcp', 'udp')}
    if acl_read or acl_set:
        evidence['rpcinfo'] = command('rpcinfo', '-p', '127.0.0.1')
    if svc.poll() is not None:
        raise RuntimeError('GSS acceptor exited; inspect retained guest daemon log metadata')
    evidence.update({'listeners': check_listeners(), 'exports': command('exportfs', '-v'), 'kernel': command('uname', '-r'),
                     'versions': pathlib.Path('/proc/fs/nfsd/versions').read_text().strip(),
                     'nfs_client_mounts': command('findmnt', '-rn', '-t', 'nfs,nfs4', check=False), 'tests': [], 'acl_by_mode': {}})
    if evidence['nfs_client_mounts']:
        raise ValueError('Unexpected NFS client mount')
    modes = ('readiness', 'in-process') if acl_set else ('readiness', 'in-process', 'release')
    for mode in modes:
        evidence['acl_by_mode'][mode] = {'before': base.acl_snapshot()}
        if acl_read or acl_set:
            evidence['acl_by_mode'][mode]['seed_before'] = base.acl_read_seed_metadata(include_masked=acl_read)
        if acl_set:
            evidence['acl_by_mode'][mode]['created_before'] = base.acl_set_snapshot()
        test = run_test(run_output / 'cli.test', run_output / 'nfs-viewer-linux-amd64', mode, run_output, groups, large, nfs3, acl_read=acl_read, acl_set=acl_set)
        evidence['tests'].append(test)
        evidence['acl_by_mode'][mode]['after'] = base.acl_snapshot()
        if acl_read or acl_set:
            evidence['acl_by_mode'][mode]['seed_after'] = base.acl_read_seed_metadata(include_masked=acl_read)
        if acl_set:
            evidence['acl_by_mode'][mode]['created_after'] = base.acl_set_snapshot()
        evidence['acl_by_mode'][mode]['identity_files'] = [
            {'name': path.name, 'uid': path.lstat().st_uid, 'gid': path.lstat().st_gid,
             'mode': oct(path.lstat().st_mode & 0o777), 'bytes': path.lstat().st_size}
            for path in sorted((base.ROOT / 'data').glob('gss3-identity-*' if nfs3 else 'gss-identity-*'))]
        if nfs3:
            readonly = base.ROOT / 'readonly/read.txt'
            evidence['acl_by_mode'][mode]['readonly_file'] = {
                'uid': readonly.lstat().st_uid, 'gid': readonly.lstat().st_gid,
                'mode': oct(readonly.lstat().st_mode & 0o777), 'bytes': readonly.lstat().st_size,
                'sha256': hashlib.sha256(readonly.read_bytes()).hexdigest()}
        if groups:
            root = base.ROOT / 'data/gss-groups'
            evidence['acl_by_mode'][mode]['group_acl'] = command('getfacl', '--numeric', '--absolute-names', '--recursive', str(root))
            evidence['acl_by_mode'][mode]['group_files'] = [
                {'name': path.name, 'uid': path.lstat().st_uid, 'gid': path.lstat().st_gid,
                 'mode': oct(path.lstat().st_mode & 0o7777), 'bytes': path.lstat().st_size}
                for path in sorted(root.iterdir())]
        if mode == 'readiness' and upcall.exists():
            evidence['gss_upcall_after_readiness'] = command('cat', str(upcall), timeout=3)
            if evidence['gss_upcall_after_readiness'] != ('1' if proxy else '0'):
                raise ValueError('Authenticated readiness did not use the selected acceptor')
        if mode == 'readiness' and (test['returncode'] or test['timed_out'] or not test['matched_tests'] or test['skipped_tests']):
            raise RuntimeError('The standalone GSS readiness profile failed; full matrix was not started')
    evidence['after'] = base.isolation()
    evidence['tests_passed'] = all(not item['returncode'] and not item['timed_out'] and item['matched_tests'] and not item['skipped_tests'] for item in evidence['tests'])
    if diagnostic:
        # A diagnostic result never changes the supported-profile verdict. In
        # particular, it does not enable public protected-UDP selection.
        try:
            result = run_test(run_output / 'nfs.test', run_output / 'nfs-viewer-linux-amd64', 'udp-diagnostic', run_output,
                              groups=groups, nfs3=True, diagnostic=True)
            result['passed'] = not result['returncode'] and not result['timed_out'] and result['matched_tests'] and not result['skipped_tests']
            evidence['udp_protected_diagnostic'] = result
            result['files'] = [
                {'name': path.name, 'uid': path.lstat().st_uid, 'gid': path.lstat().st_gid,
                 'mode': oct(path.lstat().st_mode & 0o777), 'bytes': path.lstat().st_size}
                for path in sorted((base.ROOT / 'data').glob('gss3-udp-*'))]
        except Exception:
            evidence['udp_protected_diagnostic'] = {'passed': False, 'error': traceback.format_exc()}
        evidence['after_diagnostic'] = base.isolation()


if __name__ == '__main__':
    base.entry_gate()
    auth_sys = sys.argv[1:] == ['--auth-sys']
    if sys.argv[1:] and not auth_sys:
        raise SystemExit('Unexpected fixture adapter arguments')
    instance_id = pathlib.Path('/var/lib/cloud/data/instance-id').read_text().strip()
    expected = r'nfs-viewer-kernel-[a-z0-9-]{1,48}' if auth_sys else r'nfs-viewer-kernel-gss-[a-z0-9-]{1,48}'
    if not re.fullmatch(expected, instance_id) or (auth_sys and instance_id.startswith('nfs-viewer-kernel-gss-')):
        raise SystemExit('Refusing an unexpected GSS cloud-init instance identity')
    os.umask(0o077)
    result = {'stage': 'kernel-nfs-loopback-mit-gss', 'run_id': instance_id.removeprefix('nfs-viewer-'),
              'domain_joined': False, 'microsoft_ad_verified': False, 'tests_passed': False}
    if auth_sys:
        result['stage'] = 'kernel-nfs-loopback-auth-sys'
    try:
        (execute_auth_sys if auth_sys else execute)(result)
    except Exception:
        result['error'] = traceback.format_exc()
    finally:
        run_output = base.OUTPUT / result['run_id'] if result.get('run_id') else None
        if result.get('cleanup_authorized'):
            try:
                result['cleanup'] = cleanup(run_output)
            except Exception:
                result['cleanup'] = {'passed': False, 'error': traceback.format_exc()}
        else:
            result['cleanup'] = {'passed': False, 'reason': 'Read-only preflight rejected fixture ownership'}
        if run_output:
            result['daemon_logs'] = {name: {'guest_path': str(run_output / name), 'bytes': (run_output / name).stat().st_size,
                                          'sha256': hashlib.sha256((run_output / name).read_bytes()).hexdigest()}
                                     for name in ('kdc.log', 'svcgssd.log', 'gssproxy.log') if (run_output / name).is_file()}
    text = json.dumps(result, sort_keys=True)
    pathlib.Path('/var/lib/nfs-lab-kernel-gss.json').write_text(text + '\n')
    with open('/dev/ttyS0', 'w') as serial:
        serial.write('NFS_LAB_KERNEL_EVIDENCE ' + text + '\n')
        serial.write('NFS_LAB_KERNEL_' + ('COMPLETE' if result['tests_passed'] and result['cleanup']['passed'] and 'error' not in result else 'FAILED') + '\n')
    subprocess.run(['systemctl', 'poweroff'], check=True)
