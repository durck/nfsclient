#!/usr/bin/python3
"""Guarded, single-attempt AD enrollment and RFC2307 evidence in the private guest.

The join action inherits its password from stdin. Never put it in media, argv,
output or this file. A failed/uncertain join is deliberately not retried.
"""
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time

STATE = pathlib.Path('/var/lib/nfs-viewer-msad')
MARKER = STATE / 'domain-joined.json'
KEYTAB = pathlib.Path('/etc/krb5.keytab')
SSSD = pathlib.Path('/etc/sssd/sssd.conf')
REALM = 'MSAD.NFS.TEST'
DOMAIN = 'msad.nfs.test'
USERS = {'alice': 24001, 'bob': 24002, 'svc-nfs': 24004}
GROUPS = {'nfsusers': 24000, 'nfsreaders': 24003}
KRB_CONFIG = '''[libdefaults]
 default_realm = MSAD.NFS.TEST
 dns_lookup_realm = false
 dns_lookup_kdc = true
 rdns = false

[domain_realm]
 .msad.nfs.test = MSAD.NFS.TEST
 msad.nfs.test = MSAD.NFS.TEST
'''
SSSD_CONFIG = '''[sssd]
config_file_version = 2
domains = msad.nfs.test

[domain/msad.nfs.test]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_domain = msad.nfs.test
krb5_realm = MSAD.NFS.TEST
ad_server = nfsaddc1.msad.nfs.test
ad_hostname = nfs.msad.nfs.test
ad_enabled_domains = msad.nfs.test
ldap_id_mapping = false
auto_private_groups = false
use_fully_qualified_names = false
ad_enable_gc = false
ad_gpo_access_control = enforcing
cache_credentials = false
dyndns_update = false
'''


def command(*args, timeout=30, env=None):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, env=env)
    if result.returncode:
        raise RuntimeError('Command failed: ' + repr(args) + '\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def exists(path):
    return os.path.lexists(path)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_json(path, value):
    data = json.dumps(value, sort_keys=True) + '\n'
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as temp:
        temp.write(data)
        temp.flush()
        os.fsync(temp.fileno())
    os.replace(temp.name, path)


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError('Unsafe configuration file: ' + str(path))
    return info


def isolation():
    if os.geteuid() != 0 or command('hostname', '-f') != 'nfs.msad.nfs.test':
        raise RuntimeError('Expected dedicated root-managed Linux guest')
    if pathlib.Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'VMware, Inc.':
        raise RuntimeError('Expected VMware lab guest')
    if STATE.is_symlink() or not STATE.is_dir():
        raise RuntimeError('Management bootstrap is missing')
    info = STATE.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('Unsafe management state directory')
    addresses = json.loads(command('ip', '-j', 'address'))
    links = [entry for entry in addresses if entry['ifname'] != 'lo']
    if (len(links) != 1 or links[0]['ifname'] != 'lab0'
            or links[0]['address'] != '00:0c:29:bd:04:52'
            or len(links[0]['addr_info']) != 1
            or links[0]['addr_info'][0]['family'] != 'inet'
            or links[0]['addr_info'][0]['local'] != '192.0.2.20'
            or links[0]['addr_info'][0]['prefixlen'] != 24):
        raise RuntimeError('Unexpected private NIC/address')
    ipv4 = json.loads(command('ip', '-4', '-j', 'route'))
    ipv6 = json.loads(command('ip', '-6', '-j', 'route'))
    if (len(ipv4) != 1 or ipv4[0].get('dst') != '192.0.2.0/24'
            or ipv4[0].get('dev') != 'lab0' or ipv4[0].get('gateway') or ipv6):
        raise RuntimeError('Unexpected guest routes')
    dns = command('resolvectl', 'dns').splitlines()
    if dns != ['Global:', 'Link 2 (lab0): 192.0.2.10']:
        raise RuntimeError('Unexpected guest DNS servers: ' + repr(dns))
    records = {}
    for name, kind, expected in (
        ('nfsaddc1.msad.nfs.test', 'A', '192.0.2.10'),
        ('nfs.msad.nfs.test', 'A', '192.0.2.20'),
        ('_kerberos._tcp.msad.nfs.test', 'SRV', '0 100 88 nfsaddc1.msad.nfs.test.'),
        ('_ldap._tcp.dc._msdcs.msad.nfs.test', 'SRV', '0 100 389 nfsaddc1.msad.nfs.test.'),
    ):
        # systemd-resolved also answers /etc/hosts entries (cloud-init maps the
        # guest's own name to 127.0.1.1). Check AD's authoritative self A record
        # directly, and separately check normal DC/service discovery below.
        records[name] = command('dig', '@192.0.2.10', '+short', name, kind)
        if records[name] != expected:
            raise RuntimeError('Unexpected DNS record: ' + name)
        if name != 'nfs.msad.nfs.test' and command('dig', '+short', name, kind) != expected:
            raise RuntimeError('System resolver disagrees with AD: ' + name)
    return {'addresses': addresses, 'ipv4_routes': ipv4, 'ipv6_routes': ipv6, 'dns': dns, 'records': records}


def local_collision_check():
    for database, expected in (('passwd', USERS), ('group', GROUPS)):
        for line in command('getent', '-s', 'files', database).splitlines():
            fields = line.split(':')
            if fields[0] in expected or int(fields[2]) in expected.values():
                raise RuntimeError('Local identity collides with AD: ' + database + ' ' + fields[0])


def phase(required):
    regular(MARKER)
    value = json.loads(MARKER.read_text())
    if value.get('domain') != DOMAIN or value.get('phase') not in required:
        raise RuntimeError('Unexpected enrollment phase; inspect saved state without retrying join')
    return value


def preflight(dc_epoch):
    scope = isolation()
    if abs(time.time() - dc_epoch) > 60:
        raise RuntimeError('DC and Linux clocks differ by more than 60 seconds')
    local_collision_check()
    for path in (MARKER, KEYTAB, SSSD, STATE / 'before-join'):
        if exists(path):
            raise RuntimeError('Existing domain/bootstrap state: ' + str(path))
    fragments = pathlib.Path('/etc/sssd/conf.d')
    if fragments.is_symlink() or any(fragments.glob('*.conf')):
        raise RuntimeError('Existing SSSD configuration fragment')
    unit = command('systemctl', 'show', 'sssd.service', '--property=ActiveState,SubState,MainPID')
    if set(unit.splitlines()) != {'ActiveState=inactive', 'SubState=dead', 'MainPID=0'}:
        raise RuntimeError('SSSD must be inactive before enrollment')
    pgrep = subprocess.run(['pgrep', '-x', 'sssd|sssd_.*'], text=True, capture_output=True, timeout=5)
    if pgrep.returncode != 1 or pgrep.stdout:
        raise RuntimeError('Cannot establish absence of SSSD processes')
    for name in ('/etc/krb5.conf', '/etc/nsswitch.conf'):
        regular(pathlib.Path(name))
    packages = command('dpkg-query', '-W', '-f=${Package}\t${Version}\t${db:Status-Status}\n',
                       'adcli', 'sssd-ad', 'sssd-tools', 'libnss-sss', 'krb5-user')
    if len(packages.splitlines()) != 5 or any(not line.endswith('\tinstalled') for line in packages.splitlines()):
        raise RuntimeError('Required domain packages are not installed')
    return {'utc': stamp(), 'phase': 'preflight', 'scope': scope, 'packages': packages,
            'clock_skew_seconds': time.time() - dc_epoch}


def prepare(dc_epoch):
    report = preflight(dc_epoch)
    backup = STATE / 'before-join'
    backup.mkdir(mode=0o700)
    for name in ('krb5.conf', 'nsswitch.conf'):
        shutil.copy2('/etc/' + name, backup / name)
    report.update(domain=DOMAIN, phase='prepared')
    # Claim domain state before changing configuration, also protecting a partial
    # join from historical MIT fixtures. This marker does not assert success.
    write_json(MARKER, report)
    pathlib.Path('/etc/krb5.conf').write_text(KRB_CONFIG)
    write_json(STATE / 'preflight.json', report)
    return report


def join():
    isolation()
    state = phase({'prepared'})
    local_collision_check()
    if exists(KEYTAB) or exists(SSSD):
        raise RuntimeError('Refusing to replace existing domain credentials/configuration')
    state.update(phase='join-attempted', attempted_utc=stamp())
    write_json(MARKER, state)
    # Password is inherited from SSH's encrypted stdin. No show-password,
    # service-name or add-service-principal: svc-nfs owns the NFS SPN already.
    args = ['adcli', 'join', DOMAIN, '--domain-realm=' + REALM,
            '--domain-controller=nfsaddc1.msad.nfs.test', '--host-fqdn=nfs.msad.nfs.test',
            '--computer-name=NFS', '--domain-ou=OU=NfsViewerLab,DC=msad,DC=nfs,DC=test',
            '--host-keytab=/etc/krb5.keytab', '--login-user=Administrator', '--stdin-password']
    result = subprocess.run(args, stdin=sys.stdin, text=True, capture_output=True, timeout=90)
    state['join_exit'] = result.returncode
    state['join_output'] = result.stdout + result.stderr
    if result.returncode:
        write_json(MARKER, state)
        raise RuntimeError('Enrollment failed/uncertain; inspect marker and AD computer before any recovery')
    regular(KEYTAB)
    KEYTAB.chmod(0o600)
    state.update(phase='joined', joined_utc=stamp())
    write_json(MARKER, state)
    return {key: state[key] for key in ('domain', 'phase', 'joined_utc', 'join_exit')}


def configure():
    isolation()
    state = phase({'joined'})
    local_collision_check()
    if exists(SSSD) or any(pathlib.Path('/etc/sssd/conf.d').glob('*.conf')):
        raise RuntimeError('Refusing existing SSSD configuration')
    regular(KEYTAB)
    proof = command('adcli', 'testjoin', '--domain=' + DOMAIN, '--host-keytab=/etc/krb5.keytab', timeout=45)
    fd = os.open(SSSD, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(SSSD_CONFIG)
    nss = pathlib.Path('/etc/nsswitch.conf')
    regular(nss)
    lines = nss.read_text().splitlines()
    for database in ('passwd', 'group'):
        indexes = [index for index, line in enumerate(lines) if line.startswith(database + ':')]
        if len(indexes) != 1:
            raise RuntimeError('Ambiguous NSS database: ' + database)
        index = indexes[0]
        if 'sss' not in lines[index].split('#')[0].split()[1:]:
            body, separator, comment = lines[index].partition('#')
            lines[index] = body.rstrip() + ' sss' + (' #' + comment if separator else '')
    nss.write_text('\n'.join(lines) + '\n')
    config_check = command('sssctl', 'config-check')
    command('systemctl', 'enable', '--now', 'sssd.service', 'sssd-nss.socket')
    if command('systemctl', 'is-active', 'sssd.service') != 'active':
        raise RuntimeError('SSSD failed to start')
    state.update(phase='configured', configured_utc=stamp(), testjoin=proof, config_check=config_check)
    write_json(MARKER, state)
    return {'domain': DOMAIN, 'phase': 'configured', 'testjoin': proof, 'config_check': config_check}


def verify(bob_reader=False):
    scope = isolation()
    phase({'configured', 'verified'})
    local_collision_check()
    info = regular(KEYTAB)
    if stat.S_IMODE(info.st_mode) != 0o600 or stat.S_IMODE(regular(SSSD).st_mode) != 0o600:
        raise RuntimeError('Domain configuration must be root-only')
    if SSSD.read_text() != SSSD_CONFIG or pathlib.Path('/etc/krb5.conf').read_text() != KRB_CONFIG:
        raise RuntimeError('Unexpected domain configuration drift')
    # On the first start these objects do not exist in the cache yet, and
    # sss_cache correctly refuses an unmatched invalidation request.
    command('getent', '-s', 'sss', 'passwd', 'bob')
    command('getent', '-s', 'sss', 'group', 'nfsreaders')
    command('sss_cache', '-d', DOMAIN, '-u', 'bob', '-g', 'nfsreaders')
    identity = {}
    for attempt in range(12):
        for name, uid in USERS.items():
            entry = command('getent', '-s', 'sss', 'passwd', name).split(':')
            numeric = command('getent', '-s', 'sss', 'passwd', str(uid)).split(':')
            if entry != numeric or entry[0] != name or int(entry[2]) != uid or int(entry[3]) != 24000:
                raise RuntimeError('Unexpected domain identity: ' + name)
            group_ids = sorted(int(group) for group in command('id', '-G', name).split())
            if int(command('id', '-u', name)) != uid or int(command('id', '-g', name)) != 24000:
                raise RuntimeError('NSS identity differs from SSSD: ' + name)
            identity[name] = {'uid': uid, 'gid': 24000, 'groups': group_ids,
                              'passwd': ':'.join(entry), 'id': command('id', name)}
        if (24003 in identity['bob']['groups']) == bob_reader:
            break
        time.sleep(1)
        command('sss_cache', '-d', DOMAIN, '-u', 'bob', '-g', 'nfsreaders')
    expected = {'alice': [24000, 24003], 'bob': [24000, 24003] if bob_reader else [24000], 'svc-nfs': [24000]}
    if any(identity[name]['groups'] != groups for name, groups in expected.items()):
        raise RuntimeError('Unexpected domain supplementary groups: ' + json.dumps(identity))
    groups = {}
    for name, gid in GROUPS.items():
        value = command('getent', '-s', 'sss', 'group', name)
        fields = value.split(':')
        if fields[0] != name or int(fields[2]) != gid or command('getent', '-s', 'sss', 'group', str(gid)) != value:
            raise RuntimeError('Unexpected domain group: ' + name)
        groups[name] = value
    testjoin = command('adcli', 'testjoin', '--domain=' + DOMAIN, '--host-keytab=/etc/krb5.keytab', timeout=45)
    # A private tmpfs cache verifies real machine AS exchange without retaining
    # a ticket or printing key material. klist -e prints ticket metadata only.
    with tempfile.TemporaryDirectory(prefix='nfs-msad-', dir='/run') as temp:
        env = dict(os.environ, KRB5CCNAME='FILE:' + temp + '/machine.ccache')
        acquired = False
        try:
            command('kinit', '-k', '-t', str(KEYTAB), 'NFS$@' + REALM, env=env)
            acquired = True
            ticket = command('klist', '-e', env=env)
        finally:
            if acquired:
                command('kdestroy', env=env)
    result = {'utc': stamp(), 'domain': DOMAIN, 'scope': scope, 'users': identity, 'groups': groups,
              'bob_reader_expected': bob_reader, 'testjoin': testjoin, 'machine_ticket': ticket,
              'keytab_metadata': command('klist', '-kte', str(KEYTAB)),
              # domain-status requires the optional InfoPipe responder, which
              # this NSS-only fixture does not install or enable.
              'sssd_service': command('systemctl', 'is-active', 'sssd.service'),
              'config_sha256': hashlib.sha256(SSSD_CONFIG.encode()).hexdigest(),
              'microsoft_ad_nfs_validated': False}
    destination = STATE / ('identity-bob-reader.json' if bob_reader else 'identity-baseline.json')
    write_json(destination, result)
    state = phase({'configured', 'verified'})
    state.update(phase='verified', verified_utc=stamp())
    write_json(MARKER, state)
    return result


if __name__ == '__main__':
    os.umask(0o077)
    action = sys.argv[1]
    if action in ('preflight', 'prepare') and len(sys.argv) == 3:
        result = globals()[action](float(sys.argv[2]))
    elif action == 'join' and len(sys.argv) == 2:
        result = join()
    elif action == 'configure' and len(sys.argv) == 2:
        result = configure()
    elif action in ('verify', 'verify-bob-reader') and len(sys.argv) == 2:
        result = verify(action == 'verify-bob-reader')
    else:
        raise SystemExit('Expected preflight/prepare DC_EPOCH, join, configure, verify or verify-bob-reader')
    print(json.dumps(result, sort_keys=True))
