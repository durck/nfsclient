#!/usr/bin/python3
"""Derive explicitly supplied AD account keys with native KDC-provided salt.

Passwords arrive as a JSON object on encrypted SSH stdin. Raw ktutil output is
never retained: a failed interactive command can echo subsequent input.
The interop profile consumes newly user-provided credentials, never the protected
legacy password store. --preflight checks readiness without reading stdin.
"""
import argparse
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys

sys.dont_write_bytecode = True

HERE = pathlib.Path(__file__).resolve().parent
ROOT = pathlib.Path('/var/lib/nfs-viewer-msad/kerberos')
REALM = 'MSAD.NFS.TEST'
SPN = 'nfs/nfs.msad.nfs.test@' + REALM
ENCTYPES = ('aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96')
STAGE = 'preflight'


def profile(name):
    if name == 'legacy':
        return {'name': name, 'root': ROOT, 'users': ('alice', 'bob', 'svc-nfs'),
                'uids': (24001, 24002, 24004), 'groups': ('nfsusers', 'nfsreaders'),
                'gids': (24000, 24003), 'service': 'svc-nfs', 'spn': SPN}
    if name == 'interop':
        return {'name': name, 'root': pathlib.Path('/var/lib/nfs-viewer-msad/kerberos-interop'),
                'users': ('nv-alice', 'nv-bob', 'nv-nfs'), 'uids': (25001, 25002, 25004),
                'groups': ('nviusers', 'nvireaders'), 'gids': (25000, 25003),
                'service': 'nv-nfs', 'spn': 'nfs/nfs-interop.msad.nfs.test@' + REALM}
    raise RuntimeError('Unknown credential profile')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def parse_payload(payload, selected):
    """Validate only the fixed profile schema; never include input in errors."""
    if not isinstance(payload, bytes) or len(payload) > 8192:
        raise RuntimeError('Credential input exceeds bound or is not bytes')
    try:
        value = json.loads(payload.decode('utf-8'), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, RecursionError):
        raise RuntimeError('Invalid credential JSON') from None
    if type(value) is not dict:
        raise RuntimeError('Unexpected credential object')
    names = set(selected['users'])
    if selected['name'] == 'legacy':
        passwords, kvnos = value, dict.fromkeys(names, 2)
    else:
        if set(value) != {'passwords', 'kvnos'}:
            raise RuntimeError('Interop requires exactly passwords and kvnos')
        passwords, kvnos = value['passwords'], value['kvnos']
    if type(passwords) is not dict or type(kvnos) is not dict or set(passwords) != names or set(kvnos) != names:
        raise RuntimeError('Unexpected credential account set')
    if any(not isinstance(p, str) or not 12 <= len(p) <= 256 or any(c in p for c in '\r\n\0') for p in passwords.values()):
        raise RuntimeError('Unsupported credential input shape')
    if any(type(k) is not int or not 1 <= k <= 255 for k in kvnos.values()):
        raise RuntimeError('Account KVNO must be an integer between 1 and 255')
    return passwords, kvnos


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def config(enctypes):
    selected = ' '.join(enctypes)
    return f'''[libdefaults]
 default_realm = MSAD.NFS.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 canonicalize = false
 udp_preference_limit = 1
 ticket_lifetime = 1h
 forwardable = false
 default_tkt_enctypes = {selected}
 default_tgs_enctypes = {selected}
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 MSAD.NFS.TEST = {{
  kdc = 192.0.2.10:88
 }}
[domain_realm]
 .msad.nfs.test = MSAD.NFS.TEST
 msad.nfs.test = MSAD.NFS.TEST
'''


def run(args, env, data=None, sensitive=False):
    try:
        result = subprocess.run(args, text=True, input=data, capture_output=True, env=env, timeout=45)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Native credential command timed out; no automatic retry') from None
    if result.returncode:
        # Never attach raw interaction or command exceptions to persisted logs.
        raise RuntimeError('Native credential command failed: ' + pathlib.Path(args[0]).name)
    return '' if sensitive else result.stdout.strip()


def inspect_prerequisites(selected):
    domain = module('domain', 'join-linux-domain.py')
    domain.isolation()
    domain.phase({'verified'})
    guard = module('domain_guard', 'check-enrolled-guards.py')
    before = guard.snapshot()
    root = selected['root']
    if os.path.lexists(root):
        raise RuntimeError('Credential stage already exists; inspect it instead of reprovisioning')
    # AD accounts need not exist yet during preflight. Local files must not
    # supply the future RFC2307 names/IDs in their place.
    for database, names, ids in (('passwd', selected['users'], selected['uids']),
                                 ('group', selected['groups'], selected['gids'])):
        for line in domain.command('getent', '-s', 'files', database).splitlines():
            fields = line.split(':')
            if len(fields) < 3 or not fields[2].isdigit():
                raise RuntimeError('Invalid local NSS record')
            if fields[0] in names or int(fields[2]) in ids:
                raise RuntimeError('Local identity collides with selected AD profile')
    tools = {}
    for name in ('ktutil', 'kinit', 'klist', 'kvno'):
        path = pathlib.Path('/usr/bin', name).resolve(strict=True)
        domain.regular(path)
        if not os.access(path, os.X_OK):
            raise RuntimeError('Native credential tool is not executable')
        tools[name] = str(path)
    helper = HERE / 'keytabalias'
    domain.regular(helper)
    if not os.access(helper, os.X_OK):
        raise RuntimeError('Keytab alias helper is not executable')
    return domain, guard, before, tools


def main(argv=None):
    global STAGE
    STAGE = 'preflight'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('legacy', 'interop'), default='legacy')
    parser.add_argument('--preflight', action='store_true', help='check readiness without stdin or credential creation')
    args = parser.parse_args(argv)
    os.umask(0o077)
    selected = profile(args.profile)
    domain, guard, before, tools = inspect_prerequisites(selected)
    root = selected['root']
    if args.preflight:
        after = guard.snapshot()
        if before != after:
            raise RuntimeError('Domain state changed during read-only preflight')
        print(json.dumps({'stage': 'credential-preflight', 'profile': args.profile,
                          'root': str(root), 'root_absent': True, 'stdin_read': False,
                          'passed': True, 'before': before, 'after': after}, sort_keys=True))
        return
    STAGE = 'credential-input'
    secrets, kvnos = parse_payload(sys.stdin.buffer.read(8193), selected)
    # Fresh private directory is the reservation; failures retain it for inspection.
    root.mkdir(mode=0o700)
    common = root / 'krb5.conf'
    common.write_text(config(ENCTYPES))
    env = dict(os.environ, KRB5_CONFIG=str(common), LC_ALL='C')
    evidence = {'stage': 'native-msad-current-keys', 'profile': args.profile,
                'domain': 'msad.nfs.test', 'accounts': {}, 'kvnos': kvnos,
                'kvno': kvnos[selected['service']], 'password_or_spn_updates': False,
                'service_principal': selected['spn'], 'nfs_validated': False}
    for user in selected['users']:
        STAGE = 'derive-keytab:' + user
        principal = user + '@' + REALM
        path = root / (user + '.keytab')
        commands = []
        for enctype in ENCTYPES:
            commands.extend(['addent -password -p ' + principal + ' -k ' + str(kvnos[user]) + ' -e ' + enctype + ' -f', secrets[user]])
        commands.extend(['wkt ' + str(path), 'quit', ''])
        run([tools['ktutil']], env, '\n'.join(commands), sensitive=True)
        STAGE = 'validate-account-keytab:' + user
        # ktutil may return zero after an interactive subcommand error. Native
        # kinit for each enctype plus the alias tool validate actual outputs.
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 8192:
            raise RuntimeError('Missing/invalid generated keytab')
        path.chmod(0o600)
        metadata = run([tools['klist'], '-kte', str(path)], env)
        entries = [line for line in metadata.splitlines() if principal in line]
        if len(entries) != 2 or any(not line.strip().startswith(str(kvnos[user]) + ' ') for line in entries):
            raise RuntimeError('Unexpected account key count/KVNO')
        if any(sum('(' + et + ')' in line for line in entries) != 1 for et in ENCTYPES):
            raise RuntimeError('Account key enctypes differ')
        account = {'principal': principal, 'kvno': kvnos[user], 'keytab_metadata': metadata, 'as_checks': []}
        for index, enctype in enumerate(ENCTYPES):
            STAGE = 'validate-account-as:' + user
            cfg = root / (user + '-' + str(index) + '.conf')
            cfg.write_text(config((enctype,)))
            cache = root / (user + '.ccache')
            ticket_env = dict(env, KRB5_CONFIG=str(cfg), KRB5CCNAME='FILE:' + str(cache))
            run([tools['kinit'], '-k', '-t', str(path), principal], ticket_env)
            ticket = run([tools['klist'], '-e'], ticket_env)
            if 'Default principal: ' + principal not in ticket or 'Etype (skey, tkt): ' + enctype not in ticket:
                raise RuntimeError('Native AS identity/enctype mismatch')
            account['as_checks'].append({'enctype': enctype, 'ticket_metadata': ticket})
        # Publish the ordinary FILE fixture with the common AES preference.
        run([tools['kinit'], '-k', '-t', str(path), principal], dict(env, KRB5CCNAME='FILE:' + str(root / (user + '.ccache'))))
        evidence['accounts'][user] = account
        secrets[user] = ''
    service = root / 'nfs.keytab'
    STAGE = 'alias-service-keytab'
    profile_args = ['-profile', args.profile, '-kvno', str(kvnos[selected['service']])]
    run([str(HERE / 'keytabalias'), *profile_args, '-input', str(root / (selected['service'] + '.keytab')), '-output', str(service)], env)
    evidence['service_keytab_metadata'] = run([tools['klist'], '-kte', str(service)], env)
    evidence['service_ticket_checks'] = {}
    for user in selected['users'][:2]:
        STAGE = 'decrypt-service-ticket:' + user
        ticket_env = dict(env, KRB5CCNAME='FILE:' + str(root / (user + '.ccache')))
        proof = run([tools['kvno'], '-k', str(service), selected['spn']], ticket_env)
        if re.findall(r'\bkvno = ([0-9]+)\b', proof) != [str(kvnos[selected['service']])] or 'keytab entry valid' not in proof:
            raise RuntimeError('Native service ticket decryption failed')
        evidence['service_ticket_checks'][user] = proof
    STAGE = 'domain-state-check'
    after = guard.snapshot()
    if before != after:
        raise RuntimeError('Machine keytab/configuration/service state changed')
    evidence.update(before=before, after=after, passed=True)
    (root / 'native-evidence.json').write_text(json.dumps(evidence, sort_keys=True) + '\n')
    print(json.dumps(evidence, sort_keys=True))


def entrypoint(argv=None):
    try:
        main(argv)
    except Exception:
        # JSON/parser/native-command exceptions must never expose input or keys.
        print('Credential provisioning failed during ' + STAGE + '; inspect non-secret state. No automatic retry.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(entrypoint())
