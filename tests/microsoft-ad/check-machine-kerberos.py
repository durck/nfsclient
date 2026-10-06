#!/usr/bin/python3
"""Run the standalone Go Kerberos client against the enrolled guest's AD.

Use the existing machine keytab in place. This neither provisions ordinary-user
credentials nor configures NFS, changes domain secrets, or exports any keytab.
"""
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CONFIG = """[libdefaults]
 default_realm = MSAD.NFS.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 canonicalize = false
 udp_preference_limit = 1

[realms]
 MSAD.NFS.TEST = {
  kdc = 192.0.2.10:88
 }

[domain_realm]
 .msad.nfs.test = MSAD.NFS.TEST
 msad.nfs.test = MSAD.NFS.TEST
"""


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r'machine-[0-9]{8}-[0-9]{2}', sys.argv[1]):
        raise RuntimeError('Expected a fresh machine evidence run identifier')
    os.umask(0o077)
    domain = load('domain', 'join-linux-domain.py')
    guard = load('guard', 'check-enrolled-guards.py')
    domain.isolation()
    state = json.loads(domain.MARKER.read_text())
    if state.get('phase') != 'verified' or state.get('domain') != 'msad.nfs.test':
        raise RuntimeError('Requires the already verified AD domain join')
    # mkdir deliberately refuses an existing run, including a symlink.
    run = domain.STATE / sys.argv[1]
    run.mkdir(mode=0o700)
    before = guard.snapshot()
    result = {'passed': False, 'run': sys.argv[1], 'before': before,
              'ordinary_user_verified': False, 'service_ticket_decrypted': False,
              'microsoft_ad_nfs_verified': False}
    try:
        config = run / 'krb5.conf'
        config.write_text(CONFIG)
        env = dict(os.environ, LC_ALL='C', NFS_VIEWER_MSAD_MACHINE='1',
                   NFS_VIEWER_MSAD_KRB5_CONFIG=str(config),
                   NFS_VIEWER_MSAD_MACHINE_KEYTAB='/etc/krb5.keytab')
        env.pop('NFS_VIEWER_MSAD_KRBCLIENT', None)
        jobs = [('machine', 'krbclient.test', ['-test.run=^TestMicrosoftADMachineKerberos$', '-test.timeout=180s']),
                ('alias', 'keytabalias.test', ['-test.timeout=60s'])]
        for name, binary, args in jobs:
            domain.regular(HERE / binary)
            process = subprocess.run([str(HERE / binary), '-test.v', *args],
                                     env=env, text=True, capture_output=True, timeout=200)
            (run / (name + '.stdout.txt')).write_text(process.stdout)
            (run / (name + '.stderr.txt')).write_text(process.stderr)
            result[name + '_exit'] = process.returncode
            if process.returncode or '--- FAIL:' in process.stdout or '--- SKIP:' in process.stdout:
                raise RuntimeError(name + ' verification failed; inspect retained metadata-only output')
            if name == 'machine':
                cases = re.findall(r'--- PASS: TestMicrosoftADMachineKerberos/(tcp|udp-preferred)/(aes128|aes256) ', process.stdout)
                if set(cases) != {(n, e) for n in ('tcp', 'udp-preferred') for e in ('aes128', 'aes256')} or len(cases) != 4:
                    raise RuntimeError('Missing or duplicate machine profile results')
                result['profiles'] = [dict(transport=n, enctype=e) for n, e in cases]
        domain.command('adcli', 'testjoin', '--domain=msad.nfs.test', '--host-keytab=/etc/krb5.keytab')
        result['testjoin_passed'] = True
        result['passed'] = True
    finally:
        result['after'] = guard.snapshot()
        result['domain_state_unchanged'] = result['before'] == result['after']
        result['passed'] = result['passed'] and result['domain_state_unchanged']
        domain.write_json(run / 'result.json', result)
        print(json.dumps(result, sort_keys=True))
    if not result['passed']:
        raise RuntimeError('Domain state changed during machine fixture')


if __name__ == '__main__':
    main()
