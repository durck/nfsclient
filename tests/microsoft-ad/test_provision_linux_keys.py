"""Synthetic schema and no-input preflight regressions; never contacts a guest."""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('provision_keys', pathlib.Path(__file__).with_name('provision-linux-keys.py'))
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


def credentials():
    names = provision.profile('interop')['users']
    return {'passwords': dict.fromkeys(names, 'synthetic-password-only'),
            'kvnos': dict(zip(names, (1, 2, 255)))}


class CredentialInputTests(unittest.TestCase):
    def test_exact_profiles_and_actual_kvnos(self):
        interop = provision.profile('interop')
        passwords, kvnos = provision.parse_payload(json.dumps(credentials()).encode(), interop)
        self.assertEqual(set(passwords), {'nv-alice', 'nv-bob', 'nv-nfs'})
        self.assertEqual(kvnos, {'nv-alice': 1, 'nv-bob': 2, 'nv-nfs': 255})
        legacy = provision.profile('legacy')
        supplied = dict.fromkeys(legacy['users'], 'synthetic-legacy-only')
        _, kvnos = provision.parse_payload(json.dumps(supplied).encode(), legacy)
        self.assertEqual(kvnos, dict.fromkeys(legacy['users'], 2))
        with self.assertRaises(RuntimeError):
            provision.parse_payload(json.dumps(supplied).encode(), interop)
        with self.assertRaises(RuntimeError):
            provision.parse_payload(json.dumps(credentials()).encode(), legacy)
        with self.assertRaises(RuntimeError):
            provision.profile('arbitrary')

    def test_rejects_unexpected_accounts_types_and_secret_shapes(self):
        bad = [b'', b'[]', b'null', b'"synthetic-private-marker"', b'\xff',
               b'{"synthetic-private-marker":', b'x' * 8193,
               b'{"passwords":{},"passwords":{},"kvnos":{}}']
        for field, value in [('passwords', []), ('kvnos', []), ('extra', 1)]:
            obj = credentials()
            obj[field] = value
            bad.append(json.dumps(obj).encode())
        for value in [True, 0, -1, 256, 2.0, '2', None]:
            obj = credentials()
            obj['kvnos']['nv-nfs'] = value
            bad.append(json.dumps(obj).encode())
        for value in ['', 'short', 'x' * 257, 'synthetic\npassword', 'synthetic\rpassword', 'synthetic\0password', 42]:
            obj = credentials()
            obj['passwords']['nv-alice'] = value
            bad.append(json.dumps(obj).encode())
        for field in ('passwords', 'kvnos'):
            obj = credentials()
            obj[field]['alice'] = obj[field].pop('nv-alice')
            bad.append(json.dumps(obj).encode())
        for data in bad:
            with self.subTest(length=len(data)):
                with self.assertRaises(RuntimeError) as caught:
                    provision.parse_payload(data, provision.profile('interop'))
                self.assertNotIn('synthetic-private-marker', str(caught.exception))
                self.assertNotIn('synthetic-password-only', str(caught.exception))

    def test_duplicate_nested_account_is_refused(self):
        data = json.dumps(credentials()).replace('"nv-alice": "synthetic-password-only"',
                                                 '"nv-alice": "synthetic-password-only", "nv-alice": "other-password-only"')
        with self.assertRaisesRegex(RuntimeError, '^Invalid credential JSON$'):
            provision.parse_payload(data.encode(), provision.profile('interop'))

    def test_preflight_never_reads_stdin_or_creates_credential_directory(self):
        class ForbiddenInput:
            @property
            def buffer(self):
                raise AssertionError('Preflight attempted credential input')

        with tempfile.TemporaryDirectory() as directory:
            selected = provision.profile('interop')
            selected['root'] = pathlib.Path(directory) / 'new-credentials'
            state = {'machine_keytab': 'synthetic-unchanged-metadata'}
            guard = types.SimpleNamespace(snapshot=lambda: state.copy())
            output = io.StringIO()
            with mock.patch.object(provision, 'profile', return_value=selected), \
                    mock.patch.object(provision, 'inspect_prerequisites', return_value=(None, guard, state.copy(), {})), \
                    mock.patch.object(provision.sys, 'stdin', ForbiddenInput()), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(provision.entrypoint(['--profile', 'interop', '--preflight']), 0)
            report = json.loads(output.getvalue())
            self.assertTrue(report['passed'])
            self.assertFalse(report['stdin_read'])
            self.assertEqual(report['before'], report['after'])
            self.assertFalse(selected['root'].exists())
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_invalid_json_cli_failure_does_not_echo_input_or_create_root(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = provision.profile('interop')
            selected['root'] = pathlib.Path(directory) / 'new-credentials'
            stdin = types.SimpleNamespace(buffer=io.BytesIO(b'{"synthetic-private-marker":'))
            output, error = io.StringIO(), io.StringIO()
            with mock.patch.object(provision, 'profile', return_value=selected), \
                    mock.patch.object(provision, 'inspect_prerequisites', return_value=(None, None, {}, {})), \
                    mock.patch.object(provision.sys, 'stdin', stdin), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                self.assertEqual(provision.entrypoint(['--profile', 'interop']), 1)
            self.assertEqual(output.getvalue(), '')
            self.assertNotIn('synthetic-private-marker', error.getvalue())
            self.assertIn('credential-input', error.getvalue())
            self.assertFalse(selected['root'].exists())

    def test_interop_full_flow_keeps_profile_and_uses_actual_kvnos(self):
        # Reproduce the complete orchestration with synthetic native responses.
        # This catches profile/env variable shadowing without invoking a KDC.
        with tempfile.TemporaryDirectory() as directory:
            selected = provision.profile('interop')
            selected['root'] = pathlib.Path(directory) / 'new-credentials'
            supplied = credentials()
            state = {'machine_keytab': 'synthetic-unchanged-metadata'}
            guard = types.SimpleNamespace(snapshot=lambda: state.copy())
            calls, derived = [], []
            tickets = {}

            def native(args, env, data=None, sensitive=False):
                name = pathlib.Path(args[0]).name
                calls.append(name)
                if name == 'ktutil':
                    self.assertTrue(sensitive)
                    user = selected['users'][len(derived)]
                    lines = data.splitlines()
                    for index, enctype in enumerate(provision.ENCTYPES):
                        self.assertEqual(lines[index * 2], 'addent -password -p ' + user + '@' + provision.REALM
                                         + ' -k ' + str(supplied['kvnos'][user]) + ' -e ' + enctype + ' -f')
                        self.assertEqual(lines[index * 2 + 1], supplied['passwords'][user])
                    path = selected['root'] / (user + '.keytab')
                    self.assertEqual(lines[4:], ['wkt ' + str(path), 'quit'])
                    path.write_bytes(b'synthetic-keytab-only')
                    derived.append(user)
                    return ''
                if name == 'klist' and args[1] == '-kte':
                    user = pathlib.Path(args[2]).stem
                    principal = selected['spn'] if user == 'nfs' else user + '@' + provision.REALM
                    kvno = supplied['kvnos']['nv-nfs' if user == 'nfs' else user]
                    return '\n'.join(str(kvno) + ' 01/01/00 00:00:00 ' + principal + ' (' + et + ')'
                                     for et in provision.ENCTYPES)
                if name == 'kinit':
                    self.assertEqual(args[1:3], ['-k', '-t'])
                    self.assertIn(args[4].split('@')[0], derived)
                    conf = pathlib.Path(env['KRB5_CONFIG']).read_text()
                    enctype = next(line.split('=', 1)[1].strip().split()[0] for line in conf.splitlines()
                                   if line.strip().startswith('default_tkt_enctypes'))
                    tickets[env['KRB5CCNAME']] = (args[4], enctype)
                    return ''
                if name == 'klist' and args[1:] == ['-e']:
                    principal, enctype = tickets[env['KRB5CCNAME']]
                    return 'Default principal: ' + principal + '\nEtype (skey, tkt): ' + enctype + ', ' + enctype
                if name == 'keytabalias':
                    self.assertEqual(args[1:], ['-profile', 'interop', '-kvno', '255', '-input',
                                               str(selected['root'] / 'nv-nfs.keytab'), '-output',
                                               str(selected['root'] / 'nfs.keytab')])
                    return 'Synthetic alias validated'
                if name == 'kvno':
                    self.assertEqual(args[1:], ['-k', str(selected['root'] / 'nfs.keytab'), selected['spn']])
                    self.assertIn(tickets[env['KRB5CCNAME']][0], ['nv-alice@MSAD.NFS.TEST', 'nv-bob@MSAD.NFS.TEST'])
                    return selected['spn'] + ': kvno = 255, keytab entry valid'
                self.fail('Unexpected synthetic command')

            tools = {name: '/fixture/' + name for name in ('ktutil', 'kinit', 'klist', 'kvno')}
            output, error = io.StringIO(), io.StringIO()
            stdin = types.SimpleNamespace(buffer=io.BytesIO(json.dumps(supplied).encode()))
            with mock.patch.object(provision, 'profile', return_value=selected), \
                    mock.patch.object(provision, 'inspect_prerequisites', return_value=(None, guard, state.copy(), tools)), \
                    mock.patch.object(provision, 'run', side_effect=native), \
                    mock.patch.object(provision.sys, 'stdin', stdin), \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                self.assertEqual(provision.entrypoint(['--profile', 'interop']), 0, error.getvalue())
            report = json.loads(output.getvalue())
            self.assertTrue(report['passed'])
            self.assertEqual(derived, list(selected['users']))
            self.assertEqual(calls.count('kinit'), 9)
            self.assertEqual(calls.count('keytabalias'), 1)
            self.assertEqual(calls.count('kvno'), 2)
            self.assertEqual(report['kvnos'], supplied['kvnos'])
            self.assertEqual(set(report['service_ticket_checks']), {'nv-alice', 'nv-bob'})
            self.assertEqual(report['before'], report['after'])
            self.assertFalse(report['nfs_validated'])
            self.assertEqual(json.loads((selected['root'] / 'native-evidence.json').read_text()), report)
            self.assertNotIn('synthetic-password-only', output.getvalue())


if __name__ == '__main__':
    unittest.main()
