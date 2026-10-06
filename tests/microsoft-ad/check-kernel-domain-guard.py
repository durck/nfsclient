#!/usr/bin/python3
"""Exercise real runner guards with mocked paths/processes; never touch a VM."""
import ast
import contextlib
import json
import pathlib
import stat
import subprocess
import types
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
BASE = ast.parse((HERE / 'run-kernel-nfs.py').read_text())
GSS = ast.parse((HERE / 'run-kernel-gss.py').read_text())
GOOD_UNIT = 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\n'
UNIT_ARGS = ['systemctl', 'show', 'sssd.service', '--property=LoadState,ActiveState,SubState,MainPID']
PROCESS_ARGS = ['pgrep', '-x', 'sssd|sssd_.*']
INDICATORS = ('/etc/krb5.keytab', '/etc/sssd/sssd.conf', '/var/lib/nfs-viewer-msad/domain-joined.json')


def load_functions(tree, names, namespace):
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in selected} != set(names):
        raise AssertionError('Requested production function is missing')
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<runner-guard>', 'exec'), namespace)
    return namespace


class Fixture:
    def __init__(self):
        self.paths = {}
        self.children = []
        self.unit = subprocess.CompletedProcess(UNIT_ARGS, 0, GOOD_UNIT, '')
        self.processes = subprocess.CompletedProcess(PROCESS_ARGS, 1, '', '')
        self.calls = []
        self.reads = []

    def lstat(self, path, *args, **kwargs):
        value = self.paths.get(path.as_posix())
        if value is None:
            raise FileNotFoundError(str(path))
        if isinstance(value, Exception):
            raise value
        return types.SimpleNamespace(st_mode=value)

    def iterdir(self, path):
        if path.as_posix() != '/etc/sssd/conf.d':
            raise AssertionError('Unexpected directory enumeration')
        if isinstance(self.children, Exception):
            raise self.children
        return iter(path / name for name in self.children)

    def run(self, args, **kwargs):
        self.calls.append(args)
        if kwargs != {'text': True, 'capture_output': True, 'timeout': 5}:
            raise AssertionError('Guard subprocess must be bounded and read-only')
        if args == UNIT_ARGS:
            result = self.unit
        elif args == PROCESS_ARGS:
            result = self.processes
        else:
            raise AssertionError('Unexpected subprocess; mutation prohibited: ' + repr(args))
        if isinstance(result, Exception):
            raise result
        return result

    def read_text(self, path, *args, **kwargs):
        self.reads.append(path.as_posix())
        values = {'/sys/class/dmi/id/sys_vendor': 'VMware, Inc.\n',
                  '/sys/class/dmi/id/product_name': 'VMware20,1\n',
                  '/var/lib/nfs-lab-packages.json': json.dumps({'stage': 'offline-packages-installed-services-inactive'})}
        if path.as_posix() not in values:
            raise AssertionError('Credential/config contents must not be read')
        return values[path.as_posix()]

    def command(self, *args, **kwargs):
        if args == ('hostname', '-f'):
            return 'nfs.msad.nfs.test'
        if args == ('dpkg', '--print-architecture'):
            return 'amd64'
        raise AssertionError('Unexpected setup command; mutation prohibited: ' + repr(args))

    @contextlib.contextmanager
    def patched(self):
        with contextlib.ExitStack() as stack:
            for name, replacement in [('lstat', self.lstat), ('iterdir', self.iterdir), ('read_text', self.read_text)]:
                stack.enter_context(mock.patch.object(pathlib.Path, name, autospec=True, side_effect=replacement))
            stack.enter_context(mock.patch.object(pathlib.Path, 'is_file', return_value=True))
            for name in ('write_text', 'write_bytes', 'mkdir', 'chmod', 'rename', 'unlink', 'open'):
                stack.enter_context(mock.patch.object(pathlib.Path, name, side_effect=AssertionError('Filesystem mutation prohibited')))
            stack.enter_context(mock.patch.object(subprocess, 'run', side_effect=self.run))
            stack.enter_context(mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('Process launch prohibited')))
            yield

    def functions(self):
        base = load_functions(BASE, ('reject_domain_state', 'entry_gate', 'execute'),
                              {'pathlib': pathlib, 'subprocess': subprocess, 'stat': stat, 'json': json,
                               'platform': types.SimpleNamespace(system=lambda: 'Linux'), 'command': self.command})
        guard = types.SimpleNamespace(reject_domain_state=base['reject_domain_state'])
        gss = load_functions(GSS, ('inspect_empty_guest', 'claim_empty_guest', 'execute_auth_sys', 'execute'),
                             {'base': guard, 'command': self.command})
        return base, gss


class DomainGuardTests(unittest.TestCase):
    def rejects_every_boundary(self, fixture):
        base, gss = fixture.functions()
        boundaries = [('entry_gate', lambda evidence: base['entry_gate']()),
                      ('base.execute', base['execute']), ('inspect_empty_guest', gss['inspect_empty_guest']),
                      ('claim_empty_guest', lambda evidence: gss['claim_empty_guest'](evidence, True)),
                      ('execute_auth_sys', gss['execute_auth_sys']), ('execute_gss', gss['execute'])]
        for name, boundary in boundaries:
            with self.subTest(boundary=name), fixture.patched():
                evidence = {}
                with self.assertRaisesRegex(SystemExit, 'Refusing synthetic kernel fixture:'):
                    boundary(evidence)
                self.assertEqual(evidence, {})
                self.assertEqual(fixture.reads, [])

    def test_all_indicator_types_refuse_without_opening_credentials(self):
        for path in INDICATORS:
            for mode in (stat.S_IFREG, stat.S_IFLNK, stat.S_IFDIR):
                with self.subTest(path=path, mode=mode):
                    fixture = Fixture()
                    fixture.paths[path] = mode
                    self.rejects_every_boundary(fixture)
                    self.assertEqual(fixture.calls, [])

    def test_unreadable_or_uninspectable_indicators_refuse(self):
        for path in INDICATORS:
            for failure in (PermissionError('private'), OSError('I/O error')):
                with self.subTest(path=path, failure=type(failure).__name__):
                    fixture = Fixture()
                    fixture.paths[path] = failure
                    self.rejects_every_boundary(fixture)

    def test_sssd_config_fragments_refuse(self):
        for mode, children in ((stat.S_IFDIR, ['domain.conf']), (stat.S_IFDIR, ['.domain.conf']),
                               (stat.S_IFDIR, PermissionError('private')), (stat.S_IFLNK, []),
                               (PermissionError('private'), [])):
            with self.subTest(mode=mode, children=children):
                fixture = Fixture()
                fixture.paths['/etc/sssd/conf.d'], fixture.children = mode, children
                self.rejects_every_boundary(fixture)

    def test_unsafe_or_ambiguous_service_state_refuses(self):
        cases = [GOOD_UNIT.replace('inactive', state) for state in ('active', 'activating', 'deactivating', 'reloading', 'failed')]
        cases += [GOOD_UNIT.replace('MainPID=0', 'MainPID=44'), GOOD_UNIT.replace('SubState=dead', 'SubState=running'),
                  GOOD_UNIT.replace('LoadState=loaded', 'LoadState=error'), '', GOOD_UNIT + 'MainPID=0\n',
                  GOOD_UNIT.replace('MainPID=0\n', ''), GOOD_UNIT + 'unexpected\n']
        for output in cases:
            with self.subTest(output=output):
                fixture = Fixture()
                fixture.unit.stdout = output
                self.rejects_every_boundary(fixture)

    def test_running_unmanaged_sssd_and_probe_failures_refuse(self):
        for source, result in [('processes', subprocess.CompletedProcess(PROCESS_ARGS, 0, '123\n', '')),
                               ('processes', subprocess.CompletedProcess(PROCESS_ARGS, 1, 'unexpected\n', '')),
                               ('processes', subprocess.CompletedProcess(PROCESS_ARGS, 2, '', 'invalid')),
                               ('unit', subprocess.CompletedProcess(UNIT_ARGS, 1, GOOD_UNIT, 'failed')),
                               ('unit', FileNotFoundError('systemctl')),
                               ('unit', subprocess.TimeoutExpired(UNIT_ARGS, 5)),
                               ('processes', FileNotFoundError('pgrep')),
                               ('processes', subprocess.TimeoutExpired(PROCESS_ARGS, 5))]:
            with self.subTest(source=source, result=result):
                fixture = Fixture()
                setattr(fixture, source, result)
                self.rejects_every_boundary(fixture)

    def test_empty_non_domain_fixture_retains_existing_entry_gate(self):
        for load in ('loaded', 'masked', 'not-found'):
            with self.subTest(load=load):
                fixture = Fixture()
                fixture.unit.stdout = GOOD_UNIT.replace('loaded', load)
                fixture.paths['/etc/sssd/conf.d'] = stat.S_IFDIR
                fixture.children = ['README']
                base, _ = fixture.functions()
                with fixture.patched():
                    base['entry_gate']()
                self.assertEqual(fixture.calls, [UNIT_ARGS, PROCESS_ARGS])
                self.assertEqual(len(fixture.reads), 3)

    def test_main_guard_precedes_cleanup_evidence_and_poweroff_scope(self):
        for tree, expression in ((BASE, 'entry_gate()'), (GSS, 'base.entry_gate()')):
            main = next(node for node in tree.body if isinstance(node, ast.If) and '__name__' in ast.unparse(node.test))
            self.assertIsInstance(main.body[0], ast.Expr)
            self.assertEqual(ast.unparse(main.body[0].value), expression)


if __name__ == '__main__':
    unittest.main(verbosity=2)
