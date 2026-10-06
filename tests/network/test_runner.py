import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('network_runner', pathlib.Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerCleanupTests(unittest.TestCase):
    def test_timeout_stops_client_before_server_and_preserves_failure(self):
        calls = []
        failure = subprocess.TimeoutExpired('docker run client', 600)

        def command(args, **kwargs):
            calls.append(args)
            if args[:2] == ['docker', 'inspect']:
                return json.dumps([{'Image': 'fixture', 'NetworkSettings': {'Networks': {'bridge': {'IPAddress': '172.17.0.9'}}}}])
            return '/test/cache'

        def run(args, **kwargs):
            calls.append(args)
            if args[:2] == ['docker', 'run']:
                raise failure
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(runner, 'ROOT', pathlib.Path(temporary)), \
             patch.object(runner, 'command', side_effect=command), \
             patch.object(runner.subprocess, 'run', side_effect=run), \
             patch('sys.argv', ['run.py', '--target', 'linux']), \
             patch.object(runner.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value = io.StringIO('{}')
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                runner.main()
            self.assertIs(caught.exception, failure)
        stops = [args[-1] for args in calls if args[:2] == ['docker', 'stop']]
        self.assertEqual(len(stops), 2, 'both owned containers must be stopped after client timeout')
        self.assertEqual(stops[0], stops[1] + '-client')


if __name__ == '__main__':
    unittest.main()
