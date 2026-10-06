"""Actual networkless-container package install and local MIT ticket issuance."""
import importlib.util
import argparse
import json
import os
import pathlib
import subprocess

if not pathlib.Path('/.dockerenv').is_file():
    raise SystemExit('This check requires a disposable Docker container')
parser = argparse.ArgumentParser()
parser.add_argument('--proxy', action='store_true')
args = parser.parse_args()
os.umask(0o077)
spec = importlib.util.spec_from_file_location('gss_fixture', '/scripts/run-kernel-gss.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
policy = pathlib.Path('/usr/sbin/policy-rc.d')
if policy.read_text() != '#!/bin/sh\nexit 101\n':
    raise SystemExit('Unexpected container package policy')
policy.unlink()
output = pathlib.Path('/tmp/gss-package-check')
output.mkdir(mode=0o700)
try:
    installed = fixture.ensure_packages(output, pathlib.Path('/bundle'), pathlib.Path('/scripts/verify-linux-bundle.py'), args.proxy)
    print(json.dumps(installed, indent=2))
    if args.proxy:
        extra = pathlib.Path('/etc/gssproxy/99-foreign.conf')
        extra.write_text('[service/foreign]\n')
        evidence = {}
        try:
            fixture.stop_packaged_proxy(evidence)
        except ValueError as error:
            assert 'configuration inventory' in str(error) and not evidence
        else:
            raise AssertionError('Foreign proxy configuration was accepted')
        finally:
            extra.unlink()
        config = pathlib.Path('/etc/gssproxy/24-nfs-server.conf')
        original = config.read_bytes()
        config.write_bytes(original + b'\n')
        try:
            fixture.stop_packaged_proxy(evidence)
        except ValueError as error:
            assert 'differs from authenticated Ubuntu payload' in str(error) and not evidence
        else:
            raise AssertionError('Modified package configuration was accepted')
        finally:
            config.write_bytes(original)
        print('Packaged-proxy takeover rejected foreign/modified configuration before service mutation')
    credentials = fixture.setup_credentials(output)
    print(json.dumps(credentials, indent=2))
    if args.proxy:
        for protected in fixture.PROXY_PATHS:
            protected.write_text('owned-negative-check\n')
            try:
                fixture.start_proxy(output, kernel=False)
            except ValueError as error:
                assert 'Refusing existing gssproxy runtime' in str(error)
                assert protected.read_text() == 'owned-negative-check\n'
            else:
                raise AssertionError('Pre-existing proxy path was accepted')
            finally:
                protected.unlink()
        print('Proxy pre-existing socket/PID negative guards passed without overwriting sentinels')
        process = fixture.start_proxy(output, kernel=False)
        assert process.poll() is None
        print(subprocess.check_output(['gssproxy', '--version'], text=True))
        print('Proxy foreground socket/PID/config readiness passed; container cannot prove kernel registration')
    print(subprocess.check_output(['ss', '-H', '-lntu'], text=True))
finally:
    fixture.stop_credentials()
    fixture.remove_proxy_runtime()
assert not fixture.SECRET.exists()
assert all(process.poll() is not None for process in fixture.PROCESSES)
assert all(not path.exists() and not path.is_symlink() for path in fixture.PROXY_PATHS)
print('NFS_LAB_OFFLINE_KDC_CHECK_COMPLETE: authenticated offline install, TGT, service-ticket decrypt, credential cleanup passed')
