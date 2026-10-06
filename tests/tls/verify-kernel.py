#!/usr/bin/env python3
"""Independently verify retained kernel TLS files and restoration in the guest."""
import collections
import hashlib
import json
import pathlib
import re
import subprocess
import sys


def main():
    run = pathlib.Path(sys.argv[1]).resolve()
    if run.parent != pathlib.Path('/var/lib/nfs-viewer-msad/runs') or not run.name.startswith('tls-'):
        raise ValueError('Dedicated completed TLS run required')
    evidence = json.loads((run/'evidence.json').read_text())
    assert evidence['passed'] and evidence['domain_preserved']
    assert evidence['before'] == evidence['after'] and evidence['services_before'] == evidence['services_after']
    assert 'xprtsec=tls' in evidence['exports'] and evidence['alpn_fixture_build']
    counters = lambda text: {line.split()[0]: int(line.split()[1]) for line in text.splitlines()}
    before, after = counters(evidence['tls_before']), counters(evidence['tls_after'])
    assert after['TlsTxSw'] > before['TlsTxSw'] and after['TlsRxSw'] > before['TlsRxSw']
    counts = collections.Counter()
    payloads = {'api': b'real-kernel-tls\x00'*65536, 'cli': b'tls-shell\x00'*65536}
    files = []
    root = run/'tree/data'
    for p in root.iterdir():
        if p.name == 'seed':
            assert p.read_bytes() == b'kernel RPC-with-TLS fixture\n'
            continue
        m = re.fullmatch(r'tls-(api|cli)-(windows|linux)-(4\.[012])-(trusted-ip|trusted-dns|trusted|insecure)-(\d+)', p.name)
        assert m, p.name
        kind, platform, version, policy, _ = m.groups()
        counts[kind, platform, version, policy] += 1
        if kind == 'cli':
            assert {f.name for f in p.iterdir()} == {'binary'}
            p = p/'binary'
        s = p.lstat()
        assert p.is_file() and not p.is_symlink() and (s.st_uid, s.st_gid, s.st_mode & 0o7777) == (25001, 25000, 0o644), p
        content = p.read_bytes()
        assert content == payloads[kind], p
        files.append(dict(path=str(p.relative_to(run/'tree')), bytes=len(content), sha256=hashlib.sha256(content).hexdigest(), uid=s.st_uid, gid=s.st_gid, mode=oct(s.st_mode & 0o7777)))
    expected = {}
    for platform in ('windows', 'linux'):
        for version in ('4.0', '4.1', '4.2'):
            for policy in ('trusted-ip', 'trusted-dns', 'insecure'):
                expected['api', platform, version, policy] = 1
            for policy in ('trusted', 'insecure'):
                expected['cli', platform, version, policy] = 2
    assert dict(counts) == expected
    assert not subprocess.check_output(['exportfs', '-v']).strip()
    assert not pathlib.Path('/etc/exports.d/nfs-viewer-tls.exports').exists()
    assert not pathlib.Path('/etc/nfs.conf.d/99-nfs-viewer-tls.conf').exists()
    assert not pathlib.Path('/srv/nfs-viewer-tls').exists()
    assert subprocess.run(['pgrep', '-x', 'tlshd-alpn'], capture_output=True).returncode == 1
    print(json.dumps(dict(passed=True, files=files, kernel_tls_tx=after['TlsTxSw']-before['TlsTxSw'], kernel_tls_rx=after['TlsRxSw']-before['TlsRxSw'], domain_preserved=True, services_restored=True), indent=2))


if __name__ == '__main__':
    main()
