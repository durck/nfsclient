#!/usr/bin/env python3
"""Read-only checks of the retained tar, boundary snapshot and client logs."""
import hashlib
import json
import pathlib
import re
import sys
import tarfile


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    base = pathlib.Path(sys.argv[1]).resolve()
    reports = {}
    for platform in ('windows', 'linux'):
        log = (base/f'nfsv2-{platform}-interop.log').read_text(encoding='utf-8-sig')
        require('--- FAIL:' not in log and '\nPASS\n' in log, 'Incomplete interop '+platform)
        leaves = re.findall(r'--- PASS: TestNFS2Server/(tcp|udp)/(2|auto)/([^ ]+) ', log)
        require(len(leaves) == 40 and len(set(leaves)) == 40, 'Behavior matrix differs')
        large = re.findall(r'NFS2_LARGE platform='+platform+r' transport=(tcp|udp) bytes=(\d+) sha256=([0-9a-f]+)', log)
        require(len(large) == 2 and {x[0] for x in large} == {'tcp', 'udp'}, 'Large transfer matrix differs')
        # Independent hash of the mathematical pattern, with bounded buffers.
        block = bytes(range(251))*4096
        remaining = (32 << 20)+17
        h = hashlib.sha256()
        while remaining:
            data = block[:min(len(block), remaining)]
            h.update(data)
            remaining -= len(data)
        require(all(int(n) == (32 << 20)+17 and digest == h.hexdigest() for _, n, digest in large), 'Large stream digest differs')
        reports[platform] = dict(behavior_leaves=40, large_transports=2, large_bytes=(32 << 20)+17, large_sha256=h.hexdigest())
    linux = (base/'nfsv2-linux-interop.log').read_text(encoding='utf-8-sig')
    require(all('--- PASS: TestNFS2ServerDiscovery/'+transport in linux for transport in ('tcp', 'udp')), 'Real rpcbind discovery missing')
    for name, expected in [('windows-cli', 4), ('windows-release', 4), ('linux-cli-release', 8)]:
        log = (base/('nfsv2-'+name+'.log')).read_text(encoding='utf-8-sig')
        require('--- FAIL:' not in log and '--- SKIP:' not in log and log.count('NFS2_CLI selection=') == expected and '\nPASS\n' in log, 'CLI matrix differs: '+name)
    payload = b'independent-v2\x00'*32768
    with tarfile.open(base/'nfsv2-retained.tar') as archive:
        members = {m.name.rstrip('/'): m for m in archive.getmembers()}
        require(not any('.nfs-upload-' in name for name in members), 'Retained staging objects')

        def check(name, expected, uid, gid, mode):
            m = members[name]
            require(m.isfile() and (m.uid, m.gid, m.mode) == (uid, gid, mode), 'Metadata differs: '+name)
            require(archive.extractfile(m).read() == expected, 'Retained bytes differ: '+name)

        for platform in ('windows', 'linux'):
            for version in ('2', 'auto'):
                for transport in ('tcp', 'udp'):
                    name = f'v2-{platform}-{version}-{transport}'
                    check('data/'+name+'/binary', payload, 20001, 20001, 0o600)
                    check('data/'+name+'/race', b'winner', 20001, 20001, 0o640)
                    require({p.rsplit('/', 1)[1] for p in members if p.startswith('data/'+name+'/')} == {'binary', 'race'}, 'Unexpected workspace object')
                    check('squashed/'+name, b'squashed', 65534, 65534, 0o600)
        cli = [p for p in members if re.fullmatch(r'data/cli-(tcp|udp)-(2|auto)-\d+/binary', p)]
        require(len(cli) == 16, 'Retained CLI results differ')
        for name in cli:
            check(name, b'real-v2-shell\x00'*8192, 20001, 20001, 0o644)
        check('data/public.txt', b'NFSv2 fixture\n', 0, 0, 0o644)
        check('data/private.txt', b'private-alice\n', 20001, 20001, 0o600)
        check('data/group.txt', b'shared-group\n', 0, 20003, 0o640)
        check('readonly/seed', b'read-only-seed\n', 0, 0, 0o644)
        require({p for p in members if p.startswith('readonly/')} == {'readonly/seed'}, 'Read-only export changed')
    boundary = (base/'nfsv2-boundary.txt').read_text().splitlines()
    require(boundary[0].split()[:2] == ['/data/boundary.bin', '2147483647'] and boundary[1].split()[:2] == ['/data/too-large.bin', '2147483648'], 'Boundary fixture size differs')
    require(boundary[2:] == ['tmpfs', 'V2-END'], 'Boundary tail/filesystem differs')
    print(json.dumps(dict(passed=True, platforms=reports, cli_profiles=16, rpcbind_transports=2, retained_policy_bytes=True, sparse_boundary=True, complete_2gib_transfer=False), indent=2))


if __name__ == '__main__':
    main()
