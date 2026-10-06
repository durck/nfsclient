#!/usr/bin/python3
"""Expose only non-secret SSH/bootstrap facts through the private guest serial port."""
import datetime
import json
import os
import pathlib
import subprocess


def output(*args):
    return subprocess.check_output(args, text=True, timeout=15).strip()


def service_state(name):
    result = subprocess.run(['systemctl', 'is-active', name], text=True, capture_output=True, timeout=15)
    if result.returncode not in (0, 3):
        raise RuntimeError('Cannot inspect management service: ' + name)
    return result.stdout.strip()


def main():
    if os.geteuid() != 0 or output('hostname', '-f') != 'nfs.msad.nfs.test':
        raise RuntimeError('Unexpected management guest identity')
    if pathlib.Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'VMware, Inc.':
        raise RuntimeError('Expected the dedicated VMware guest')
    routes = json.loads(output('ip', '-4', '-j', 'route')) + json.loads(output('ip', '-6', '-j', 'route'))
    if any(route.get('dst') == 'default' for route in routes):
        raise RuntimeError('Unexpected default route')
    public_key = pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip().split()
    if len(public_key) < 2 or public_key[0] != 'ssh-ed25519':
        raise RuntimeError('Missing Ed25519 host public key')
    evidence = {
        'stage': 'msad-management-ready',
        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'hostname': output('hostname', '-f'),
        'kernel': output('uname', '-r'),
        'addresses': json.loads(output('ip', '-j', 'address')),
        'routes': routes,
        'ssh_host_public_key': ' '.join(public_key[:2]),
        'ssh_fingerprint': output('ssh-keygen', '-lf', '/etc/ssh/ssh_host_ed25519_key.pub'),
        'ssh_service': service_state('ssh.service'),
        'ssh_socket': service_state('ssh.socket'),
        'labadmin': output('getent', 'passwd', 'labadmin'),
        'domain_marker_present': pathlib.Path('/var/lib/nfs-viewer-msad/domain-joined.json').exists(),
        'machine_keytab_present': pathlib.Path('/etc/krb5.keytab').exists(),
    }
    directory = pathlib.Path('/var/lib/nfs-viewer-msad')
    directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / 'management.json'
    destination.write_text(json.dumps(evidence, sort_keys=True) + '\n')
    destination.chmod(0o600)
    with open('/dev/ttyS0', 'w') as serial:
        serial.write('NFS_LAB_MANAGEMENT_EVIDENCE ' + json.dumps(evidence, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
