"""Disposable native Ganesha/LizardFS Kerberos backchannel capability probe."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

os.umask(0o077)
root = Path('/run/nfs-test')
root.mkdir(parents=True, exist_ok=True)
Path('/lab').mkdir(exist_ok=True)
if subprocess.check_output(['stat', '-f', '-c', '%T', str(root)], text=True).strip() != 'tmpfs':
    raise SystemExit('disposable credential tmpfs required')
conf = '''[libdefaults]
 default_realm = NFS.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 udp_preference_limit = 1
[realms]
 NFS.TEST = {
  kdc = 127.0.0.1:88
 }
'''
Path('/etc/krb5.conf').write_text(conf, encoding='utf-8')
profile = root / 'kdc.conf'
profile.write_text('''[realms]
 NFS.TEST = {
  database_name = /run/nfs-test/principal
  key_stash_file = /run/nfs-test/stash
 }
''', encoding='utf-8')
os.environ['KRB5_KDC_PROFILE'] = str(profile)


def quiet(args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


quiet(['kdb5_util', 'create', '-s', '-P', os.urandom(32).hex()])
for principal, keytab in [('root@NFS.TEST', root / 'client.keytab'),
                          ('nfs/server.nfs.test@NFS.TEST', Path('/etc/krb5.keytab'))]:
    quiet(['kadmin.local', '-q', 'addprinc -randkey -e aes256-cts-hmac-sha1-96:normal ' + principal])
    quiet(['kadmin.local', '-q', f'ktadd -norandkey -k {keytab} {principal}'])

# Reuse the retained storage/configuration recipe without editing its AUTH_SYS
# default. This probe needs only the native MDS root, not data-server traffic.
base = Path('/work/tests/pnfs/lizardfs/start-node.sh').read_text(encoding='utf-8')
old = 'NFS_KRB5 { Active_krb5 = false; }'
assert base.count(old) == 1 and base.count(' SecType = sys;') == 1
base = base.replace(old, 'NFS_KRB5 { Active_krb5 = true; PrincipalName = "nfs"; KeytabPath = "/etc/krb5.keytab"; }')
base = base.replace(' SecType = sys;', ' SecType = krb5i, krb5p;')
script = root / 'mds.sh'
script.write_text(base, encoding='utf-8')
os.environ.update(LAB_SUBNET='127.0.0.0/8', LAB_MASTER='127.0.0.1')
children = []


def stop(signum, frame):
    for child in children:
        if child.poll() is None:
            child.terminate()
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
log = (root / 'process.log').open('wb')
children.append(subprocess.Popen(['krb5kdc', '-n'], stdout=log, stderr=log))
children.append(subprocess.Popen(['sh', str(script), 'mds'], stdout=log, stderr=log))
deadline = time.monotonic() + 40
while time.monotonic() < deadline:
    if any(child.poll() is not None for child in children):
        raise SystemExit('native fixture exited before readiness')
    try:
        with socket.create_connection(('127.0.0.1', 2049), timeout=0.2):
            pass
        quiet(['kinit', '-k', '-t', str(root / 'client.keytab'), '-c', 'FILE:' + str(root / 'probe.ccache'), 'root@NFS.TEST'])
        (root / 'ready').write_text('READY\n', encoding='utf-8')
        break
    except (OSError, subprocess.CalledProcessError):
        time.sleep(0.1)
else:
    raise SystemExit('native fixture readiness timeout')
while all(child.poll() is None for child in children):
    time.sleep(0.2)
raise SystemExit('native fixture process exited')
