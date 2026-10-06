"""Provision only the disposable container's synthetic directory, never a host."""
import logging
import os
import re
from pathlib import Path

import ldb
from samba import generate_random_password
from samba.auth import system_session
from samba.provision import provision

os.umask(0o077)
target = Path('/run/nfs-ad')
if target.exists():
    raise SystemExit('Refusing to reprovision an existing fixture directory')
target.mkdir()
result = provision(
    logging.getLogger('fixture'), system_session(), targetdir=str(target),
    realm='AD.NFS.TEST', domain='NFSLAB', hostname='dc',
    serverrole='active directory domain controller', dns_backend='NONE',
    adminpass=generate_random_password(48, 64), skip_sysvolacl=True,
)
# This KDC/LDAP fixture does not serve SMB, SYSVOL or DNS and needs no privileged
# container. Skip SYSVOL ACL setup instead of granting host filesystem powers.
conf = target / 'etc/smb.conf'
text = re.sub(r'(?m)^\s*server services =.*$', '\tserver services = ldap, cldap, kdc', conf.read_text())
text = text.replace('[global]', '[global]\n\tkerberos encryption types = strong')
conf.write_text(text)
db = result.samdb
for user in ('alice', 'bob', 'disabled', 'nfs-service'):
    db.newuser(user, generate_random_password(48, 64))
    rows = db.search(expression=f'(sAMAccountName={user})', attrs=['dn'])
    change = ldb.Message()
    change.dn = rows[0].dn
    change['msDS-SupportedEncryptionTypes'] = ldb.MessageElement('24', ldb.FLAG_MOD_REPLACE, 'msDS-SupportedEncryptionTypes')
    if user == 'nfs-service':
        change['servicePrincipalName'] = ldb.MessageElement('nfs/server.ad.nfs.test', ldb.FLAG_MOD_REPLACE, 'servicePrincipalName')
        change['userPrincipalName'] = ldb.MessageElement('nfs/server.ad.nfs.test@AD.NFS.TEST', ldb.FLAG_MOD_REPLACE, 'userPrincipalName')
    db.modify(change)
print('Synthetic Samba AD provisioned; AES128/AES256 accounts and NFS SPN ready')
