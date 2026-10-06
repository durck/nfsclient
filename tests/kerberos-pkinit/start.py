"""Disposable MIT PKINIT realm; generate all private material at runtime."""
from pathlib import Path
import os, subprocess

p=Path('/run/nfs-test');p.mkdir(mode=0o700,parents=True,exist_ok=True)
os.umask(0o077)
def run(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def authority(name):
    run('openssl','req','-new','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2','-subj','/CN='+name,'-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(p/(name+'.key')),'-out',str(p/(name+'.crt')))
authority('ca');authority('other-ca')
def certificate(name,components,eku,days='1'):
    principal='\n'.join('name'+str(i)+'=GeneralString:'+v for i,v in enumerate(components))
    ext='[cert]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+eku+'\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\nsubjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:identity\n[identity]\nrealm=EXP:0,GeneralString:NFS.TEST\nprincipal=EXP:1,SEQUENCE:principal\n[principal]\ntype=EXP:0,INTEGER:'+('2' if len(components)==2 else '1')+'\nnames=EXP:1,SEQUENCE:names\n[names]\n'+principal+'\n'
    (p/(name+'.conf')).write_text(ext)
    run('openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN='+name,'-keyout',str(p/(name+'.key')),'-out',str(p/(name+'.req')))
    expiry=['-not_before','20200101000000Z','-not_after','20200102000000Z'] if days=='expired' else ['-days',days]
    run('openssl','x509','-req','-sha256','-in',str(p/(name+'.req')),'-CA',str(p/'ca.crt'),'-CAkey',str(p/'ca.key'),'-CAcreateserial',*expiry,'-extfile',str(p/(name+'.conf')),'-extensions','cert','-out',str(p/(name+'.crt')))
certificate('kdc',['krbtgt','NFS.TEST'],'1.3.6.1.5.2.3.5')
certificate('client',['root'],'1.3.6.1.5.2.3.4')
certificate('foreign',['alice'],'1.3.6.1.5.2.3.4')
certificate('expired',['root'],'1.3.6.1.5.2.3.4','expired')
(p/'index').touch();(p/'crlnumber').write_text('01\n')
(p/'ca.conf').write_text('[ca]\ndefault_ca=local\n[local]\ndatabase=/run/nfs-test/index\nprivate_key=/run/nfs-test/ca.key\ncertificate=/run/nfs-test/ca.crt\ncrlnumber=/run/nfs-test/crlnumber\ndefault_md=sha256\ndefault_crl_days=1\n')
run('openssl','ca','-config',str(p/'ca.conf'),'-gencrl','-out',str(p/'clean.crl'))
run('openssl','ca','-config',str(p/'ca.conf'),'-revoke',str(p/'kdc.crt'))
run('openssl','ca','-config',str(p/'ca.conf'),'-gencrl','-out',str(p/'revoked.crl'))
(p/'kdc.conf').write_text('[realms]\n NFS.TEST = {\n  database_name = /run/nfs-test/principal\n  key_stash_file = /run/nfs-test/stash\n  pkinit_identity = FILE:/run/nfs-test/kdc.crt,/run/nfs-test/kdc.key\n  pkinit_anchors = FILE:/run/nfs-test/ca.crt\n  pkinit_require_freshness = true\n }\n')
os.environ.update(KRB5_CONFIG='/work/tests/kerberos/krb5.conf',KRB5_KDC_PROFILE='/run/nfs-test/kdc.conf')
master=os.urandom(32).hex()
run('kdb5_util','create','-s','-P',master);del master
run('kadmin.local','-q','addprinc +requires_preauth -nokey root@NFS.TEST')
run('kadmin.local','-q','addprinc -randkey -e aes256-cts-hmac-sha1-96:normal nfs/server.nfs.test@NFS.TEST')
run('kadmin.local','-q','modprinc -maxlife "4 seconds" nfs/server.nfs.test@NFS.TEST')
run('kadmin.local','-q','ktadd -norandkey -k /run/nfs-test/server.keytab nfs/server.nfs.test@NFS.TEST')
os.execvp('krb5kdc',['krb5kdc','-n'])
