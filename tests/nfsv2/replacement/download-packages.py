"""Download only package files selected by apt from a signature-verified index.
Run apt update against the local signed repository before using this helper.
"""
import pathlib,lzma,re,urllib.parse,urllib.request,hashlib,concurrent.futures,json,sys
root=pathlib.Path(sys.argv[1])
index={}
for block in lzma.decompress((root/'dists/bookworm/main/binary-amd64/Packages.xz').read_bytes()).decode().split('\n\n'):
 fields=dict(line.split(': ',1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
 if 'Filename' in fields:index[fields['Filename']]=fields
paths=[urllib.parse.unquote(x) for x in re.findall(r"'file:/repo/([^']+)'",'\n'.join(p.read_text() for p in root.glob('*package-plan.txt')))]
assert paths

def fetch(name):
 assert name.startswith('pool/') and '..' not in pathlib.PurePosixPath(name).parts
 spec=index[name];dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True)
 if dest.exists(): data=dest.read_bytes()
 else:
  with urllib.request.urlopen('https://deb.debian.org/debian/'+urllib.parse.quote(name,safe='/+'),timeout=120) as response:data=response.read()
 assert len(data)==int(spec['Size']) and hashlib.sha256(data).hexdigest()==spec['SHA256'],name
 dest.write_bytes(data)
 return {'path':name,'sha256':spec['SHA256'],'size':len(data)}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
 result=list(pool.map(fetch,paths))
(root/'verified-packages.json').write_text(json.dumps(result,indent=2))
print('Verified packages:',len(result),'bytes:',sum(x['size'] for x in result))
