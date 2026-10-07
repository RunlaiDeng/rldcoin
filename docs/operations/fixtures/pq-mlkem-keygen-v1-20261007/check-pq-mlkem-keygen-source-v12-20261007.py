from pathlib import Path
import json,hashlib,time,datetime,os,urllib.request
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin')
b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';name='pq-mlkem-keygen-source-v12-20261007'
root=b/(name+'-private');out=e/(name+'-checks.json');assert not root.exists() and not out.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
core=json.loads((e/'core-hybrid-quorum-integrated-v11-20261007-core-source.json').read_bytes())
protected={str(r/v['path']):v['sha256'] for v in core['files']}
for p in [Path(__file__),r/'tools/fixtures/pq-tls-candidate/transport.c',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json']:protected[str(p)]=sha(p)
def pins():assert all(sha(Path(p))==h for p,h in protected.items())
pins();start=time.monotonic();deadline=start+30;mask=os.umask(0o077);root.mkdir(mode=0o700)
files=[];error=None;commit='a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324'
try:
 for n in ('prompt.json','expectedResults.json'):
  url='https://raw.githubusercontent.com/usnistgov/ACVP-Server/'+commit+'/gen-val/json-files/ML-KEM-keyGen-FIPS203/'+n
  with urllib.request.urlopen(url,timeout=max(.01,deadline-time.monotonic())) as response:
   assert response.status==200 and response.url==url
   raw=response.read(8*1024*1024+1);assert len(raw)<=8*1024*1024
  doc=json.loads(raw);assert doc['algorithm']=='ML-KEM' and doc['mode']=='keyGen' and doc['revision']=='FIPS203'
  p=root/n;p.write_bytes(raw);files.append(dict(path=str(p.relative_to(r)),sha256=sha(p),bytes=len(raw),url=url))
 assert [g['parameterSet'] for g in doc['testGroups']]==['ML-KEM-512','ML-KEM-768','ML-KEM-1024']
 pins();assert time.monotonic()<=deadline
except BaseException as ex:error=type(ex).__name__+': '+str(ex)[:200]
finally:os.umask(mask)
duration=round(time.monotonic()-start,6)
out.write_text(json.dumps(dict(format='RLD-PQ-MLKEM-KEYGEN-SOURCE-V12',completed=error is None,duration_seconds=duration,budget_seconds=30,attempts=1,error=error,commit=commit,files=files,protected_sha256=protected,controller_sha256=sha(Path(__file__)),source_only=True,key_generation_calls=0,cryptographic_qualification=False,Native_Runtime_Node_calls=0,whole_goal_completed=False),indent=2)+'\n')
print(json.dumps(dict(completed=error is None,duration_seconds=duration,error=error,files=[{'bytes':x['bytes'],'sha256':x['sha256']} for x in files])))
raise SystemExit(0 if error is None else 1)
