from pathlib import Path
import urllib.request,hashlib,json,time,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';name='pq-nist-external-source-v4-20261007';root=b/(name+'-public');stagep=e/(name+'-stage.json');out=e/(name+'-checks.json');assert not any(p.exists() for p in (root,stagep,out));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();protected={str(p):sha(p) for p in [Path(__file__),r/'tools/pq_authorization_candidate.py',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',e/'core-era-integrated-v11-20261007-checks.json',e/'pq-hybrid-cross-v3-20261007-checks.json']};core=json.loads((e/'core-era-integrated-v11-20261007-core-source.json').read_text());protected.update({str(r/v['path']):v['sha256'] for v in core['files']})
def pins():assert all(sha(Path(p))==h for p,h in protected.items())
stage=dict(format='RLD-PQ-NIST-EXTERNAL-SOURCE-V4',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=30,attempts=1,hypothesis='NIST official current sigVer-FIPS204 source has external pure ML-DSA-87 tests compatible with public API; old crate bundled vectors use internal interface and cannot qualify candidate external encoding.',network='Exactly official public GitHub commit lookup and two raw files; no credential/vector/key uploads.',exit='First HTTP/pin/shape/size error or original30 deadline; no retry. Source acquisition only, not test qualification.',protected_sha256=protected)
pins();stagep.write_text(json.dumps(stage,indent=2)+'\n');root.mkdir(mode=0o700);start=time.monotonic();deadline=start+30;requests=[];error=None;selected=[];commit=None
maxbytes=4*1024*1024
def get(url,label,limit):
 remaining=deadline-time.monotonic();assert remaining>0
 with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept':'application/json','User-Agent':'rldcoin-local-standards-probe'}),timeout=min(10,remaining)) as response:
  assert response.status==200;data=response.read(limit+1);assert len(data)<=limit
 p=root/label;assert not p.exists();p.write_bytes(data);requests.append(dict(url=url,sha256=sha(p),bytes=len(data),path=str(p.relative_to(r))));return json.loads(data)
try:
 commits=get('https://api.github.com/repos/usnistgov/ACVP-Server/commits?path=gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json&per_page=1','commit.json',65536);commit=commits[0]['sha'];assert len(commit)==40 and all(c in '0123456789abcdef' for c in commit)
 base='https://raw.githubusercontent.com/usnistgov/ACVP-Server/'+commit+'/gen-val/json-files/ML-DSA-sigVer-FIPS204/'
 prompt=get(base+'prompt.json','prompt.json',maxbytes);expected=get(base+'expectedResults.json','expectedResults.json',maxbytes);assert prompt['vsId']==expected['vsId'] and prompt['algorithm']=='ML-DSA' and prompt['mode']=='sigVer' and prompt['revision']=='FIPS204'
 answers={}
 for group in expected['testGroups']:
  for test in group['tests']:
   key=(group['tgId'],test['tcId']);assert key not in answers and type(test['testPassed'])is bool;answers[key]=test['testPassed']
 for group in prompt['testGroups']:
  if group['parameterSet']=='ML-DSA-87' and group.get('signatureInterface')=='external' and group.get('preHash')=='pure':
   for test in group['tests']:
    key=(group['tgId'],test['tcId']);assert key in answers
    pk=bytes.fromhex(test['pk']);sig=bytes.fromhex(test['signature']);message=bytes.fromhex(test['message']);context=bytes.fromhex(test['context']);assert len(pk)==2592 and len(sig)==4627 and len(message)<=65536 and len(context)<=255
    selected.append(dict(tg_id=key[0],tc_id=key[1],expected=answers[key],key_bytes=len(pk),signature_bytes=len(sig),message_bytes=len(message),context_bytes=len(context)))
 assert selected and any(v['expected'] for v in selected) and any(not v['expected'] for v in selected);pins()
except BaseException as ex:error=type(ex).__name__+': '+str(ex)[:350]
duration=round(time.monotonic()-start,6);completed=error is None and duration<=30;report=dict(format=stage['format'],completed=completed,duration_seconds=duration,budget_seconds=30,attempts=1,error=error,nist_commit=commit,requests=requests,selected=selected,selected_count=len(selected),controller_sha256=sha(Path(__file__)),stage_sha256=sha(stagep),core_source=core['commitment'],core_source_unchanged=error is None,source_only=True,standard_KAT_executed=False,adopted_pq_profile=False,whole_goal_completed=False)
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='selected'}));raise SystemExit(0 if completed else 1)
