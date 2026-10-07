from pathlib import Path
import json,os,time,hashlib,datetime,importlib.util,sys
from dataclasses import replace
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';name='pq-hybrid-policy-v2-20261007';private=b/(name+'-private');stagep=e/(name+'-stage.json');out=e/(name+'-checks.json');assert not any(p.exists() for p in (private,stagep,out));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();prior=json.loads((e/'pq-hybrid-provider-v1-20261007-checks.json').read_text());assert prior['completed'];used=prior['duration_seconds'];source=r/'tools/pq_authorization_candidate.py';compile(source.read_text(),str(source),'exec');protected={str(Path(p)):h for p,h in json.loads((e/'pq-hybrid-provider-v1-20261007-stage.json').read_text())['protected_sha256'].items()};protected[str(source)]=sha(source);protected[str(Path(__file__))]=sha(Path(__file__));protected[str(e/'pq-hybrid-provider-v1-20261007-checks.json')]=sha(e/'pq-hybrid-provider-v1-20261007-checks.json');original=b/'pq-hybrid-provider-v1-20261007-private';seal=original/'PRIVATE_INVENTORY.json';protected[str(seal)]=sha(seal)
# Read public material only; the prior private signing keys are never opened.
public_names=['ed-public.der','pq-public.der','wrong-pq-public.der','ed-signature.bin','pq-signature.bin','ed-altered-signature.bin','pq-altered-signature.bin','intent.bin'];protected.update({str(original/n):sha(original/n) for n in public_names})
def pins():assert all(sha(Path(p))==h for p,h in protected.items())
stage=dict(format='RLD-PQ-HYBRID-POLICY-V2',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=60,previous_used_seconds=used,remaining_seconds=60-used,attempts=1,hypothesis='Actual Ed25519 and ML-DSA-87 verification must use AND over identical canonical candidate intent, caller-pinned currency/region/purpose/key pair and finite trusted epoch interval. A genuine valid half never replaces the missing/forged other half. No signing/private-key reads/Native import/old fixture opens.',exit='First unexpected result/pin/deadline ends scope; preserve all fresh public scratch. Original provider budget60 cumulative, no reset.',protected_sha256=protected)
pins();stagep.write_text(json.dumps(stage,indent=2)+'\n');os.umask(0o077);private.mkdir(mode=0o700);start=time.monotonic();deadline=start+60-used;results=[];error=None
try:
 spec=importlib.util.spec_from_file_location('rld_pq_candidate',source);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
 intent=json.loads((original/'intent.bin').read_bytes().split(b'\0',1)[1]);assert module.signing_bytes(intent)==(original/'intent.bin').read_bytes()
 policy=module.Policy(module.PROFILE,intent['currency_root'],intent['region_root'],'PAYMENT',1,2,(original/'ed-public.der').read_bytes(),(original/'pq-public.der').read_bytes());proof=module.Proof((original/'ed-signature.bin').read_bytes(),(original/'pq-signature.bin').read_bytes());openssl=Path('/opt/homebrew/opt/openssl@3/bin/openssl').resolve()
 def case(label,expect,p=policy,i=intent,s=proof,epoch=1):
  at=time.monotonic();assert at<deadline;scratch=private/label;result=module.verify_candidate(p,i,s,epoch,scratch,openssl,deadline);results.append(dict(case=label,expected=expect.value,actual=result.value,duration_seconds=round(time.monotonic()-at,6),scratch_created=scratch.exists()));assert result is expect,label
 case('both-actual-signatures',module.Result.VERIFIED)
 case('only-valid-classical',module.Result.REJECTED,s=replace(proof,pq_signature=b''))
 case('only-valid-pq',module.Result.REJECTED,s=replace(proof,ed_signature=b''))
 case('valid-ed-forged-pq',module.Result.REJECTED,s=replace(proof,pq_signature=(original/'pq-altered-signature.bin').read_bytes()))
 case('valid-pq-forged-ed',module.Result.REJECTED,s=replace(proof,ed_signature=(original/'ed-altered-signature.bin').read_bytes()))
 case('wrong-pinned-pq-key',module.Result.REJECTED,p=replace(policy,pq_public_der=(original/'wrong-pq-public.der').read_bytes()))
 case('wrong-purpose',module.Result.REJECTED,i=dict(intent,purpose='FINALITY'))
 case('wrong-currency-root',module.Result.REJECTED,i=dict(intent,currency_root='04'*32))
 case('wrong-region-root',module.Result.REJECTED,i=dict(intent,region_root='05'*32))
 case('changed-nonce',module.Result.REJECTED,i=dict(intent,nonce=2))
 case('expired-observation',module.Result.REJECTED,epoch=3)
 case('premature-intent',module.Result.REJECTED,i=dict(intent,epoch=2),epoch=1)
 case('unknown-profile',module.Result.REJECTED,p=replace(policy,profile='UNIMPLEMENTED'))
 case('boolean-epoch',module.Result.REJECTED,i=dict(intent,epoch=True))
 case('unbounded-horizon',module.Result.REJECTED,p=replace(policy,valid_until_epoch=1<<64))
 malformed=[b'{"epoch":1,"epoch":2}',b'{"epoch":NaN}',b'{"epoch":1.0}',b'[]',b'X'*2049,b'{"x":'+b'['*500+b']'*500+b'}']
 for n,raw in enumerate(malformed):
  try:module.decode_intent(raw)
  except module.Rejected:results.append(dict(case='malformed-wire-'+str(n),expected='refused',actual='refused'))
  else:raise AssertionError('malformed candidate JSON accepted')
 assert module.decode_intent(json.dumps(intent).encode())==intent
 assert all(not row['scratch_created'] for row in results if row['case'] in ('only-valid-classical','only-valid-pq','wrong-purpose','wrong-currency-root','wrong-region-root','expired-observation','premature-intent','unknown-profile','boolean-epoch','unbounded-horizon'))
 pins()
except BaseException as ex:error=type(ex).__name__+': '+str(ex)[:350]
duration=round(time.monotonic()-start,6);total=round(used+duration,6);completed=error is None and total<=60;files=[dict(path=str(p.relative_to(private)),sha256=sha(p),bytes=p.stat().st_size) for p in sorted(private.rglob('*')) if p.is_file()];inventory=private/'PRIVATE_INVENTORY.json';inventory.write_text(json.dumps(dict(files=files),indent=2)+'\n');report=dict(format=stage['format'],completed=completed,duration_seconds=duration,previous_used_seconds=used,cumulative_seconds=total,budget_seconds=60,attempts=1,error=error,results=results,source_sha256=sha(source),controller_sha256=sha(Path(__file__)),stage_sha256=sha(stagep),private_inventory_sha256=sha(inventory),private_file_count=len(files),old_provider_seal_unchanged=sha(seal)==protected[str(seal)],core_source=prior['core_source'],core_source_unchanged=error is None,hybrid_AND_policy_implemented=completed,standard_KAT_qualified=False,independent_implementation_qualified=False,native_integration_qualified=False,mainnet=False,whole_goal_completed=False)
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'}));raise SystemExit(0 if completed else 1)
