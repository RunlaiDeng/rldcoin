from pathlib import Path
import os,sys,time,json,hashlib,subprocess,signal,datetime,dis,builtins,types
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(r/'tools'))
from regional_paged_fault_scope import inventory
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();name='regional-contact-apply-native-lock-v1-20261007';helper=b/'observe-contact-apply-native-lock-v1-20261007.py';root=b/'native-contact-apply-lock-v1-private-20261007';stage=e/(name+'-stage.json');checks=e/(name+'-checks.json');seal=b/'native-contact-apply-lock-v1-stopped-private-inventory-20261007.json';log=b/(name+'.log');python=r/'tmp/rldcoin-goal-20261001-venv/bin/python';identity=e/'regional-contact-apply-defer-v1-identity-20261007.json'
assert not any(p.exists() for p in (root,stage,checks,seal,log));x=json.loads(identity.read_text());core=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text());binary=b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate'
protected={**{str(r/p):v for p,v in x['python_source_sha256'].items()},**{str(r/p):v for p,v in x['native_source_sha256'].items()},**{str(r/z['path']):z['sha256'] for z in core['files']},str(binary):x['actual_cli_sha256']};assert len(protected)==453
for p in (helper,Path(__file__),identity,python.resolve(),r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',b/'contact-apply-defer-v1-source-reversal-20261007.json',e/'regional-contact-apply-defer-related-v1-20261007.json'):protected[str(p)]=sha(p)
receipt=json.loads((r/'docs/WHITEPAPER_FREEZE_RECEIPT.json').read_text())
for field in ('canonical_markdown','pdf'):protected[str(r.parent/'rldcoin-website'/receipt[field]['path'])]=receipt[field]['sha256']
seals=x['protected_private_inventory_sha256']
def pins():
 assert all(sha(Path(p))==v for p,v in protected.items()),'source/binary/controller/evidence/freeze changed'
 assert all(sha(Path(p))==v for p,v in seals.items()),'old immutable inventory changed'
pins();compile(helper.read_text(),str(helper),'exec')
# Import and actual attribute-name binding only, no generated function execution.
import interstellar_mesh as mesh
assert callable(mesh.Node) and isinstance(mesh._verified_transits,dict) and callable(mesh._verified_transits.clear)
assert 'mesh._TRANSIT_WITNESSES' not in helper.read_text()
started=time.monotonic();deadline=started+60
stage.write_text(json.dumps(dict(recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=60,attempts=1,hypothesis='Fresh actual signed finalized-import and native contact-apply held OS lock must be typed unknown, same full retained frame reverified after release without import/maturity/spending authority; original source Native binary+Service tick unchanged under bounded fault injection, TCP tick only noop model.',exit='First proof/lock/type/head/bytes/source/cold guard or original60, no repeated same currency or extension',protected_sha256=protected,private_inventory_sha256=seals,root=str(root),root_absent_before_creation=True,companion_source_commitment=x['python_source_commitment'],native_source_manifest_commitment=x['native_source_manifest_commitment'],core_source_commitment=x['core_source_commitment'],cli_binary_sha256=x['actual_cli_sha256'],full_fault_qualified=False,whole_goal_completed=False),indent=2)+'\n')
exhausted=False
with log.open('xb') as output:
 process=subprocess.Popen([str(python),'-B',str(helper),str(deadline)],cwd=r,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdout=output,stderr=output,start_new_session=True)
 try:code=process.wait(timeout=max(.001,deadline-time.monotonic()))
 except subprocess.TimeoutExpired:
  exhausted=True;os.killpg(process.pid,signal.SIGTERM)
  try:process.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
  code=process.returncode
error=None
try:pins()
except Exception as exception:error=str(exception)
results=[json.loads(line.split(' ',1)[1]) for line in log.read_text().splitlines() if line.startswith('contact-apply-native-result ')];private={str(root):inventory(root)} if root.exists() else {};seal.write_text(json.dumps(private,sort_keys=True)+'\n');duration=round(time.monotonic()-started,6);completed=code==0 and not exhausted and error is None and len(results)==1 and results[0]['completed'] and duration<=60
report=dict(completed=completed,exit_code=code,helper_terminal=process.poll() is not None,budget_seconds=60,attempts=1,duration_seconds=duration,budget_exhausted=exhausted,pin_error=error,stage_sha256=sha(stage),helper_sha256=sha(helper),controller_sha256=sha(Path(__file__)),log_sha256=sha(log),stopped_inventory_sha256=sha(seal),stopped_files=sum(len(v) for v in private.values()),result=results[0] if results else None,old_custody_unchanged=True,old_private_not_rescanned=True,failed_currency_sealed=not completed,failed_currency_never_reopen=not completed,full_fault_qualified=False,whole_goal_completed=False)
checks.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);raise SystemExit(0 if completed else 1)
