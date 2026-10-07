from pathlib import Path
import os,sys,time,json,hashlib,subprocess,signal,ast
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(r/'tools'));from regional_paged_fault_scope import inventory
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();helper=b/'observe-tcp-einval-six-peers-v1-20261007.py';name='regional-tcp-einval-six-peers-v1-20261007';root=b/'tcp-einval-six-peers-v1-private-20261007';log=b/(name+'.log');stage=e/(name+'-stage.json');checks=e/(name+'-checks.json');seal=b/'tcp-einval-six-peers-v1-stopped-private-inventory-20261007.json';python=r/'tmp/rldcoin-goal-20261001-venv/bin/python';assert not any(p.exists() for p in (root,log,stage,checks,seal));ast.parse(helper.read_text())
# Actual names/attributes bind without Fixture/Worker/Node constructors or functions.
import interstellar_mesh as mesh,interstellar_tcp as tcp
from test_interstellar_tcp import Fixture
from regional_carriage_worker import Worker
for owner,names in ((tcp,('client_connect','send','receive','outgoing')),(mesh,('atomic',)),(mesh.Node,('__init__','close'))):assert all(callable(getattr(owner,n)) for n in names)
x=json.loads((e/'regional-contact-apply-defer-v1-identity-20261007.json').read_text());core=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text());protected={**{str(r/p):h for p,h in x['python_source_sha256'].items()},**{str(r/p):h for p,h in x['native_source_sha256'].items()},**{str(r/z['path']):z['sha256'] for z in core['files']},str(b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate'):x['actual_cli_sha256']};assert len(protected)==453
for p in (helper,Path(__file__),python.resolve(),r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',e/'regional-contact-snapshot-error-attribution-counter-v1-20261007.json'):protected[str(p)]=sha(p)
seals=dict(x['protected_private_inventory_sha256']);p=b/'native-paged-full-fault-apply-v9-stopped-private-inventory-20261007.json';seals[str(p)]=sha(p)
def pins():assert all(sha(Path(p))==h for p,h in protected.items()) and all(sha(Path(p))==h for p,h in seals.items())
pins();budget=50.466611;started=time.monotonic();deadline=started+budget;stage.write_text(json.dumps(dict(budget_seconds=budget,attempts=1,original_TCP60_prior_seconds=9.533389,hypothesis='Actual six-peer signed-ground TLS ordinary concurrent workers reproduce EINVAL with exact OS errno and bounded original-call traceback. Original Service snapshot race means final TCP errors cannot exclude TCP origin. OSError wrappers only call original once and rethrow unchanged; zero Native/copy/deadline/threshold changes.',exit='First exact EINVAL, source/byte/capacity/stop guard, thirty-second body/cold completion or remaining original TCP60. Absence leaves original cause unknown, no waiver or conjectural repair.',protected_sha256=protected,private_inventory_sha256=seals),indent=2)+'\n');exhausted=False
with log.open('xb') as stream:
 p=subprocess.Popen([str(python),'-B',str(helper),str(deadline)],cwd=r,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdout=stream,stderr=stream,start_new_session=True)
 try:code=p.wait(timeout=max(.001,deadline-time.monotonic()))
 except subprocess.TimeoutExpired:
  exhausted=True;os.killpg(p.pid,signal.SIGTERM)
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
  code=p.returncode
pin_error=None
try:pins()
except Exception as error:pin_error=str(error) or type(error).__name__
rows=[json.loads(line.split(' ',1)[1]) for line in log.read_text().splitlines() if line.startswith('tcp-einval-result ')];private={str(root):inventory(root)} if root.exists() else {};seal.write_text(json.dumps(private,sort_keys=True)+'\n');duration=round(time.monotonic()-started,6);done=code==0 and not exhausted and pin_error is None and len(rows)==1 and rows[0]['completed'] and duration<=budget
report=dict(completed=done,duration_seconds=duration,original_TCP60_cumulative_seconds=round(9.533389+duration,6),budget_seconds=budget,attempts=1,helper_exit_code=code,helper_terminal=p.poll() is not None,budget_exhausted=exhausted,pin_error=pin_error,helper_sha256=sha(helper),controller_sha256=sha(Path(__file__)),log_sha256=sha(log),stage_sha256=sha(stage),seal_sha256=sha(seal),stopped_files=sum(len(v) for v in private.values()),result=rows[0] if rows else None,old_failure_sources_bytes_unchanged=pin_error is None,full_fault_status='FAIL',whole_goal_completed=False);checks.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);raise SystemExit(0 if done else 1)
