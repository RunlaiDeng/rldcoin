from pathlib import Path
import ast,copy,json,time,sys,threading,types,hashlib
from concurrent.futures import ThreadPoolExecutor
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();deadline=start+60;out=e/'regional-bft-bounded-readonly-cold-model-v1-20261007-checks.json';assert not out.exists()
helper=b/'observe-bft-four-cli-service-first-service-diag-v33-20261006.py';tree=ast.parse(helper.read_text());fn=next(z for z in ast.walk(tree) if isinstance(z,ast.FunctionDef) and z.name=='verify_replica_readonly');module=ast.Module(body=[fn],type_ignores=[]);code=compile(module,str(helper),'exec');jobs=[];states={};callers={};heads={}
class Caller:
 def __init__(self,k):self.k=k
 def read_text(self):
  result=copy.deepcopy(callers[self.k])
  if bad==self.k and field in ('binding','head','pending','outbox'):result[field]='invalid'
  return json.dumps(result)
for label in ('earth','proxima'):
 for n in range(4):
  ledger=Path('/readonly-model')/label/str(n);key=str(ledger);heads[key]='head-'+key;callers[key]=dict(binding='bound-'+key,head='caller-'+key,pending=None,outbox=None);states[key]=dict(currency='currency',region=label,height=4 if label=='earth' else 15,fixture_only=True,live_rld=False,ledger={});jobs.append((label,n,dict(ledger=ledger,signer='signer-'+key,caller=Caller(key))))
lock=threading.Lock();events=[];bad=field=None
class Preparation:
 pin='currency';region_ids={'earth':'earth','proxima':'proxima'};origin='earth';root=Path('/readonly-model')
 def remaining(self):assert time.monotonic()<deadline;return 1
 def call(self,ledger,command,*args):
  key=str(ledger)
  with lock:events.append((key,command))
  if command=='history-check':return dict(history_head='wrong' if bad==key and field=='history' else heads[key])
  if command=='status':
   result=copy.deepcopy(states[key])
   if bad==key and field in result:result[field]='invalid'
   return result
  assert command=='bft-status';return dict(binding=callers[key]['binding'],head=callers[key]['head'])
class Node:
 def __init__(self,cfg):self.id=cfg['node_id'];self.network='currency';self.state={'archives':{'one':{}}}
 def __enter__(self):return self
 def __exit__(self,*args):return False
 def archived(self,i):assert i=='one'
def cold(native,config,root,head):
 with lock:events.append((str(root/'proxima'/str(native)),'complete-native-cold'))
 assert head==heads[str(root/'proxima'/str(native))]
 if bad==str(root/'proxima'/str(native)) and field=='native-cold':raise ValueError('complete envelope refusal')
 return dict(messages_authenticated=7)
ns=dict(p=Preparation(),heads=heads,native=list(range(4)),configs=list(range(4)),transport=[dict(node_id='node-'+str(n),state='/readonly-model/mesh/'+str(n)) for n in range(4)],pins=[dict(node_id='node-'+str(n)) for n in range(4)],json=json,Path=Path,inventory=lambda p:{'one':1,'two':2},mesh=types.SimpleNamespace(Node=Node),verify_stopped_state_pinned=cold);exec(code,ns);worker=ns['verify_replica_readonly']
with ThreadPoolExecutor(max_workers=4) as pool:baseline=list(pool.map(worker,jobs))
assert len(baseline)==8 and sum(v[3] for v in baseline)==28 and sum(v[4] for v in baseline)==8;assert [v[:2] for v in baseline]==[(l,n) for l,n,_ in jobs];assert len(events)==28
negative=0
for label,n,row in jobs:
 for f in ('history','currency','region','height','fixture_only','live_rld','binding','head','pending','outbox')+ (('native-cold',) if label=='proxima' else ()):
  bad=str(row['ledger']);field=f
  try:
   with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(worker,jobs))
   raise RuntimeError('bad independent replica accepted')
  except (AssertionError,ValueError):negative+=1
bad=field=None
# Original exact per-replica cold checks are retained; only aggregation variables change.
t=json.loads((b/'bounded-readonly-v33-transformation-20261007.json').read_text());old=t['old_cold'];a=old.index('   p.remaining();');z=old.index("  assert all(state==states[label][0]");body=old[a:z];body=body.replace('states[label].append(state)','local_state=state').replace("cold_messages+=report['messages_authenticated']","local_messages=report['messages_authenticated']").replace("mesh_files+=len(inventory(Path(transport[n]['state'])))","local_mesh_files=len(inventory(Path(transport[n]['state'])))");body='\n'.join(line[3:] if line.startswith('   ') else line for line in body.splitlines());expected=ast.parse('def check():\n'+'\n'.join(' '+line for line in body.splitlines())).body[0].body
assert [ast.dump(x,include_attributes=False) for x in fn.body[2:-1]]==[ast.dump(x,include_attributes=False) for x in expected]
assert time.monotonic()<deadline
result=dict(completed=True,budget_seconds=60,attempts=1,duration_seconds=round(time.monotonic()-start,6),all_original_per_replica_cold_predicates_AST_exact_after_only_local_aggregation=True,independent_replica_jobs=8,maximum_workers=4,negative_replica_field_cases=negative,all_bad_replica_failures_propagate=True,result_order_and_exact_counts_preserved=True,models_not_actual_Native_authentication=True,Native_Node_Runtime_key_sign_socket_fixture_calls=0,actual_ground60_cumulative_unchanged=59.80325,new180=0,new600=0,helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),fullfault_qualified=False)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
