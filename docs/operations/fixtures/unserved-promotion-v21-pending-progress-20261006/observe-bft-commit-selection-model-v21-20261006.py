import ast, hashlib, json, time
from pathlib import Path
from types import SimpleNamespace
r=Path.cwd(); assert r==Path('/Users/galaxy/GitHub/rldcoin')
b=r/'tmp/default-relay-20260930'; e=r/'docs/operations/evidence'
start=time.monotonic(); deadline=start+10
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=r/'tools/interstellar_mesh.py'; source_hash=sha(source)
prior=e/'regional-bft-single-commit-boundary-v21-20261006-checks.json'
v=json.loads(prior.read_text())['result']; target=v['current_source_pair'][0]['packet_id']
root=b/'native-bft-four-cli-service-first-service-diag-v21-private-20261006'
journal=root/'ordinary-process-controller/first-service-events.jsonl'
snapshot=json.loads((root/'ordinary-process-controller/first-service-journal.json').read_text())
assert sha(journal)==snapshot['journal_sha256']
raw=journal.read_bytes(); selected=[]
for line in raw.splitlines():
 row=json.loads(line); z=row['record']
 if row['slot']==2 and any(target in m[k] for m in [z['before'],*z['plans'],z.get('after',z['before'])] for k in ('pending','arrivals','prepared')):
  selected.append(z)
# Exact target pair is recovered from qualified target rows, not node constructors.
peers={z['peer'] for z in selected if z['sequence'] in {x['sequence'] for x in v['typed_prepare_prefix']['target_records']}}
assert len(peers)==1
peer=peers.pop(); selected=[z for z in selected if z['peer']==peer]
assert len(selected)==34 and all(z['completed'] for z in selected)
assert not any(target in z['selected'] or target in z['hop_attempts'] for z in selected)
summary=[]
for z in selected:
 plan=z['plans'][0] if z['plans'] else None
 before=z['before']; after=z['after']
 preceding=plan['pending'][:plan['pending'].index(target)] if plan and target in plan['pending'] else []
 summary.append(dict(sequence=z['sequence'],role=z['role'],retry_count=len(z['retries']),plan_count=len(z['plans']),selected_count=len(z['selected']),pending_before=before['pending'].index(target) if target in before['pending'] else None,pending_plan=plan['pending'].index(target) if preceding or plan and target in plan['pending'] else None,pending_after=after['pending'].index(target) if target in after['pending'] else None,preceding_carried=sum(i in z['selected'] for i in preceding),inclusive_seconds=z['prepare_inclusive_seconds']))
node=next(x for x in ast.parse(source.read_text()).body if isinstance(x,ast.ClassDef) and x.name=='Node')
fn=next(x for x in node.body if isinstance(x,ast.FunctionDef) and x.name=='_exchange_plan')
branch=next(x for x in fn.body if isinstance(x,ast.If) and 'transit_class_steps' in ast.unparse(x.test))
assert {x.id for x in ast.walk(branch) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Load)}<= {'self','peer','first_plan','reversed','i','pending','list','dict','arrivals','set','items'}
code=compile(ast.fix_missing_locations(ast.Module(body=[branch],type_ignores=[])),str(source),'exec')
# Primitive bounded rank model, conditional on authentic/routable/fitting IDs.
ids=[format(i,'064x') for i in range(1,65)]; ids[29]=target
first={'pending':ids[17:49],'arrivals':ids[49:]}; assert first['pending'].index(target)==12
cases=[]
for step in range(8):
 for parity in range(2):
  groups=[ids[::2],ids[1::2]]
  if parity:groups.reverse()
  env=dict(self=SimpleNamespace(state={'transit_class_steps':{peer:step},'first_arrivals':ids}),peer=peer,first_plan=first,pending=groups)
  exec(code,{'__builtins__':{'reversed':reversed,'list':list,'dict':dict,'set':set}},env)
  result=env['pending']; assert all(set(a)==set(b) for a,b in zip(result,groups))
  cases.append(dict(step=step,class_order=parity,priority_enabled=(step//2)%2==0,target_class_position=next(a.index(target) for a in result if target in a),selected=target in [a[0] for a in result]))
assert all(not x['selected'] for x in cases)
# Retained FIFO cannot be displaced by newer arrivals: with two complete
# unsuppressed offers each prepare, the same rank12 target is served on turn7.
pending=list(first['pending']); turn=0
while target in pending:
 turn+=1; offered=pending[:2]; pending=pending[2:]
 if target in offered:break
assert turn==7
assert time.monotonic()<deadline and sha(source)==source_hash and sha(journal)==snapshot['journal_sha256']
result=dict(completed=True,duration_seconds=round(time.monotonic()-start,6),budget_seconds=10,attempts=1,production_file_sha256=source_hash,prior_checks_sha256=sha(prior),journal_sha256=snapshot['journal_sha256'],target_packet_id=target,exact_source_branch_cases=cases,actual_prepare_records=summary,full_four_retry_records=sum(len(z['retries'])==4 for z in selected),records_without_plan=sum(not z['plans'] for z in selected),planned_records=sum(bool(z['plans']) for z in selected),actual_preceding_carried_total=sum(x['preceding_carried'] for x in summary),conditional_FIFO_service_turn=turn,newest_priority_cannot_select_rank12_in_this_model=True,unconditional_starvation_or_unique_historical_cause_proved=False,Node_Native_Runtime_socket_key_sign_fixture_calls=0,production_unchanged=True,full_fault_qualified=False)
print(json.dumps(result,sort_keys=True))
