from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v35-private-20261006';start=time.monotonic();prior=2.388521;deadline=start+20-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v35-20261006-checks.json').read_text());assert not q['completed'] and q['guardian']['owned_processes_stopped'];seal=b/'native-bft-four-cli-service-first-service-diag-v35-stopped-private-inventory-20261006.json';assert sha(seal)==q['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def read(p,lines=False):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return [json.loads(v) for v in raw.splitlines()] if lines else json.loads(raw)
edge=json.loads((e/'regional-bft-exact-proposal-edge-v35-20261007-checks.json').read_text());pid=edge['packet_id'];peer=edge['actual_first_hop'];records=read(root/'ordinary-process-controller/first-service-events.jsonl',True);raw=read(root/'mesh/2/mesh-state.json');sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;s=mesh.load_state_storage(root/'mesh/2/mesh-state.json',raw['network'],raw['node_id'])
rows=[];step=0;unknown=[]
for v in records:
 if v['slot']!=2 or v['record']['peer']!=peer:continue
 z=v['record'];before=step;selected=z.get('selected',[]);retries=z['retries'];carried=[i for i in selected if i not in retries];offered=[]
 if carried:
  assert z['plans'];pending=z['plans'][0]['pending']
  for i in carried:
   if len(offered)==2 or i not in pending:break
   offered.append(i)
  step+=len(carried)-len(offered)
 elif z['completed'] and not selected:
  unknown.append(z['sequence']);step+=1
 if z['completed']:
  rows.append(dict(sequence=z['sequence'],priority_pair_condition=(before//2)%2==0,reconstructed_class_step_before=before,step_delta=step-before,full4_retry=len(retries)==4,selected=selected,target_selected=pid in selected,target_prepared_before=pid in z['before']['prepared'],target_pending_before=pid in z['before']['pending'],target_suppressed=pid in z['suppressed_ids'],target_hop_attempts=z['hop_attempts'].get(pid,0),plan_pending=len(z['plans'][0]['pending']) if z['plans'] else None))
assert time.monotonic()<deadline
for p,h in seen.items():assert sha(Path(p))==h
actual=s['transit_class_steps'][peer]
# Use only a suffix with no ambiguous empty selection; reverse from exact saved
# class-step value, independent of unknown earlier active-set and failed calls.
backward=[];at=actual
for z in reversed(rows):
 if not z['selected']:break
 delta=z['step_delta'];at-=delta
 backward.append(dict(z,exact_suffix_class_step_before=at,exact_suffix_priority_pair_condition=(at//2)%2==0))
backward.reverse()
assert backward, 'no exact bounded suffix'
result=dict(completed=True,hypothesis='After failed original send and full4 retry, exact prepared current Proposal may never revisit spare priority because four ordinary selections advance class step by4, preserving (step//2)%2 forever. Reconstruct actual original per-peer steps from complete prepare records, matching final source state before any model repair.',rows=backward,exact_final_class_steps=actual,forward_ambiguous_empty_records=unknown,forward_step_sum=step,whole_trace_reconstruction_proved=False,conditional_live_frame_hint_not_recorded_or_proved=True,unique_maturity_cause=False,source_source_bound=sha(r/'tools/interstellar_mesh.py'),consumed_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6),new180=0,new600=0)
out=e/'regional-bft-prepared-proposal-phase-v35-v2-20261007-checks.json';assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
