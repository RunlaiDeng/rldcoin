from pathlib import Path
import json,hashlib,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v33-private-20261006';start=time.monotonic();prior=7.675695;deadline=start+20-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();seal=b/'native-bft-four-cli-service-first-service-diag-v33-stopped-private-inventory-20261006.json';cp=e/'regional-bft-four-cli-service-first-service-diag-v33-20261006-checks.json';checks=json.loads(cp.read_text());assert checks['guardian']['owned_processes_stopped'] and sha(seal)==checks['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def read(p,lines=False):
 data=p.read_bytes();h=hashlib.sha256(data).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return [json.loads(z) for z in data.splitlines()] if lines else json.loads(data)
trace=read(root/'ordinary-process-controller/finite-trace-events.jsonl',True);view=read(root/'ordinary-process-controller/final-observation-2.json');target='53cd34c77caf93eea002bb50e5ee79fb16e43faba31e5108661426784db8d4e7';refused=[z for z in trace if z['slot']==2 and z.get('packet_id')==target and z['stage']=='deferred_input_not_queued'];assert len(refused)==1 and refused[0]['failure_stage']=='input_slot_occupied';at=refused[0]['monotonic_seconds'];groups={}
for z in trace:
 if z['slot']==2 and z.get('nonce') and z['stage'] in ('deferred_input_queued','deferred_attempt','deferred_local_custody'):
  groups.setdefault(z['nonce'],[]).append(z)
occupied=[]
for nonce,rows in groups.items():
 queued=[z for z in rows if z['stage']=='deferred_input_queued'];finished=[z for z in rows if z['stage']=='deferred_local_custody'];q=min([z['monotonic_seconds'] for z in queued],default=None);f=min([z['monotonic_seconds'] for z in finished],default=None)
 if q is not None and q<=at and (f is None or f>=at):
  occupied.append(dict(nonce=nonce,peer=queued[0]['peer'],queued_at=q,completed_at=f,observed_queued_to_completed_seconds=None if f is None else round(f-q,6),packets=sorted({z['packet_id'] for z in queued}),attempt_events=len({z['sequence'] for z in rows if z['stage']=='deferred_attempt'}),target_was_part_of_that_job=any(z['packet_id']==target for z in queued)))
for p,h in seen.items():assert sha(Path(p))==h
assert time.monotonic()<deadline
result=dict(completed=True,budget_seconds=20,attempts=1,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6),actual_target_not_queued_reason='input_slot_occupied',actual_target_rejection_monotonic=at,overlapping_queued_request_candidates=occupied,intervals_cannot_reconstruct_untraced_rejection_or_live_queue_object=True,final_deferred_input_counters=view['transport']['tcp']['contacts']['deferred_input'],actual_mesh_lease_costs=view['transport']['tcp']['contacts']['mesh_lease_costs'],actual_Native_operation_costs=view['bft_observation']['operations'],retained_byte_hashes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,new180=0,new600=0,unique_maturity_cause=False,fullfault_qualified=False)
out=e/'regional-bft-target-input-slot-v33-20261007-checks.json';assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ('actual_mesh_lease_costs','actual_Native_operation_costs')},sort_keys=True))
