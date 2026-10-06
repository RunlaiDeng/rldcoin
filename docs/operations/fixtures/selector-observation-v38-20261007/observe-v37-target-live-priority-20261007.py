from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v37-private-20261006';start=time.monotonic();prior=1.665612;deadline=start+20-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();q=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v37-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v37-stopped-private-inventory-20261006.json';assert sha(seal)==q['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def read(p,lines=False):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return [json.loads(z) for z in raw.splitlines()] if lines else json.loads(raw)
sys.path.insert(0,str(b));import first_service_diagnostic_observer_v4_20261007 as diag
edge=json.loads((e/'regional-bft-exact-prepare-edge-v37-20261007-checks.json').read_text());pid=edge['packet_id'];peer=edge['actual_first_hop'];records=read(root/'ordinary-process-controller/first-service-events.jsonl',True);trace=read(root/'ordinary-process-controller/finite-trace-events.jsonl',True);count={i:0 for i in range(4)}
for v in records:
 z=v['record'];diag.check_record(z,sequenced=True);count[v['slot']]+=1;assert z['sequence']==count[v['slot']],'record gap';assert 'priority' in z
rows=[]
for v in records:
 if v['slot']!=2:continue
 z=v['record']
 if z['peer']!=peer or z['sequence']<74:continue
 p=z['priority'];rows.append(dict(sequence=z['sequence'],role=z['role'],completed=z['completed'],class_step=p['class_step'],priority_pair=p['pair_enabled'],hint_present=p['hint_scope'] is not None,hint_frame_count=len(p['frame_ids']),current_active_packet_count=len(p['matching_packet_ids']),target_in_current_hint=p is not None and pid in p['matching_packet_ids'],target_prepared_before=pid in z['before']['prepared'],target_pending_before=pid in z['before']['pending'],full4_retry=len(z['retries'])==4,target_selected=pid in z.get('selected',[]),target_hop_attempts=z['hop_attempts'].get(pid,0),target_suppressed=pid in z['suppressed_ids'],plan_pending=len(z['plans'][0]['pending']) if z['plans'] else None))
refusals=[z for z in trace if z.get('packet_id')==pid and z['slot']==1 and z['stage'] in ('inbound_refused','deferred_input_not_queued','deferred_input_queued','deferred_local_custody','local_transport_custody')]
assert time.monotonic()<deadline
for p,h in seen.items():assert sha(Path(p))==h
result=dict(completed=True,budget_seconds=20,observed_prefix_records=count,observed_rows=rows,firsthop_actual_refusal_or_admission=refusals,full_live_or_all_Native_acceptance_not_qualified=True,records_are_original_primitive_prepare_entry_observations=True,readonly_source_inventory_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6),unique_maturity_cause=False,new180=0,new600=0)
out=e/'regional-bft-target-live-priority-v37-20261007-checks.json';assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
