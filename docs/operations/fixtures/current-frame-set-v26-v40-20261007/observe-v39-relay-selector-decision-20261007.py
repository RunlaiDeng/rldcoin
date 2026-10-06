from pathlib import Path
import json,hashlib,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v39-private-20261006';start=time.monotonic();prior=1.686628;deadline=start+20-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();q=json.loads((e/'regional-bft-exact-selector-decision-v39-20261007-checks.json').read_text());terminal=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v39-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v39-stopped-private-inventory-20261006.json';assert sha(seal)==terminal['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def load(p,lines=False):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return [json.loads(z) for z in raw.splitlines()] if lines else json.loads(raw)
sys.path.insert(0,str(r/'tools'));sys.path.insert(0,str(b));import interstellar_mesh as mesh;import first_service_diagnostic_observer_v6_20261007 as diag
pid=q['packet_id'];frame=q['frame_id'];relay=2;peer=load(root/'mesh/1/mesh-state.json')['node_id'];p=root/'mesh/2/mesh-state.json';raw=load(p);state=mesh.load_state_storage(p,raw['network'],raw['node_id']);records=load(root/'ordinary-process-controller/first-service-events.jsonl',True);trace=load(root/'ordinary-process-controller/finite-trace-events.jsonl',True);rows=[]
for item in records:
 z=item['record'];diag.check_record(z,sequenced=True)
 if item['slot']!=relay or z['peer']!=peer:continue
 entry=z['priority'];sel=z['selector'];hint=pid in entry['matching_packet_ids'];selected=pid in z.get('selected',[])
 if not hint and not selected and pid not in z['before']['pending'] and pid not in z['before']['arrivals']:continue
 pos=[]
 for call in sel['groups']:
  pos.append([dict(index=i,size=g['size'],rank=g['positions'][g['current_ids'].index(pid)],current_order=g['current_ids']) for i,g in enumerate(call) if pid in g['current_ids']])
 rows.append(dict(sequence=z['sequence'],role=z['role'],completed=z['completed'],class_step=entry['class_step'],priority_pair=entry['pair_enabled'],entry_hint_matches=hint,consumed_hint=[None if h is None else dict(target_matches=frame in h['frame_ids'],frame_count=len(h['frame_ids'])) for h in sel['hint_reads']],prepared_before=pid in z['before']['prepared'],pending_position=z['before']['pending'].index(pid) if pid in z['before']['pending'] else None,arrival_position=z['before']['arrivals'].index(pid) if pid in z['before']['arrivals'] else None,groups=pos,checks=sel['transit_checks'].get(pid,0),original_route=sel['routes'].get(pid),hop_attempts=z['hop_attempts'].get(pid,0),suppressed=pid in z['suppressed_ids'],selected=selected,full4_retry=len(z['retries'])==4))
prepared=[z for z in trace if z['slot']==relay and z['stage']=='outgoing_prepared' and z.get('packet_id')==pid];attempts=[]
for z in prepared:
 events=[v for v in trace if v['slot']==relay and v.get('peer')==z['peer'] and v.get('attempt')==z['attempt']]
 attempts.append(dict(peer=z['peer'],attempt=z['attempt'],request_sent=any(v['stage']=='request_sent' for v in events),peer_custody=any(v['stage']=='peer_custody_authenticated' for v in events),reply_local_custody=any(v['stage']=='reply_local_custody' for v in events),failures=[{k:v[k] for k in ('failure_stage','error_class')} for v in events if v['stage']=='contact_failed']))
t=state['messages'].get(pid);target=None
if t:
 packet,_,visited=mesh.transit_check(t,state['network']);target=dict(full_transit_signature_verified=True,original_complete_bytes=len(mesh.evidence.canonical(t)),hops=len(t['hops']),visited=visited,receipt=pid in state['receipts'])
assert time.monotonic()<deadline
for path,h in seen.items():assert sha(Path(path))==h
out=e/'regional-bft-relay-selector-decision-v39-20261007-checks.json';assert not out.exists();result=dict(completed=True,source=q['source'],destination=q['destination'],relay=relay,packet_id=pid,frame_id=frame,target_retained=target,rows=rows,attempts=attempts,original_custody_trace=[z for z in trace if z.get('packet_id')==pid and z['slot'] in (1,2) and z['stage'] in ('local_transport_custody','deferred_local_custody','inbound_refused','deferred_input_not_queued','deferred_input_queued')],Node_Native_Runtime_socket_key_sign_fixture_calls=0,consumed_sealed_bytes_unchanged=True,unique_maturity_cause=False,new180=0,new600=0,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6),reader_sha256=sha(Path(__file__)))
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
