from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v46-private-20261006';start=time.monotonic();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
terminal=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v46-20261006-checks.json').read_text());assert terminal['helper_terminal'] and terminal['guardian']['owned_processes_stopped']
matrix_path=e/'regional-bft-parent14-v46-matrix-20261007-checks.json';matrix=json.loads(matrix_path.read_text());prior=json.loads((e/'regional-bft-current-edge-timing-v46-v2-20261007-checks.json').read_text())['combined_original20_seconds'];deadline=start+20-prior
stage=e/'regional-bft-exact-selector-decision-v46-20261007-stage.json';out=e/'regional-bft-exact-selector-decision-v46-20261007-checks.json';assert not stage.exists() and not out.exists()
stage.write_text(json.dumps(dict(hypothesis='V46 Proposal2to1 is enqueued but not observed prepared. Inspect its actual consumed hint, current group rank, checked original route and selected competitors before any further repair. Actual consumed-hint/current-group ranks/original checked route resolves whether hint lost, group order or original route blocks target; no saved-clock guess or unique maturity claim.',budget_seconds=20,prior_seconds=prior,attempts=1,exit='first original schema/seal/signature bound or original20 deadline; no old Node Native Runtime constructors/sign/key/socket/fixture'),indent=2)+'\n')
seal=b/'native-bft-four-cli-service-first-service-diag-v46-stopped-private-inventory-20261006.json';assert sha(seal)==terminal['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];consumed={}
def load(p,lines=False):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];consumed[str(p)]=h
 return [json.loads(line) for line in raw.splitlines()] if lines else json.loads(raw)
sys.path.insert(0,str(b));sys.path.insert(0,str(r/'tools'));import first_service_diagnostic_observer_v6_20261007 as diag;import interstellar_mesh as mesh
records=load(root/'ordinary-process-controller/first-service-events.jsonl',True);trace=load(root/'ordinary-process-controller/finite-trace-events.jsonl',True);counts={i:0 for i in range(4)}
for item in records:
 z=item['record'];diag.check_record(z,sequenced=True);slot=item['slot'];counts[slot]+=1;assert z['sequence']==counts[slot];assert 'selector' in z
missing=[]
for row in matrix['rows']:
 for dest in row['destinations']:
  if not any(v['receipt'] for v in dest['complete_transport']):missing.append((row,dest))
actual_missing_count=len(missing)
selected_row=next(row for row in matrix['rows'] if row['source']==2 and row['kind']=='Proposal' and row['round']==0)
missing=[(selected_row,next(d for d in selected_row['destinations'] if d['destination']==1))]
result=dict(completed=True,observed_prefix_records=counts,missing_complete_destination_edges=actual_missing_count,chosen_edge_complete=any(v['receipt'] for v in missing[0][1]['complete_transport']),Node_Native_Runtime_socket_key_sign_fixture_calls=0,unique_maturity_cause=False,full_live_or_Native_acceptance_not_qualified=True,new180=0,new600=0)
if missing:
 row,dest=missing[0];src=row['source'];dst=dest['destination'];src_raw=load(root/f'mesh/{src}/mesh-state.json');dstid=load(root/f'mesh/{dst}/mesh-state.json')['node_id']
 enqueued=[z for z in trace if z['slot']==src and z['stage']=='source_enqueued' and z['peer']==dstid and z['envelope_id']==row['envelope_id']];assert len(enqueued)<=1
 result.update(source=src,destination=dst,kind=row['kind'],round=row['round'],body_id=row['body_id'],envelope_id=row['envelope_id'],source_enqueued=bool(enqueued))
 if enqueued:
  pid=enqueued[0]['packet_id'];frame=enqueued[0]['frame_id'];prepared=[z for z in trace if z['slot']==src and z['stage']=='outgoing_prepared' and z.get('packet_id')==pid];peers={z['peer'] for z in prepared};assert len(peers)<=1;peer=next(iter(peers),None)
  rows=[]
  for item in records:
   z=item['record']
   if item['slot']!=src or peer is not None and z['peer']!=peer:continue
   p=z['priority'];selector=z['selector'];target_in_entry=pid in p['matching_packet_ids'];selected=pid in z.get('selected',[])
   if not target_in_entry and not selected:continue
   positions=[]
   for call in selector['groups']:
    classes=[]
    for index,group in enumerate(call):
     if pid in group['current_ids']:classes.append(dict(group_index=index,class_size=group['size'],target_rank=group['positions'][group['current_ids'].index(pid)],current_packet_order=group['current_ids']))
    positions.append(classes)
   rows.append(dict(peer=z['peer'],sequence=z['sequence'],completed=z['completed'],class_step=p['class_step'],priority_pair=p['pair_enabled'],prepared_before=pid in z['before']['prepared'],pending_before=pid in z['before']['pending'],full4_retry=len(z['retries'])==4,entry_hint_matches=target_in_entry,consumed_hint_reads=[None if h is None else dict(scope=h['scope'],target_frame_matches=frame in h['frame_ids'],frame_count=len(h['frame_ids'])) for h in selector['hint_reads']],group_positions=positions,original_transit_checks=selector['transit_checks'].get(pid,0),original_route=selector['routes'].get(pid),hop_attempts=z['hop_attempts'].get(pid,0),suppressed=pid in z['suppressed_ids'],selected=selected,selected_packet_ids=z.get('selected',[])))
  attempts=[]
  for z in prepared:
   events=[v for v in trace if v['slot']==src and v.get('peer')==z['peer'] and v.get('attempt')==z['attempt']]
   attempts.append(dict(attempt=z['attempt'],peer=z['peer'],request_sent=any(v['stage']=='request_sent' for v in events),peer_custody=any(v['stage']=='peer_custody_authenticated' for v in events),reply_local_custody=any(v['stage']=='reply_local_custody' for v in events),failures=[{k:v[k] for k in ('failure_stage','error_class')} for v in events if v['stage']=='contact_failed']))
  result.update(packet_id=pid,frame_id=frame,actual_first_hop=peer,rows=rows,original_attempts=attempts,first_prepare_wait_seconds=prepared[0]['monotonic_seconds']-enqueued[0]['monotonic_seconds'] if prepared else None)
assert time.monotonic()<deadline
for path,h in consumed.items():assert sha(Path(path))==h
result.update(consumed_sealed_bytes_unchanged=True,matrix_checks_sha256=sha(matrix_path),stage_sha256=sha(stage),reader_sha256=sha(Path(__file__)),duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6))
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='rows'}));print(json.dumps([dict(sequence=z['sequence'],step=z['class_step'],priority=z['priority_pair'],full4=z['full4_retry'],selected=z['selected'],hint=z['consumed_hint_reads'],groups=z['group_positions']) for z in rows if z['priority_pair'] and not z['full4_retry']]))
