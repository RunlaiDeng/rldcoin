from pathlib import Path
import json,hashlib,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v39-private-20261006';start=time.monotonic();prior=2.151975;deadline=start+20-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=json.loads((e/'regional-bft-relay-selector-decision-v39-20261007-checks.json').read_text());term=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v39-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v39-stopped-private-inventory-20261006.json';assert sha(seal)==term['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def load(p,lines=False):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return [json.loads(z) for z in raw.splitlines()] if lines else json.loads(raw)
sys.path.insert(0,str(r/'tools'));sys.path.insert(0,str(b));import interstellar_mesh as mesh;import interstellar_transfer as wire;import first_service_diagnostic_observer_v6_20261007 as diag
p=root/'mesh/2/mesh-state.json';raw=load(p);state=mesh.load_state_storage(p,raw['network'],raw['node_id']);peer=load(root/'mesh/1/mesh-state.json')['node_id'];records=load(root/'ordinary-process-controller/first-service-events.jsonl',True)
class ReadArchive:
 summaries=mesh.Node.summaries;archive_entry=mesh.Node.archive_entry;_archive_read=mesh.Node._archive_read;archived=mesh.Node.archived
a=ReadArchive();a.id=state['node_id'];a.network=state['network'];a.archive_root=root/'mesh/2/archive';a.state=state
rows=[];descriptions={}
for item in records:
 z=item['record'];diag.check_record(z,sequenced=True)
 if item['slot']!=2 or z['peer']!=peer or z['sequence'] not in (102,107,115):continue
 ids=set(z.get('selected',[]))
 for groups in z['selector']['groups']:
  for g in groups:ids.update(g['current_ids'])
 rows.append(dict(sequence=z['sequence'],selected=z.get('selected',[]),priority=z['priority'],selector=z['selector'],hop_attempts=z['hop_attempts'],suppressed=z['suppressed_ids']))
 for pid in ids:
  if pid in descriptions:continue
  if pid in state['messages']:t=state['messages'][pid];rec=state['receipts'].get(pid);storage='active'
  else:
   ap=a.archive_root/f'{pid}.json';load(ap);blob=a.archived(pid);t=blob['transit'];rec=blob['receipt'];storage='archive'
  packet,payload,visited=mesh.transit_check(t,state['network']);frame,content=wire.inspect_frame(payload)
  if rec:mesh.receipt_check(rec,state['network']);mesh.receipt_matches(rec,t)
  desc=dict(frame_id=frame['message_id'],kind=frame['kind'],source=packet['node_id'],destination=packet['destination'],hops=len(t['hops']),storage=storage,receipt=bool(rec),complete_transit_authenticated=True)
  if frame['kind']=='regional-bft':
   envelope=json.loads(content);body=envelope['body'];v=body.get('Signed',{}).get('Vote');proposal=body.get('Signed',{}).get('Proposal');desc.update(envelope_id=hashlib.sha256(content).hexdigest(),body_id=mesh.digest(body),native_kind=v['phase'] if v else 'Proposal' if proposal else tuple(body),round=v['round'] if v else proposal['round'] if proposal else None,parent_height=v['context']['parent_height'] if v else proposal['snapshot']['statement']['height']-1 if proposal else None)
  descriptions[pid]=desc
assert time.monotonic()<deadline
for path,h in seen.items():assert sha(Path(path))==h
out=e/'regional-bft-relay-selected-frames-v39-20261007-checks.json';assert not out.exists();result=dict(completed=True,rows=rows,packets=descriptions,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6),reader_sha256=sha(Path(__file__)),sealed_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,unique_maturity_cause=False,new180=0,new600=0)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
