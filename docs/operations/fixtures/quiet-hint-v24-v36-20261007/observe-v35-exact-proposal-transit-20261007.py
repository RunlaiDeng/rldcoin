from pathlib import Path
import json,hashlib,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v35-private-20261006';start=time.monotonic();prior20=1.694117;deadline=start+20-prior20;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out=e/'regional-bft-exact-proposal-transit-v35-20261007-checks.json';assert not out.exists();prior=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v35-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v35-stopped-private-inventory-20261006.json';assert sha(seal)==prior['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];read={}
def load(p,lines=False):
 assert time.monotonic()<deadline
 data=p.read_bytes();h=hashlib.sha256(data).hexdigest();assert h==files[str(p.relative_to(root))][0];read[str(p)]=h;return [json.loads(line) for line in data.splitlines()] if lines else json.loads(data)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh
selected=json.loads((e/'regional-bft-exact-proposal-edge-v35-20261007-checks.json').read_text());pid=selected['packet_id'];trace=load(root/'ordinary-process-controller/finite-trace-events.jsonl',True);first=load(root/'ordinary-process-controller/first-service-events.jsonl',True);report=[]
for n in (0,1,2,3):
 p=root/f'mesh/{n}/mesh-state.json';v=load(p);state=mesh.load_state_storage(p,v['network'],v['node_id']);t=state['messages'].get(pid);saved=state['archives'].get(pid);events=[z for z in trace if z['slot']==n and z.get('packet_id')==pid];prepared=[z for z in events if z['stage']=='outgoing_prepared'];contexts=[]
 for z in prepared:
  peer=z['peer'];attempt=z['attempt'];rows=[w for w in trace if w['slot']==n and w.get('peer')==peer and w.get('attempt')==attempt];contexts.append(dict(peer=peer,attempt=attempt,at=z['monotonic_seconds'],stages=[w['stage'] for w in rows],failures=[{k:w[k] for k in ('failure_stage','error_class')} for w in rows if w['stage']=='contact_failed']))
 selections=[dict(sequence=z['record']['sequence'],position=z['record']['selected'].index(pid),retries=len(z['record']['retries'])) for z in first if z['slot']==n and pid in z['record'].get('selected',[])];rejected=[{k:z[k] for k in ('stage','monotonic_seconds','peer','error_class','reason') if k in z} for z in events if z['stage'] in ('inbound_refused','deferred_input_not_queued','deferred_input_queued','deferred_local_custody','inbound_local_custody')];pairrows=[]
 for peer,pair in state['first_carriage'].items():
  if pid in pair['pending'] or pid in pair['arrivals'] or pid in pair['prepared']:pairrows.append(dict(peer=peer,pending_position=pair['pending'].index(pid) if pid in pair['pending'] else None,arrival_position=pair['arrivals'].index(pid) if pid in pair['arrivals'] else None,prepared=pid in pair['prepared']))
 if t:mesh.transit_check(t,state['network'])
 report.append(dict(slot=n,node_id=state['node_id'],exact_active_transit_fully_authenticated=t is not None,exact_archived_index_present=saved is not None,receipt=pid in state['receipts'],events=len(events),selections=selections,prepared=contexts,refused_or_deferred=rejected,final_first_carriage=pairrows))
for p,h in read.items():assert sha(Path(p))==h
assert time.monotonic()<deadline
result=dict(completed=True,exact_packet_id=pid,source=2,destination=0,rows=report,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(time.monotonic()-start+prior20,6),consumed_bytes_unchanged=True,Node_Native_Runtime_key_socket_sign_fixture_calls=0,Native_authority=False,unique_maturity_cause=False,new180=0,new600=0);out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
