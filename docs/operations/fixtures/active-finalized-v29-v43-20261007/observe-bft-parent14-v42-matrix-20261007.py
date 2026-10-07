import hashlib,json,sys,time
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v42-private-20261006';start=time.monotonic();deadline=start+(20)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();stage=e/'regional-bft-parent14-v42-matrix-20261007-stage.json';out=e/'regional-bft-parent14-v42-matrix-20261007-checks.json';assert not stage.exists() and not out.exists()
stage.write_text(json.dumps(dict(budget_seconds=20,attempts=1,hypothesis='After V26 stable current frame-set rotation, distinguish old Commit3to0 analogue completed from absence at source or incomplete destination transport, determine complete actual height14 Proposal/Prepare/Commit transport matrix and next missing exact edge; distinguish absent local current-context round0..31 Proposal/Prepare/Commit generation from exact companion retention and complete destination transport. This selects one missing edge; neither absent logs nor saved height grants Native authority.',exit='first sealed-byte/signature/context guard, exact bounded4-node matrix or original20 deadline; no constructors/signatures/transport/fixture/new180/600',reader_sha256=sha(Path(__file__))),indent=2)+'\n')
prior=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v42-20261006-checks.json').read_text());assert not prior['completed'] and prior['guardian']['owned_processes_stopped']
seal=b/'native-bft-four-cli-service-first-service-diag-v42-stopped-private-inventory-20261006.json';assert sha(seal)==prior['stopped_inventory_sha256'];inventory=json.loads(seal.read_text())[str(root)];read={}
def load(p):
 rel=str(p.relative_to(root));assert sha(p)==inventory[rel][0];read[rel]=sha(p);return json.loads(p.read_text())
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;import interstellar_transfer as wire;from regional_bft_retention import unpack_state
states={i:unpack_state(load(root/f'runtime/{i}/state.json')) for i in range(4)};configs={i:load(root/f'component-bft-config-{i}.json') for i in range(4)};transport=[]
for i in range(4):
 p=root/f'mesh/{i}/mesh-state.json';v=load(p);transport.append(mesh.load_state_storage(p,v['network'],v['node_id']))
keys=tuple(x['key'] for x in configs[0]['validators']);assert all(tuple(x['key'] for x in c['validators'])==keys for c in configs.values());rows=[]
class ReadArchive:
 summaries=mesh.Node.summaries;archive_entry=mesh.Node.archive_entry;_archive_read=mesh.Node._archive_read;archived=mesh.Node.archived
for src,s in states.items():
 for ident,body,_,owned in s['messages'].bodies():
  if not owned:continue
  v=body.get('Signed',{}).get('Vote');p=body.get('Signed',{}).get('Proposal')
  if v and v['context']['parent_height']==14 and type(v['round']) is int and 0<=v['round']<=31:
   ctx=v['context'];fields=('currency','region','epoch','previous','parent_height','parent_block','parent_state');assert v['approval']['key']==keys[src]
   data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps([{k:ctx[k] for k in fields},v['round'],v['value'],v['phase'],keys[src]],separators=(',',':'),ensure_ascii=False).encode();mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys[src])).verify(bytes.fromhex(v['approval']['signature']),data);kind=v['phase'];context_hash=hashlib.sha256(json.dumps(ctx,sort_keys=True,separators=(',',':')).encode()).hexdigest();value=v['value']
  elif p and p['snapshot']['statement']['height']==15 and type(p['round']) is int and 0<=p['round']<=31:kind='Proposal';context_hash=None;value=None
  else:continue
  assert time.monotonic()<deadline;payload=s['messages'].payload(ident);content=s['messages'].content(ident);destrows=[]
  for dst,t in enumerate(transport):
   if dst==src:continue
   copies=[];a=ReadArchive();a.id=t['node_id'];a.network=t['network'];a.archive_root=root/f'mesh/{dst}/archive';a.state=t
   for pid,index in t['archives'].items():
    z=index['body']
    if z['kind']=='regional-bft' and z['source']==transport[src]['node_id'] and z['destination']==t['node_id'] and z['export_id']==content:
     ap=a.archive_root/f'{pid}.json'
     blob=a.archived(pid);tr=blob['transit'];receipt=blob['receipt'];_,raw,_=mesh.transit_check(tr,t['network']);_,carried=wire.inspect_frame(raw);assert carried==payload;mesh.receipt_check(receipt,t['network']);mesh.receipt_matches(receipt,tr);copies.append(dict(packet_id=pid,storage='archive',receipt=True))
   for pid,tr in t['messages'].items():
    z=tr['packet']['body']
    if z['node_id']!=transport[src]['node_id'] or z['destination']!=t['node_id']:continue
    _,raw,_=mesh.transit_check(tr,t['network']);frame,carried=wire.inspect_frame(raw)
    if frame['kind']!='regional-bft' or frame['export_id']!=content:continue
    assert carried==payload;receipt=t['receipts'].get(pid)
    if receipt is not None:mesh.receipt_check(receipt,t['network']);mesh.receipt_matches(receipt,tr)
    copies.append(dict(packet_id=pid,storage='active',receipt=receipt is not None))
   destrows.append(dict(destination=dst,exact_companion=ident in states[dst]['messages'] and states[dst]['messages'].payload(ident)==payload,complete_transport=copies))
  rows.append(dict(source=src,kind=kind,round=(v['round'] if v else p['round']),body_id=ident,envelope_id=content,context_sha256=context_hash,value=value,inner_vote_signature_verified=bool(v),destinations=destrows))
assert time.monotonic()<deadline
for rel,h in read.items():assert sha(root/rel)==h
result=dict(completed=True,shared_original_readonly20_prior_seconds=0.0,combined_original_readonly20_seconds=round(0.0+time.monotonic()-start,6),duration_seconds=round(time.monotonic()-start,6),budget_seconds=20,attempts=1,reference_heights=[states[i]['height'] for i in range(4)],rows=rows,consumed_sealed_files=len(read),consumed_bytes_unchanged=True,stage_sha256=sha(stage),stopped_inventory_sha256=sha(seal),Node_Native_Runtime_socket_key_sign_fixture_calls=0,proposal_inner_signature_or_Native_acceptance_qualified=False,unique_maturity_cause_proved=False,new180=0,new600=0,full_fault_qualified=False)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
