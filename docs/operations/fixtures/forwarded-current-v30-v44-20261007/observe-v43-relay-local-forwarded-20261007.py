from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v43-private-20261006';start=time.monotonic();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();priorpath=e/'regional-bft-relay-newest-first-service-v43-20261007-checks.json';prior=json.loads(priorpath.read_text());used=prior['combined_original20_seconds'];deadline=start+min(10,20-used);stage=e/'regional-bft-relay-local-forwarded-v43-20261007-stage.json';out=e/'regional-bft-relay-local-forwarded-v43-20261007-checks.json';assert not stage.exists() and not out.exists();stage.write_text(json.dumps(dict(hypothesis='Prepared retransmission displacement hypothesis falsified: all six selected current spares were unprepared. Classify actual complete packet source/destination/full Native retained envelope before adopting any minimum local-versus-forwarded current fairness counter. Target is source3 Prepare carried at relay2 for0.',budget_seconds=10,prior_readonly20_seconds=used,attempts=1,exit='first original full transit/envelope/signature/seal guard or original10/remaining20; no old Node/Native/Runtime/sign/socket/fixture'),indent=2)+'\n')
term=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v43-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v43-stopped-private-inventory-20261006.json';assert term['guardian']['owned_processes_stopped'] and sha(seal)==term['stopped_inventory_sha256'];inv=json.loads(seal.read_text())[str(root)];seen={}
def load(p):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==inv[str(p.relative_to(root))][0];seen[str(p)]=h;return json.loads(raw)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;import interstellar_transfer as wire;from regional_bft_retention import unpack_state
states={i:load(root/f'mesh/{i}/mesh-state.json') for i in range(4)};ids={v['node_id']:i for i,v in states.items()};raw=states[2];t=mesh.load_state_storage(root/'mesh/2/mesh-state.json',raw['network'],raw['node_id']);s=unpack_state(load(root/'runtime/2/state.json'))
class ReadArchive:
 summaries=mesh.Node.summaries;archive_entry=mesh.Node.archive_entry;_archive_read=mesh.Node._archive_read;archived=mesh.Node.archived
arc=ReadArchive();arc.id=t['node_id'];arc.network=t['network'];arc.archive_root=root/'mesh/2/archive';arc.state=t;rows=[]
for row in prior['rows']:
 selected=[]
 for offered in row['spares']:
  pid=offered['packet_id'];tr=t['messages'][pid] if pid in t['messages'] else arc.archived(pid)['transit'];packet,frame,_=mesh.transit_check(tr,t['network']);hdr,payload=wire.inspect_frame(frame);kind=hdr['kind'];height=None
  if kind=='regional-bft':
   env=wire.decode_json(payload);body=env['body'];ident=mesh.digest(body);assert ident in s['messages'] and s['messages'].payload(ident)==payload
   v=body.get('Signed',{}).get('Vote');p=body.get('Signed',{}).get('Proposal')
   if v:kind=v['phase'];height=v['context']['parent_height']
   elif p:kind='Proposal';height=p['snapshot']['statement']['height']-1
   else:kind=next(iter(body))
  selected.append(dict(packet_id=pid,source=ids[packet['node_id']],destination=ids[packet['destination']],forwarded=packet['node_id']!=t['node_id'],kind=kind,parent_height=height,current_frame=offered['current_frame'],prepared_before=offered['prepared_before']))
 rows.append(dict(sequence=row['sequence'],step=row['step'],newest_pair=row['newest_pair'],target_selected=row['target_selected'],spares=selected))
assert time.monotonic()<deadline
for p,h in seen.items():assert sha(Path(p))==h
result=dict(completed=True,rows=rows,prepared_retransmission_starves_target_hypothesis_falsified=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,consumed_sealed_bytes_unchanged=True,unique_maturity_cause_proved=False,reader_sha256=sha(Path(__file__)),stage_sha256=sha(stage),duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(used+time.monotonic()-start,6),new180=0,new600=0);out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
