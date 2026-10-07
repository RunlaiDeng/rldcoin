from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v42-private-20261006';start=time.monotonic();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
prior_path=e/'regional-bft-exact-selector-decision-v42-20261007-checks.json';prior=json.loads(prior_path.read_text());used=prior['combined_original20_seconds'];deadline=start+20-used
stage=e/'regional-bft-selected-current-kinds-v42-20261007-stage.json';out=e/'regional-bft-selected-current-kinds-v42-20261007-checks.json';assert not stage.exists() and not out.exists()
stage.write_text(json.dumps(dict(hypothesis='Classify actual complete selected spare frames before source2 destination1 Proposal first preparation: did checkpoint14 copies consume current spare opportunities alongside parent14 votes/proposal? Exact retained bytes and original full transport/signature checks only; no unique maturity attribution.',original_readonly_budget_seconds=20,prior_seconds=used,attempts=1,exit='first seal/schema/signature guard or remaining original20; no old fixture constructor, sign, socket or Native call'),indent=2)+'\n')
terminal=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v42-20261006-checks.json').read_text());assert terminal['helper_terminal'] and terminal['guardian']['owned_processes_stopped']
seal=b/'native-bft-four-cli-service-first-service-diag-v42-stopped-private-inventory-20261006.json';assert sha(seal)==terminal['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];reads={}
def load(p):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];reads[str(p)]=h;return json.loads(raw)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;import interstellar_transfer as wire
from regional_bft_retention import unpack_state
s=unpack_state(load(root/'runtime/2/state.json'));raw_state=load(root/'mesh/2/mesh-state.json');t=mesh.load_state_storage(root/'mesh/2/mesh-state.json',raw_state['network'],raw_state['node_id'])
class ReadArchive:
 summaries=mesh.Node.summaries;archive_entry=mesh.Node.archive_entry;_archive_read=mesh.Node._archive_read;archived=mesh.Node.archived
arc=ReadArchive();arc.id=t['node_id'];arc.network=t['network'];arc.archive_root=root/'mesh/2/archive';arc.state=t
rows=[]
for row in prior['rows']:
 if not row['priority_pair'] or row['full4_retry'] or row['selected']:continue
 selected=[]
 for pid in row['selected_packet_ids'][2:]:
  if pid in t['messages']:tr=t['messages'][pid];storage='active'
  elif pid in t['archives']:tr=arc.archived(pid)['transit'];storage='archive'
  else:raise AssertionError(('complete original transit missing',pid))
  _,frame,_=mesh.transit_check(tr,t['network']);header,payload=wire.inspect_frame(frame)
  body=None;content=header['export_id']
  if header['kind']=='regional-bft':
   env=wire.decode_json(payload);body=env['body'];ident=mesh.digest(body)
   assert ident in s['messages'] and s['messages'].payload(ident)==payload and s['messages'].content(ident)==content
   if 'Finalized' in body:kind='Finalized';height=body['Finalized']['statement']['height'];round_number=body['Finalized']['bft']['committed']['round']
   elif 'Vote' in body.get('Signed',{}):v=body['Signed']['Vote'];kind=v['phase'];height=v['context']['parent_height'];round_number=v['round']
   elif 'Proposal' in body.get('Signed',{}):v=body['Signed']['Proposal'];kind='Proposal';height=v['snapshot']['statement']['height']-1;round_number=v['round']
   else:kind=next(iter(body));height=None;round_number=None
  else:kind=header['kind'];height=None;round_number=None
  selected.append(dict(packet_id=pid,frame_id=header['message_id'],envelope_id=content,kind=kind,height_or_parent_height=height,round=round_number,destination=tr['packet']['body']['destination'],storage=storage))
 rows.append(dict(sequence=row['sequence'],class_step=row['class_step'],consumed_hint_reads=row['consumed_hint_reads'],selected_spares=selected))
 assert time.monotonic()<deadline
for p,h in reads.items():assert sha(Path(p))==h
result=dict(completed=True,rows=rows,Node_Native_Runtime_socket_key_sign_fixture_calls=0,unique_maturity_cause_proved=False,consumed_sealed_files=len(reads),consumed_bytes_unchanged=True,prior_checks_sha256=sha(prior_path),stopped_inventory_sha256=sha(seal),stage_sha256=sha(stage),reader_sha256=sha(Path(__file__)),duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(used+time.monotonic()-start,6),new180=0,new600=0,full_fault_qualified=False)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
