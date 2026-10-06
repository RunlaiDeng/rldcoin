from pathlib import Path
import sys,json,time,hashlib,copy,importlib.util
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import unpack_state
from regional_bft_joint_epoch import signed_body
from regional_paged_fault_scope import inventory
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v21-private-20261006';seal=b/'native-bft-four-cli-service-first-service-diag-v21-stopped-private-inventory-20261006.json';stage=json.loads((e/'regional-bft-single-commit-boundary-v21-20261006-stage.json').read_text());start=time.monotonic();deadline=float(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def bound():assert time.monotonic()<deadline,'single Commit original20 deadline'
def pins():
 bound();assert all(sha(Path(p))==h for p,h in stage['protected_sha256'].items())
 for p,rows in json.loads(seal.read_text()).items():assert inventory(Path(p))==rows
pins();previous=json.loads((e/'regional-bft-proposal-transport-boundary-v21-v2-20261006-checks.json').read_text());assert previous['completed'] and previous['combined_stage_seconds']==59.845831 and previous['result']['complete_regional_bft_transport_copies_authenticated']==859 and previous['result']['full_archive_index_entries_authenticated']==643
states={};transport=[];nodes=[]
for i in range(4):
 bound();p=root/f'mesh/{i}/mesh-state.json';raw=wire.read_file(p,mesh.MAX_STATE);v=wire.decode_json(raw);assert raw==wire.canonical(v);state=mesh.load_state_storage(p,v['network'],v['node_id']);transport.append(state);nodes.append(state['node_id'])
 if i in (1,2):
  raw=wire.read_file(root/f'runtime/{i}/state.json',32*1024*1024);v=wire.decode_json(raw);assert raw==wire.canonical(v);states[i]=unpack_state(v)
network=transport[2]['network'];assert len(set(nodes))==4 and all(s['network']==network for s in transport);assert all(s['binding']['currency']==network and s['height']==13 for s in states.values())
keys=[v['key'] for v in wire.decode_json(wire.read_file(root/'component-bft-config-2.json',192*1024))['validators']];assert len(set(keys))==4
matches=[]
for ident,body,value,local in states[2]['messages'].bodies():
 bound();v=signed_body(body).get('Vote')
 if local and v is not None and v['phase']=='Commit' and v['context']['parent_height']==13 and v['round']==0:matches.append((ident,v,value))
assert len(matches)==1,'ambiguous or missing exact local source2 parent13 Commit'
ident,v,value=matches[0];fields=('currency','region','epoch','previous','parent_height','parent_block','parent_state')
assert set(v)=={'context','round','value','phase','approval'} and set(v['context'])==set(fields) and type(v['round']) is int and v['round']==0
assert set(v['approval'])=={'key','signature'} and v['approval']['key']==keys[2]
assert v['context']['currency']==network and v['context']['region']==states[2]['binding']['region'] and v['context']['parent_block']==states[2]['tip']==states[1]['tip']
def vote_bytes(x):return b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+json.dumps([{k:x['context'][k] for k in fields},x['round'],x['value'],x['phase'],x['approval']['key']],separators=(',',':'),ensure_ascii=False).encode()
public=Ed25519PublicKey.from_public_bytes(bytes.fromhex(v['approval']['key']));public.verify(bytes.fromhex(v['approval']['signature']),vote_bytes(v))
bad=copy.deepcopy(v);bad['phase']='Prepare'
try:public.verify(bytes.fromhex(bad['approval']['signature']),vote_bytes(bad));raise AssertionError('altered phase signature accepted')
except InvalidSignature:pass
payload=states[2]['messages'].payload(ident);content=states[2]['messages'].content(ident)
retained=[]
for target,body,_,local in states[1]['messages'].bodies():
 bound()
 if states[1]['messages'].payload(target)==payload:retained.append(dict(body_id=target,local=local))
class ReadArchive:
 summaries=mesh.Node.summaries
 archive_entry=mesh.Node.archive_entry
 _archive_read=mesh.Node._archive_read
 archived=mesh.Node.archived
copies=[];variant_count=0;reused_index_count=0
for holder,s in enumerate(transport):
 bound();a=ReadArchive();a.id=nodes[holder];a.network=network;a.archive_root=root/f'mesh/{holder}/archive';a.state=s
 # Index fields are already authenticated by the immutable prior859/643 scope;
 # exact sealed state bytes are rechecked, not all index/transport signatures.
 for packet_id,signed in s['archives'].items():
  body=signed['body'];reused_index_count+=1
  if body['kind']!='regional-bft' or body['source']!=nodes[2] or body['destination']!=nodes[1] or body['export_id']!=content:continue
  bound();blob=a.archived(packet_id);t=blob['transit'];packet,raw,visited=mesh.transit_check(t,network);frame,data=wire.inspect_frame(raw);assert frame['kind']=='regional-bft' and frame['export_id']==content and visited[-1]==nodes[holder] and packet['node_id']==nodes[2] and packet['destination']==nodes[1];mesh.receipt_check(blob['receipt'],network);mesh.receipt_matches(blob['receipt'],t)
  if data!=payload:variant_count+=1;continue
  copies.append(dict(holder=holder,packet_id=packet_id,storage='archive',complete=True,receipt_present=True,transit_digest=mesh.digest(t),frame_sha256=hashlib.sha256(raw).hexdigest()))
 for packet_id,t in s['messages'].items():
  body=t['packet']['body']
  if body['node_id']!=nodes[2] or body['destination']!=nodes[1]:continue
  bound();packet,raw,visited=mesh.transit_check(t,network);frame,data=wire.inspect_frame(raw)
  if frame['kind']!='regional-bft' or frame['export_id']!=content:continue
  assert visited[-1]==nodes[holder] and mesh.digest(t['packet'])==packet_id
  if data!=payload:variant_count+=1;continue
  receipt=s['receipts'].get(packet_id)
  if receipt is not None:assert mesh.receipt_check(receipt,network)==packet_id;mesh.receipt_matches(receipt,t)
  copies.append(dict(holder=holder,packet_id=packet_id,storage='active',complete=True,receipt_present=receipt is not None,transit_digest=mesh.digest(t),frame_sha256=hashlib.sha256(raw).hexdigest()))
assert reused_index_count==643
source_copies=[x for x in copies if x['holder']==2];assert source_copies,'exact local Commit has no complete source envelope'
destination=[x for x in copies if x['holder']==1 and x['receipt_present']];source_ids={x['packet_id'] for x in source_copies}
observer=b/'first_service_diagnostic_observer_v3_20261006.py';spec=importlib.util.spec_from_file_location('single_commit_schema',observer);schema=importlib.util.module_from_spec(spec);spec.loader.exec_module(schema)
p=root/'ordinary-process-controller/first-service-journal.json';snapshot=wire.decode_json(wire.read_file(p,192*1024));assert snapshot['closed'] and snapshot['failed'] and snapshot['authority'] is False and snapshot['ledger_acceptance_known'] is False
raw=wire.read_file(root/'ordinary-process-controller/first-service-events.jsonl',8*1024*1024);assert hashlib.sha256(raw).hexdigest()==snapshot['journal_sha256'] and len(raw)==snapshot['journal_bytes'];last={i:0 for i in range(4)};target_rows=[];count=0
for line in raw.splitlines():
 bound();row=wire.decode_json(line);assert line==schema.encode(row) and set(row)=={'record','slot'} and type(row['slot']) is int and row['slot'] in last;z=row['record'];schema.check_record(z,sequenced=True);slot=row['slot'];assert z['sequence']==last[slot]+1;last[slot]+=1;count+=1
 if slot!=2 or z['peer']!=nodes[1]:continue
 for packet_id in source_ids:
  if any(packet_id in m[k] for m in [z['before'],*z['plans'],z.get('after',z['before'])] for k in ['pending','arrivals','prepared']) or any(packet_id in z.get(k,[]) for k in ['selected','retries','suppressed_ids','hop_attempts']):
   target_rows.append(dict(packet_id=packet_id,sequence=z['sequence'],role=z['role'],completed=z['completed'],selected=packet_id in z.get('selected',[]),hop_attempts=z['hop_attempts'].get(packet_id,0),suppressed=packet_id in z['suppressed_ids'],pending_positions=[m['pending'].index(packet_id) if packet_id in m['pending'] else None for m in z['plans']],arrival_positions=[m['arrivals'].index(packet_id) if packet_id in m['arrivals'] else None for m in z['plans']]))
assert count==snapshot['events'] and {str(k):n for k,n in last.items()}==snapshot['through_sequence'];binding=snapshot['bindings']['2'];assert binding['slot']==2 and binding['process_id']==35047 and binding['scope']==str(root)
pair=transport[2]['first_carriage'][nodes[1]];current=[]
for pid in sorted(source_ids):current.append(dict(packet_id=pid,pending_position=pair['pending'].index(pid) if pid in pair['pending'] else None,prepared=pid in pair['prepared'],global_arrival_position=transport[2]['first_arrivals'].index(pid) if pid in transport[2]['first_arrivals'] else None,observed=pid in pair['observed'] if pair['observed'] is not None else None))
classification='complete_delivered_companion_retained' if destination and retained else 'complete_delivered_companion_not_retained' if destination else 'complete_destination_envelope_absent_in_sealed_store'
pins();print(json.dumps(dict(completed=True,duration_seconds=round(time.monotonic()-start,6),target=dict(source=2,destination=1,parent_height=13,round=0,phase='Commit',body_id=ident,content_id=content,exact_payload_sha256=hashlib.sha256(payload).hexdigest(),vote_signed_bytes_sha256=hashlib.sha256(vote_bytes(v)).hexdigest(),exact_Commit_signature_verified=True,context_matches_source_and_destination_reference_tip=True,altered_phase_signature_refused=True),classification=classification,exact_complete_transport_copies=copies,complete_destination_receipt_count=len(destination),destination_exact_companion_body_retained=bool(retained),alternate_same_content_payload_count=variant_count,current_source_pair=current,typed_prepare_prefix=dict(closed_failed_not_complete_authority=True,records=count,source2_process_id=binding['process_id'],target_records=target_rows,total_selected=sum(x['selected'] for x in target_rows),total_hop_attempts=sum(x['hop_attempts'] for x in target_rows)),old859_transport_643_index_authentication_reused_not_repeated=True,stopped1630_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,Native_inner_key_subgroup_lock_quorum_acceptance_maturity_or_latest_cold_authority=False,Native_admission_rejection_or_unique_OS_schedule_cause_proved=False,prior_source60_terminal_seconds_unchanged=59.845831,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False),sort_keys=True))
