from pathlib import Path
import json,sys,time,hashlib
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import unpack_state
from regional_bft_joint_epoch import signed_body
from regional_paged_fault_scope import inventory
b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v21-private-20261006';seal=b/'native-bft-four-cli-service-first-service-diag-v21-stopped-private-inventory-20261006.json';stage=json.loads((e/'regional-bft-proposal-transport-boundary-v21-20261006-stage.json').read_text());deadline=float(sys.argv[1]);start=time.monotonic();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def bound():assert time.monotonic()<deadline,'original dependency60 remaining deadline'
def pins():
 bound();assert all(sha(Path(p))==h for p,h in stage['protected_sha256'].items())
 for p,rows in json.loads(seal.read_text()).items():assert inventory(Path(p))==rows
pins();q=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v21-20261006-checks.json').read_text());assert not q['completed'] and q['helper_terminal'] and q['budget_exhausted'] and q['result']['owned_processes_stopped'] and q['result']['services_and_owned_threads_stopped'] and q['pin_error'] is None
states=[];transport=[];nodes=[]
for i in range(4):
 bound();raw=wire.read_file(root/f'runtime/{i}/state.json',32*1024*1024);v=wire.decode_json(raw);assert raw==wire.canonical(v);states.append(unpack_state(v))
 p=root/f'mesh/{i}/mesh-state.json';raw=wire.read_file(p,mesh.MAX_STATE);v=wire.decode_json(raw);assert raw==wire.canonical(v);s=mesh.load_state_storage(p,v['network'],v['node_id']);transport.append(s);nodes.append(s['node_id'])
assert len(set(nodes))==4;network=transport[0]['network'];assert all(s['network']==network for s in transport);assert all(s['binding']['currency']==network for s in states)
proposals=[];locals=[];vote_frontier=[]
for i,st in enumerate(states):
 for ident,body,value,local in st['messages'].bodies():
  bound();signed=signed_body(body);p=signed.get('Proposal');v=signed.get('Vote')
  if p is not None:
   height=p['snapshot']['statement']['height'];assert type(height) is int and 1<=height<=24
   if height not in (14,15):continue
   proposals.append(dict(slot=i,height=height,round=p['round'],local=local,inner_signature_unqualified=True))
   if local:locals.append(dict(source=i,height=height,parent_height=height-1,body_id=ident,content=st['messages'].content(ident),payload=st['messages'].payload(ident)))
  if v is not None and v['context']['parent_height'] in (13,14):vote_frontier.append(dict(slot=i,parent_height=v['context']['parent_height'],phase=v['phase'],round=v['round'],local=local,inner_vote_not_cryptographically_qualified=True))
class ReadArchive:
 summaries=mesh.Node.summaries
 archive_entry=mesh.Node.archive_entry
 _archive_read=mesh.Node._archive_read
 archived=mesh.Node.archived
full=[];indexes=active=0
for i,s in enumerate(transport):
 a=ReadArchive();a.id=s['node_id'];a.network=network;a.archive_root=root/f'mesh/{i}/archive';a.state=s
 files,total=mesh.Node.archive_inventory(a);bound();assert len(files)<=mesh.MAX_ARCHIVE_FILES and total<=mesh.MAX_ARCHIVE_BYTES
 entries={pid:a.archive_entry(v,pid) for pid,v in s['archives'].items()};indexes+=len(entries)
 for pid,entry in entries.items():
  bound();assert entry['file_id'] in files and files[entry['file_id']]==entry['size_bytes']
  if entry['frame_object'] is not None:assert files[entry['frame_object']['file_id']]==entry['frame_object']['size_bytes']
  if entry['kind']!='regional-bft':continue
  blob=a.archived(pid);t=blob['transit'];assert t is not None;packet,raw,visited=mesh.transit_check(t,network);frame,payload=wire.inspect_frame(raw);assert frame['kind']=='regional-bft' and visited[-1]==nodes[i];mesh.receipt_check(blob['receipt'],network);mesh.receipt_matches(blob['receipt'],t)
  full.append(dict(holder=i,packet_id=pid,source=nodes.index(packet['node_id']),destination=nodes.index(packet['destination']),content=frame['export_id'],payload=payload,storage='archive',receipt_present=True))
 for pid,t in s['messages'].items():
  bound();packet,raw,visited=mesh.transit_check(t,network);assert mesh.digest(t['packet'])==pid and visited[-1]==nodes[i];frame,payload=wire.inspect_frame(raw);receipt=s['receipts'].get(pid)
  if receipt is not None:assert mesh.receipt_check(receipt,network)==pid;mesh.receipt_matches(receipt,t);active+=1
  if frame['kind']=='regional-bft':full.append(dict(holder=i,packet_id=pid,source=nodes.index(packet['node_id']),destination=nodes.index(packet['destination']),content=frame['export_id'],payload=payload,storage='active',receipt_present=receipt is not None))
 for pid,receipt in s['receipts'].items():bound();assert mesh.receipt_check(receipt,network)==pid
paths=[];private=[]
for p in locals:
 for dest in range(4):
  if dest==p['source']:continue
  bound();copies=[v for v in full if v['source']==p['source'] and v['destination']==dest and v['content']==p['content'] and v['payload']==p['payload']]
  complete=[v for v in copies if v['holder']==dest and v['receipt_present']]
  retained=any(st['messages'].payload(ident)==p['payload'] for ident,_,_,_ in states[dest]['messages'].bodies())
  paths.append(dict(source=p['source'],destination=dest,height=p['height'],parent_height=p['parent_height'],complete_destination_signed_envelope=bool(complete),complete_transport_copy_count=len(copies),destination_companion_body_retained=retained,Native_acceptance_or_maturity_unqualified=True))
  private.append(dict(source=p['source'],destination=dest,height=p['height'],body_id=p['body_id'],copies=[{k:v for k,v in x.items() if k!='payload'} for x in copies]))
# Exact labels and complete signed transport distinguish retained generation,
# delivery and companion admission. They never establish inner Native validity.
private_path=b/'bft-proposal-transport-boundary-v21-paths-private-20261006.json';assert not private_path.exists();private_path.write_text(json.dumps(private,indent=2)+'\n')
heights=[st['height'] for st in states];assert all(type(h) is int and 0<=h<=24 for h in heights)
pins();print(json.dumps(dict(completed=True,duration_seconds=round(time.monotonic()-start,6),stopped1630_bytes_unchanged=True,reference_companion_heights=heights,proposal_reference_labels=proposals,local_proposal_reference_count=len(locals),vote_reference_labels=vote_frontier,proposal_paths=paths,full_archive_index_entries_authenticated=indexes,complete_regional_bft_transport_copies_authenticated=len(full),active_receipts_authenticated=active,private_exact_paths_sha256=sha(private_path),Node_Runtime_Native_socket_key_sign_or_fixture_calls=0,inner_Proposal_or_Vote_signatures_unqualified=True,Native_ledger_acceptance_maturity_or_latest_cold_authority=False,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False),sort_keys=True))
