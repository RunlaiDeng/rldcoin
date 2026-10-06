import ast,hashlib,json,sys,time
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh
from regional_paged_fault_scope import inventory
seal=b/'bft-current-commit-delivery-v14-stopped-private-inventory-20261006.json';pins=json.loads(seal.read_text());root=Path(next(iter(pins)))/'test_native_context_commit_hint_reaches_destination_via_ordinary_ticks';states=[]
for name in ('earth','proxima','andromeda'):
 p=root/name/'mesh-state.json';v=json.loads(p.read_text());states.append(mesh.load_state_storage(p,v['network'],v['node_id']))
a,c,d=states;targets=[i for i,t in a['messages'].items() if mesh.packet_check(t['packet'],a['network'])[0]['destination']==d['node_id'] and mesh.evidence.inspect_frame(mesh.packet_check(t['packet'],a['network'])[1])[0]['kind']=='regional-bft'];prepared=set(a['first_carriage'][c['node_id']]['prepared']);targets=[i for i in targets if i in prepared];assert len(targets)==1;target=targets[0]
assert target in c['messages'] and target not in d['messages'];assert c['messages'][target]['packet']==a['messages'][target]['packet'];assert sorted((a['node_id'],d['node_id']))[0]==d['node_id']
s=ast.parse((r/'tools/interstellar_mesh.py').read_text());tick=next(n for n in ast.walk(s) if isinstance(n,ast.FunctionDef) and n.name=='tick');assert 'for peer, contact in sorted(self.contacts.items())' in ast.unparse(tick);assert ast.unparse(tick).index('self.receive(bundle, peer)')<ast.unparse(tick).index('self.prepare_exchange(peer)')
assert all(inventory(Path(path))==rows for path,rows in pins.items());duration=time.monotonic()-start;assert duration<10
out=dict(completed=True,budget_seconds=10,attempts=1,duration_seconds=round(duration,6),target_packet_id=target,source_prepared=True,relay_complete_exact_original=True,destination_complete=False,relay_destination_branch_processed_before_source_inbox_branch=True,tick_per_contact_receive_then_prepare=True,failed14_files_unchanged=True,Native_Runtime_Node_socket_key_sign_fixture_calls=0,next_entry_change='Exactly2 relay ordinary ticks before exactly1 destination ordinary tick; source remains1; no protocol mutation, no Native qualification, no repeated same-entry test.')
(e/'regional-bft-current-commit-relay-order-v14-20261006-checks.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
