from pathlib import Path
import ast,builtins,dis,hashlib,json,sys,time,types
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh
from regional_paged_fault_scope import inventory
start=time.monotonic();deadline=float(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();stage=json.loads((e/'regional-bft-ordinary-delivery-source-boundary-v2-20261006-stage.json').read_text());pins=stage['protected_sha256']
def check():
 assert time.monotonic()<deadline,'original dependency60 remaining source-boundary deadline'
 assert all(sha(Path(p))==v for p,v in pins.items())
check();root=b/'unserved-promotion-ordinary-delivery-v2-v12-private-20261006';seal=b/'unserved-promotion-ordinary-delivery-v2-v12-stopped-private-inventory-20261006.json';rows=json.loads(seal.read_text());assert sum(len(v) for v in rows.values())==15 and all(inventory(Path(p))==v for p,v in rows.items());state_path=[root/path for path in rows[str(root)] if path.endswith('/proxima/mesh-state.json')];assert len(state_path)==1;p=state_path[0];ground=p.parent.parent;source_header=json.loads(p.read_text());destp=ground/'earth/mesh-state.json';dest_header=json.loads(destp.read_text());network=source_header['network'];source=source_header['node_id'];dest=dest_header['node_id'];source_state=mesh.load_state_storage(p,network,source);dest_state=mesh.load_state_storage(destp,network,dest);target=source_state['first_arrivals'][-1];original=source_state['messages'][target];packet,frame,_=mesh.transit_check(original,network);assert packet['node_id']==source and packet['destination']==dest and len(source_state['first_arrivals'])==33;outbox=ground/'links/proxima-earth';bundles=[]
for path in outbox.glob('*.json'):
 body=mesh.verify(mesh.load(path,mesh.MAX_BATCH),'exchange',network);assert (body['node_id'],body['to'])==(source,dest) and path.stem==mesh.digest(mesh.load(path,mesh.MAX_BATCH))
 for candidate in body['transits']:
  if mesh.digest(candidate['packet'])!=target:continue
  p2,raw,visited=mesh.transit_check(candidate,network,recipient=dest,sender=source);assert raw==frame and candidate['packet']==original['packet'] and candidate['routing']==original['routing'] and len(candidate['hops'])==1 and len(body['transits'])==4;assert candidate['hops'][:-1]==original['hops'];bundles.append(dict(exchange_sha256=sha(path),transit_sha256=mesh.digest(candidate),target_index=body['transits'].index(candidate)))
assert len(bundles)==1 and target in source_state['first_carriage'][dest]['prepared'] and target not in source_state['first_carriage'][dest]['pending'];assert target not in dest_state['messages'] and target not in dest_state['receipts'];assert not dest_state['archives']
# Actual generated function/global resolution; do not construct a fixture or
# execute unittest/Node. This directly addresses the measured NameError only.
import test_interstellar_mesh as tests
h2=b/'observe-bft-unserved-promotion-ordinary-delivery-v2-unallocated-20261006.py';h3=b/'observe-bft-unserved-promotion-ordinary-delivery-v3-unallocated-20261006.py';before="namespace=dict(vars(tests));namespace['sha']=sha;exec(";after="namespace=dict(vars(tests));namespace['sha']=sha;namespace['tests']=tests;exec(";assert h3.read_text().replace(after,before).replace('unserved-promotion-ordinary-delivery-v3-v12-private-20261006','unserved-promotion-ordinary-delivery-v2-v12-private-20261006')==h2.read_text();module=ast.parse(h3.read_text());parts=[];active=False
for n in module.body:
 if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=='tree' for v in n.targets):active=True
 if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=='DeliveryCase' for v in n.targets):break
 if active:parts.append(n)
ns={'r':r,'ast':ast,'tests':tests,'sha':sha};exec(compile(ast.fix_missing_locations(ast.Module(body=parts,type_ignores=[])),'corrected-delivery-function-globals','exec'),ns);fn=ns['namespace']['test_promoted_latest_waiter_keeps_priority_until_prepared'];assert isinstance(fn,types.FunctionType);names=set()
def globals_in(code):
 for op in dis.get_instructions(code):
  if op.opname=='LOAD_GLOBAL':names.add(op.argval)
 for value in code.co_consts:
  if isinstance(value,types.CodeType):globals_in(value)
globals_in(fn.__code__);assert 'tests' in names and all(name in fn.__globals__ or hasattr(builtins,name) for name in names)
assert not (b/'unserved-promotion-ordinary-delivery-v3-v12-private-20261006').exists();assert all(inventory(Path(p))==v for p,v in rows.items());check()
print(json.dumps(dict(completed=True,duration_seconds=round(time.monotonic()-start,6),failed15_bytes_unchanged=True,failed_Node_Runtime_Native_cold_reopens=0,actual_ground_source_reference=dict(target_packet_id=target,source_ordinary_tick_completed=True,original_target_durably_prepared=True,target_selected_in_complete4_signed_exchange=True,target_ordinary_index=bundles[0]['target_index'],source_signed_packet_route_original_frame_exact=True,complete_original_hop_authenticated=True,exchange=bundles[0],frame_sha256=hashlib.sha256(frame).hexdigest(),destination_reference_has_no_target_or_receipt=True,not_latest_native_or_destination_authority=True),single_namespace_binding_and_fresh_root_fix_only=True,actual_generated_function_recursive_LOAD_GLOBAL_names=sorted(names),all_actual_global_providers_resolved=True,generated_function_not_executed=True,new_v3_fixture_unallocated_absent=True,production192_Native89_Core171_binary_unchanged=True,ordinary_destination_delivery='unknown',candidate_protocol_failure_not_inferred_from_NamespaceError=True,unseen_prior_pending_pair_order_not_reconstructed=True,Native_Runtime_Node_socket_key_sign_fixture_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False),sort_keys=True))
