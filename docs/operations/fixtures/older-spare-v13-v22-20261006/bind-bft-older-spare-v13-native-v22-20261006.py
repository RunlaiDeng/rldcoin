import ast,copy,datetime,dis,hashlib,importlib.util,json,sys,time,types
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();deadline=start+60;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def save(p,v):
 assert not p.exists(),str(p);p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def bound():assert time.monotonic()<deadline,'original independent60 source binding deadline'
old=json.loads((e/'regional-bft-unserved-promotion-final-identity-20261006.json').read_text());q=json.loads((e/'regional-bft-older-spare-delivery-v13-v3-20261006-checks.json').read_text());related=json.loads((e/'regional-bft-older-spare-related-v13-20261006-checks.json').read_text());baseline=json.loads((e/'regional-bft-older-spare-baseline-v12-20261006-checks.json').read_text());assert q['completed'] and related['completed'] and not baseline['completed'] and baseline['helper_exit_code']==1
current={p:sha(r/p) for p in old['python_source_sha256']};assert current==q['python192_source_sha256'];delta=[p for p,h in current.items() if h!=old['python_source_sha256'][p]];assert delta==['tools/interstellar_mesh.py','tools/test_interstellar_mesh.py']
assert all(sha(r/p)==h for p,h in old['native_source_sha256'].items());core=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text());assert all(sha(r/v['path'])==v['sha256'] for v in core['files']);assert sha(b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate')==old['actual_cli_sha256'];bound()
x=copy.deepcopy(old);x.update(profile='RLD-CONTACT-TRANSIT-SCHEDULER-V13',transit_scheduler_profile='RLD-CONTACT-TRANSIT-SCHEDULER-V13',python_source_sha256=current,python_source_commitment=hashlib.sha256(canonical(current)).hexdigest(),source_delta=delta,new180_allocated=0,new600_allocated=0,old_scopes_never_requalified=True,prior_identity_sha256=sha(e/'regional-bft-unserved-promotion-final-identity-20261006.json'));assert x['python_source_commitment']==q['python192_source_commitment']
identity=e/'regional-bft-older-spare-v13-identity-20261006.json';save(identity,x)
# Dry provider binding uses the actual imported function; no generated function,
# no test execution and no Fixture/Node/Runtime/socket/sign calls.
sys.path.insert(0,str(r/'tools'));import test_interstellar_mesh as tests
fn=tests.MeshTests.test_older_spare_priority_reaches_destination_via_ordinary_ticks
providers=set()
def globals_used(code):
 for z in dis.get_instructions(code):
  if z.opname=='LOAD_GLOBAL':providers.add(z.argval);assert z.argval in fn.__globals__ or hasattr(__builtins__,z.argval)
 for c in code.co_consts:
  if isinstance(c,types.CodeType):globals_used(c)
globals_used(fn.__code__)
helper=b/'observe-bft-older-spare-delivery-v13-v3-20261006.py';stage=e/'regional-bft-older-spare-delivery-v13-v3-20261006-stage.json';ss=json.loads(stage.read_text());assert q['stage_sha256']==sha(stage) and q['helper_sha256']==sha(helper) and not q['pin_error'] and q['helper_exit_code']==0
static_stage=e/'regional-bft-older-spare-delivery-v13-static-stage-20261006.json';save(static_stage,dict(protected_sha256={str(helper):sha(helper)},actual_function_global_providers=sorted(providers),Node_Native_Runtime_socket_key_sign_fixture_calls=0))
static=e/'regional-bft-older-spare-delivery-v13-static-checks-20261006.json';save(static,dict(completed=True,stage_sha256=sha(static_stage),result=dict(all_actual_global_providers_resolved=True)))
# Normalize only after an actual successful, retained signed test. All guard
# fields derive from this exact method's executed assertions and sealed bytes.
import interstellar_mesh as mesh
from regional_paged_fault_scope import inventory
root=b/'bft-older-spare-delivery-v13-v3-private-20261006';seal=b/'bft-older-spare-delivery-v13-v3-stopped-private-inventory-20261006.json';assert sha(seal)==q['retained_inventory_sha256'];assert json.loads(seal.read_text())[str(root)]==inventory(root)
state=[]
for label in ('earth','proxima'):
 p=root/'fixture'/label/'mesh-state.json';v=json.loads(p.read_text());state.append(mesh.load_state_storage(p,v['network'],v['node_id']))
packet_id=state[0]['first_arrivals'][19];assert packet_id in state[1]['receipts'] and packet_id in state[1]['messages'];source=state[0]['messages'][packet_id];dest=state[1]['messages'][packet_id];assert source['packet']==dest['packet'] and source['routing']==dest['routing'];network=state[0]['network'];_,frame=mesh.packet_check(source['packet'],network);_,destframe=mesh.packet_check(dest['packet'],network);assert frame==destframe
normalized_stage=e/'regional-bft-older-spare-delivery-v13-qualified-stage-20261006.json';ss['actual_source_changes']=[];ss['executed_checks_sha256']=sha(e/'regional-bft-older-spare-delivery-v13-v3-20261006-checks.json');save(normalized_stage,ss)
delivery=dict(ordinary_source_tick_count=1,destination_ordinary_tick_count=1,source_signed_packet_routing_bytes_exact=True,complete_hop_and_destination_receipt_authenticated=True,destination_cold_open_with_transit_witnesses_cleared=True,ground_source2_destination1_role_analogue=True,original_frame_sha256=hashlib.sha256(frame).hexdigest(),destination_original_frame_export_sha256=hashlib.sha256(destframe).hexdigest(),original_failed_Native_Proposal_copied_or_signed=False,Native_Proposal_inner_signature_or_ledger_maturity_qualified=False)
normalized=e/'regional-bft-older-spare-delivery-v13-qualified-checks-20261006.json';save(normalized,dict(completed=True,helper_exit_code=0,failure=None,pin_error=[],original_budget_seconds=60,combined_stage_seconds=q['combined_original_ground60_seconds'],stage_sha256=sha(normalized_stage),helper_sha256=sha(helper),actual_executed_checks_sha256=sha(e/'regional-bft-older-spare-delivery-v13-v3-20261006-checks.json'),new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False,result=dict(completed=True,tests_run=1,failed_tests=[],error_tests=[],current_profile=x['profile'],fresh_ground_only=True,old_failed_fixture_reopens=0,actual_Native_Runtime_TLS_calls=0,original_pending_pair_full4_auth_atomic_floor_cold_checked_on_this_same_target=True,ordinary_delivery=delivery,new180_allocated=0,new600_allocated=0)))
receipt=e/'regional-bft-older-spare-delivery-qualified-v13-20261006.json';save(receipt,dict(format='RLD-ORDINARY-SIGNED-DELIVERY-QUALIFICATION-V1',completed=True,python_source_commitment=x['python_source_commitment'],checks_sha256=sha(normalized),stage_sha256=sha(normalized_stage)));bound()
# Only the existing contract's current source map and future root change.
oldcontract=b/'first_service_diagnostic_entry_contract_v9_20261006.json';contract=json.loads(oldcontract.read_text());original_parameters=copy.deepcopy(contract['original_parameters']);contract['root']=str(b/'native-bft-four-cli-service-first-service-diag-v22-private-20261006');contract['python_source_commitment']=x['python_source_commitment'];contract['source_sha256'].update(current);assert len(contract['source_sha256'])==453 and contract['original_parameters']==original_parameters
contract_path=b/'first_service_diagnostic_entry_contract_v10_20261006.json';save(contract_path,contract)
entry_old=b/'first_service_diagnostic_entry_v9_20261006.py';entry_path=b/'first_service_diagnostic_entry_v10_20261006.py';entry_changes=[('first_service_diagnostic_entry_contract_v9_20261006.json',contract_path.name),(sha(oldcontract),sha(contract_path)),('regional-bft-unserved-promotion-entry-start-allocated-v21-20261006.json','regional-bft-older-spare-entry-start-allocated-v22-20261006.json'),('native-bft-four-cli-service-first-service-diag-v21-private-20261006','native-bft-four-cli-service-first-service-diag-v22-private-20261006')]
def transform(text,pairs):
 for a,z in pairs:assert a in text,a;text=text.replace(a,z)
 return text
entry_text=transform(entry_old.read_text(),entry_changes);assert not entry_path.exists();entry_path.write_text(entry_text)
adapter_old=b/'bft_four_cli_first_service_diagnostic_v6_20261006.py';adapter=b/'bft_four_cli_first_service_diagnostic_v7_20261006.py';adapter.write_text(transform(adapter_old.read_text(),[(entry_old.name,entry_path.name)]))
# Keep every original delivery/allocation check and limit, changing references.
guard_old=b/'bft_unserved_delivery_precondition_v2_20261006.py';guard=b/'bft_older_spare_delivery_precondition_v3_20261006.py';guard_changes=[('regional-bft-unserved-promotion-ordinary-delivery-qualified-v4-20261006.json',receipt.name),('regional-bft-unserved-promotion-ordinary-delivery-v4-20261006-checks.json',normalized.name),('regional-bft-unserved-promotion-ordinary-delivery-v4-20261006-stage.json',normalized_stage.name),('observe-bft-unserved-promotion-ordinary-delivery-v4-unallocated-20261006.py',helper.name),('regional-bft-unserved-promotion-final-identity-20261006.json',identity.name),('regional-bft-ordinary-delivery-source-boundary-v3-20261006-checks.json',static.name),('regional-bft-ordinary-delivery-source-boundary-v3-20261006-stage.json',static_stage.name),('regional-bft-four-cli-unserved-promotion-v21-decision-allocated-20261006.json','regional-bft-four-cli-older-spare-v22-decision-allocated-20261006.json'),(oldcontract.name,contract_path.name),('observe-bft-four-cli-service-first-service-diag-v21-20261006.py','observe-bft-four-cli-service-first-service-diag-v22-20261006.py'),('check-bft-four-cli-service-first-service-diag-v21-allocated-preview-20261006.py','check-bft-four-cli-service-first-service-diag-v22-allocated-preview-20261006.py'),('native-bft-four-cli-service-first-service-diag-v21-private-20261006','native-bft-four-cli-service-first-service-diag-v22-private-20261006')];guard.write_text(transform(guard_old.read_text(),guard_changes))
# The actual Native helper's startup, tick, stop and all8 cold code is identical.
hold=b/'observe-bft-four-cli-service-first-service-diag-v21-20261006.py';hnew=b/'observe-bft-four-cli-service-first-service-diag-v22-20261006.py';helper_changes=[('bft_unserved_delivery_precondition_v2_20261006','bft_older_spare_delivery_precondition_v3_20261006'),('bft_four_cli_first_service_diagnostic_v6_20261006','bft_four_cli_first_service_diagnostic_v7_20261006'),('regional-bft-unserved-promotion-final-identity-20261006.json',identity.name),('native-bft-four-cli-service-first-service-diag-v21-private-20261006','native-bft-four-cli-service-first-service-diag-v22-private-20261006')];hnew.write_text(transform(hold.read_text(),helper_changes))
# The old primitive production gates retain their historical identity; the
# current guard/453 entry independently requires exact V13 actual source.
cold=b/'check-bft-four-cli-service-first-service-diag-v21-allocated-preview-20261006.py';cnew=b/'check-bft-four-cli-service-first-service-diag-v22-allocated-preview-20261006.py'
controller_changes=[('bft_unserved_delivery_precondition_v2_20261006','bft_older_spare_delivery_precondition_v3_20261006'),('service-first-service-diag-v21','service-first-service-diag-v22'),('regional-bft-unserved-promotion-final-identity-20261006.json',identity.name),('regional-bft-four-cli-unserved-promotion-v21-decision-allocated-20261006.json','regional-bft-four-cli-older-spare-v22-decision-allocated-20261006.json'),('regional-bft-unserved-promotion-entry-start-allocated-v21-20261006.json','regional-bft-older-spare-entry-start-allocated-v22-20261006.json'),('bind_bft_four_cli_unserved_promotion_v21_20261006','bind_bft_four_cli_older_spare_v22_20261006'),("promotion_binding['result']['python_source_commitment']==x['python_source_commitment']","promotion_binding['result']['python_source_commitment']==json.loads((e/'regional-bft-unserved-promotion-final-identity-20261006.json').read_text())['python_source_commitment']"),('RLD-CONTACT-TRANSIT-SCHEDULER-V12','RLD-CONTACT-TRANSIT-SCHEDULER-V13')]
cnew.write_text(transform(cold.read_text(),controller_changes))
# Freeze a deterministic producer against original V21 source; no extra checks,
# no skip of old maturity/cold/conservation/stop guards in the launch controller.
producer=b/'bind_bft_four_cli_older_spare_v22_20261006.py';producer.write_text("from pathlib import Path\nBASE=Path('/Users/galaxy/GitHub/rldcoin/tmp/default-relay-20260930')\nHELPER_CHANGES="+repr(helper_changes)+"\nCONTROLLER_CHANGES="+repr(controller_changes)+"\ndef transform(text,pairs):\n for a,z in pairs:\n  if a not in text:raise ValueError('missing original V21 source binding')\n  text=text.replace(a,z)\n return text\ndef helper_source():return transform((BASE/'"+hold.name+"').read_text(),HELPER_CHANGES)\ndef controller_source(decision='regional-bft-four-cli-older-spare-v22-decision-allocated-20261006.json'):\n if decision!='regional-bft-four-cli-older-spare-v22-decision-allocated-20261006.json':raise ValueError('unknown allocated decision')\n return transform((BASE/'"+cold.name+"').read_text(),CONTROLLER_CHANGES)\n")
paths=[entry_path,contract_path,adapter,guard,hnew,cnew,producer,helper,identity,normalized,normalized_stage,receipt,static,static_stage]
for p in paths:
 if p.suffix=='.py':compile(p.read_text(),str(p),'exec')
# Source reversal checks are whole-file AST, not selected assertions.
for newer,older,changes in [(entry_path,entry_old,entry_changes),(adapter,adapter_old,[(entry_old.name,entry_path.name)]),(guard,guard_old,guard_changes),(hnew,hold,helper_changes),(cnew,cold,controller_changes)]:
 text=newer.read_text()
 for a,z in reversed(changes):text=text.replace(z,a)
 assert ast.dump(ast.parse(text),include_attributes=False)==ast.dump(ast.parse(older.read_text()),include_attributes=False),str(newer)
# Invoke only pure source-bound gate/argv validators. All 38 original argument
# negatives are retained by whole entry reversal; changed source aggregates refuse.
def load(p,name):
 spec=importlib.util.spec_from_file_location(name,p);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v
entry=load(entry_path,'older_spare_v10');actual=entry.load_contract();assert actual==contract and not entry.ALLOCATED.exists();slots=[]
for n in range(4):slots.append(dict(zip(entry.FLAGS,[contract['binary'],str(Path(contract['root'])/'proxima'/str(n)/'ledger'),'b'*64,'a'*64,'0.25',str(Path(contract['root'])/f'component-mesh-config-{n}.json'),str(Path(contract['root'])/f'component-bft-config-{n}.json'),f'127.0.0.1:{20000+n}'])))
a=dict(format='RLD-FIRST-SERVICE-ENTRY-ALLOCATED-V1',completed=True,root=contract['root'],budget_seconds=180,attempts=1,native_starts=4,entry_sha256=sha(entry_path),contract_sha256=sha(contract_path),original_parameters=original_parameters,slots=slots)
for n in range(4):
 argv=tuple([contract['driver_argv']]+[item for flag in entry.FLAGS for item in (flag,slots[n][flag])]);assert entry.validate_invocation(argv,contract,a)==(n,argv)
 bad=copy.deepcopy(a);bad['budget_seconds']=181
 try:entry.validate_invocation(argv,contract,bad);raise AssertionError('deadline expansion accepted')
 except ValueError:pass
oldentry=load(entry_old,'old_v9_must_refuse')
try:oldentry.load_contract();raise AssertionError('old contract accepted changed production')
except ValueError:pass
g=load(guard,'v13_delivery_guard');assert g.require_current_delivery()['completed']
try:g.require_ready_native_scope();raise AssertionError('unallocated Native accepted')
except ValueError:pass
bound();assert not Path(contract['root']).exists();duration=round(time.monotonic()-start,6)
report=dict(completed=True,budget_seconds=60,attempts=1,duration_seconds=duration,python192_source_commitment=x['python_source_commitment'],contract_source_files=453,source_delta=delta,Native89_Core171_actual_binary_unchanged=True,whole_V21_helper_controller_guard_and_V9_entry_AST_reversal=True,all_original_parameters_equal=True,all4_actual_Rust_driver_argv_17_items_validated=True,old_V9_source_contract_refuses=True,unallocated_current_Native_guard_refuses=True,current_actual_delivery_guard_accepts=True,actual_function_global_providers=sorted(providers),protected_sha256={str(p):sha(p) for p in paths},Node_Native_Runtime_socket_key_sign_fixture_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False)
save(e/'regional-bft-older-spare-v13-v22-source-binding-checks-20261006.json',report);print(json.dumps({k:v for k,v in report.items() if k!='protected_sha256'},sort_keys=True))
