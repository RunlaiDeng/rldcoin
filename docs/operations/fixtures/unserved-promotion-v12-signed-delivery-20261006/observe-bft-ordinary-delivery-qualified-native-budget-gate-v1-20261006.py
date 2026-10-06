from pathlib import Path
import ast,copy,hashlib,importlib.util,json,runpy,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(b));start=time.monotonic();deadline=float(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();stage=json.loads((e/'regional-bft-ordinary-delivery-qualified-native-budget-gate-v1-20261006-stage.json').read_text());pins=stage['protected_sha256']
def check():
 assert time.monotonic()<deadline,'original dependency60 remaining ground qualification deadline'
 assert all(sha(Path(p))==v for p,v in pins.items())
check();import bft_unserved_delivery_precondition_v2_20261006 as guard
import bind_bft_four_cli_unserved_promotion_v21_20261006 as bind
receipt=guard.require_current_delivery();assert receipt['completed'] and receipt['python_source_commitment']=='1914160b341d21f5df8ec03f74380cb0532cdbc4b302baa02875dc434f277d40';assert not guard.ALLOCATED.exists()
helper=bind.NEW_HELPER.read_text();unarmed=bind.NEW_CONTROLLER.read_text();allocated_name='regional-bft-four-cli-unserved-promotion-v21-decision-allocated-20261006.json';preview=guard.NATIVE_CONTROLLER.read_text();assert bind.validate(helper,unarmed) and bind.validate(helper,preview,allocated_name)
for source,decision in [(unarmed,bind.DECISION),(preview,allocated_name)]:
 normalized=source
 for before,after in reversed(bind.controller_transformations(decision)):assert after in normalized;normalized=normalized.replace(after,before)
 assert normalized==bind.OLD_CONTROLLER.read_text()
normal=helper
for before,after in reversed(bind.helper_transformations()):assert after in normal;normal=normal.replace(after,before)
assert normal==bind.OLD_HELPER.read_text()
actual_refusals=[]
for label,path in [('ready_guard',None),('helper',bind.NEW_HELPER),('unarmed_controller',bind.NEW_CONTROLLER),('allocated_preview_controller',guard.NATIVE_CONTROLLER)]:
 try:
  if path is None:guard.require_ready_native_scope()
  else:runpy.run_path(str(path),run_name='__main__')
 except ValueError as ex:assert str(ex)=='Native180 scope remains unallocated';actual_refusals.append(label)
 else:raise AssertionError('ground receipt bypassed Native allocation '+label)
 assert not {'regional_contact_node','regional_paged_fault_prepare','regional_paged_fault_scope','interstellar_mesh','interstellar_tcp'} & set(sys.modules)
# A positive pure allocation-schema model validates the prepared review result;
# no file, allocation, helper main or Native process is produced by that model.
draft_path=e/bind.DECISION;draft=json.loads(draft_path.read_text());assert draft['owner_authorized'] is False and draft['new180_allocated']==0;model=copy.deepcopy(draft);model.update(owner_authorized=True,completed=True,new180_allocated=1);original_path=guard.ALLOCATED;original_read=guard.read_json
class OnlyModelPath:
 def is_file(self):return True
fake=OnlyModelPath();guard.ALLOCATED=fake
current=[model]
def modeled_read(path):
 if path is fake:return copy.deepcopy(current[0]),'0'*64
 return original_read(path)
guard.read_json=modeled_read
negative=[]
try:
 assert guard.require_native_allocation()==model
 for field,value in [('owner_authorized',False),('new180_allocated',True),('new600_allocated',1),('budget_seconds',181),('attempts',2),('owner_first_signs',2),('old_failed_reopens',1),('custody_copies',1),('root',str(b/'native-bft-four-cli-service-first-service-diag-v19-private-20261006')),('helper_sha256','0'*64),('controller_sha256','0'*64),('contract_sha256','0'*64),('delivery_receipt_sha256','0'*64),('python_source_commitment','0'*64),('native_implementation','0'*64),('core_source_commitment','0'*64),('actual_binary_sha256','0'*64)]:
  changed=copy.deepcopy(model);changed[field]=value;current[0]=changed
  try:guard.require_native_allocation()
  except ValueError:negative.append(field)
  else:raise AssertionError('bad allocation accepted '+field)
 changed=copy.deepcopy(model);changed['original_parameters']['maturity']=1;current[0]=changed
 try:guard.require_native_allocation()
 except ValueError:negative.append('original maturity')
 else:raise AssertionError('changed maturity accepted')
 changed=copy.deepcopy(model);changed['original_parameters']['owner_first_signs']=True;current[0]=changed
 try:guard.require_native_allocation()
 except ValueError:negative.append('original parameters numeric bool alias')
 else:raise AssertionError('boolean parameter alias accepted')
finally:guard.ALLOCATED=original_path;guard.read_json=original_read
assert len(negative)==19 and not guard.ALLOCATED.exists()
# All previous substantive helper/controller guards survive both variants.
controls=ast.parse((b/'observe-bft-first-arrival-ordinary-entry-binding-v1-20261006.py').read_text());cases={n.targets[0].id:ast.literal_eval(n.value) for n in controls.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('helper_cases','controller_cases')};old_negative=[]
for decision,source in [(bind.DECISION,unarmed),(allocated_name,preview)]:
 for which,rows in [('helper',cases['helper_cases']),('controller',cases['controller_cases'])]:
  for before,after in rows:
   text=helper if which=='helper' else source;assert before in text;bad=text.replace(before,after,1)
   try:bind.validate(bad if which=='helper' else helper,bad if which=='controller' else source,decision)
   except ValueError:old_negative.append(which)
   else:raise AssertionError('original maturity/cold/owner/budget guard changed')
assert len(old_negative)==44
# V9 exact source-only root/contract binding; validator code is unchanged.
p=b/'first_service_diagnostic_entry_v9_20261006.py';spec=importlib.util.spec_from_file_location('unallocated_v9_entry',p);entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry);contract=entry.load_contract();old=b/'first_service_diagnostic_entry_contract_v8_20261006.json';assert contract['source_sha256']==json.loads(old.read_text())['source_sha256'] and contract['original_parameters']==json.loads(old.read_text())['original_parameters'];text=p.read_text()
for before,after in [('first_service_diagnostic_entry_contract_v8_20261006.json','first_service_diagnostic_entry_contract_v9_20261006.json'),(sha(old),entry.CONTRACT_SHA256),('regional-bft-unserved-promotion-entry-start-allocated-v20-20261006.json','regional-bft-unserved-promotion-entry-start-allocated-v21-20261006.json'),('native-bft-four-cli-service-first-service-diag-v20-private-20261006','native-bft-four-cli-service-first-service-diag-v21-private-20261006')]:assert after in text;text=text.replace(after,before)
assert text==(b/'first_service_diagnostic_entry_v8_20261006.py').read_text();assert not Path(contract['root']).exists() and not entry.ALLOCATED.exists();assert all(sha(Path(p))==h for p,h in draft['protected_sha256'].items());check()
# No Node/cold signer is reopened: verify stopped files by immutable inventory.
sys.path.insert(0,str(r/'tools'));from regional_paged_fault_scope import inventory
for name,count in [('unserved-promotion-ordinary-delivery-v2-v12-stopped-private-inventory-20261006.json',15),('unserved-promotion-ordinary-delivery-v4-v12-stopped-private-inventory-20261006.json',16)]:
 rows=json.loads((b/name).read_text());assert sum(len(v) for v in rows.values())==count and all(inventory(Path(p))==v for p,v in rows.items())
check();print(json.dumps(dict(completed=True,duration_seconds=round(time.monotonic()-start,6),actual_V4_ground_receipt_and_current_source_positive_precondition_verified=True,actual_separate_Native_allocation_refusals=actual_refusals,positive_allocation_schema_model_only_no_file_or_worker=True,allocation_negatives=negative,whole_V21_helper_controller_variants_restore_V20=True,original_guard_mutations_refused44=True,original17setup13import15mature_all8cold_envelope_caller_owner_conservation_stop_budget_unchanged=True,V9_entry_same453sources_wholeV8_exact_after4_literal_reversal=True,failed15_and_passed16_bytes_unchanged=True,real_unarmed_owner_authorized_false=True,real_allocated_descriptor_root_and_entry_allocation_absent=True,ground_delivery_qualified=True,native_maturity_cold_conservation_still_unqualified=True,full_future_refusal_dispatches=3,Native_Runtime_Node_socket_key_sign_fixture_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False),sort_keys=True))
