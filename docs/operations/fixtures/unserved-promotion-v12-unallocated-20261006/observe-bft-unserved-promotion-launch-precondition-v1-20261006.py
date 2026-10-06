from pathlib import Path
import ast,hashlib,importlib.util,json,runpy,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(b));start=time.monotonic();deadline=float(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();stage=json.loads((e/'regional-bft-unserved-promotion-launch-precondition-v1-20261006-stage.json').read_text());pins=stage['protected_sha256']
def check():
 assert time.monotonic()<deadline,'original dependency60 remaining launch guard deadline'
 assert all(sha(Path(p))==v for p,v in pins.items())
check();import bind_bft_four_cli_unserved_promotion_20261006 as bind
from bft_unserved_delivery_precondition_v1_20261006 import require_current_delivery,RECEIPT,CHECKS,STAGE
assert not RECEIPT.exists() and not CHECKS.exists() and not STAGE.exists();helper=bind.NEW_HELPER.read_text();controller=bind.NEW_CONTROLLER.read_text();assert bind.validate(helper,controller)
for text,original,changes in [(helper,bind.OLD_HELPER,bind.helper_transformations()),(controller,bind.OLD_CONTROLLER,bind.controller_transformations())]:
 normalized=text
 for before,after in reversed(changes):assert after in normalized;normalized=normalized.replace(after,before)
 assert normalized==original.read_text()
 # Fail before importing any preparation/Native/Runtime dependency.
 t=ast.parse(text);guard=next(i for i,n in enumerate(t.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='require_current_delivery')
 native_imports=[i for i,n in enumerate(t.body) if isinstance(n,ast.ImportFrom) and n.module in ('regional_paged_fault_prepare','regional_paged_fault_scope','regional_contact_node','interstellar_mesh')];assert native_imports and all(i>guard for i in native_imports)
# Actual full future helper and controller main dispatches, refusal only. No
# native imports, fixtures, signed packets, allocation or service worker occurs.
refusals=[]
for label,path in [('guard',None),('helper',bind.NEW_HELPER),('controller',bind.NEW_CONTROLLER)]:
 try:
  if path is None:require_current_delivery()
  else:runpy.run_path(str(path),run_name='__main__')
 except ValueError as ex:assert str(ex)=='ordinary signed delivery remains unqualified';refusals.append(label)
 else:raise AssertionError('unqualified ordinary delivery dispatched '+label)
 assert not {'regional_contact_node','regional_paged_fault_prepare','regional_paged_fault_scope','interstellar_mesh','interstellar_tcp'} & set(sys.modules)
 assert not (b/'native-bft-four-cli-service-first-service-diag-v20-private-20261006').exists()
controls=ast.parse((b/'observe-bft-first-arrival-ordinary-entry-binding-v1-20261006.py').read_text());cases={n.targets[0].id:ast.literal_eval(n.value) for n in controls.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('helper_cases','controller_cases')};negatives=[]
for which,rows in [('helper',cases['helper_cases']),('controller',cases['controller_cases'])]:
 for before,after in rows:
  text=helper if which=='helper' else controller;assert before in text;bad=text.replace(before,after,1)
  try:bind.validate(bad if which=='helper' else helper,bad if which=='controller' else controller)
  except ValueError:negatives.append(dict(source=which,changed=before))
  else:raise AssertionError('original gate guard changed')
for which,text in [('helper',helper),('controller',controller)]:
 bad=text.replace(bind.GUARD,'',1)
 try:bind.validate(bad if which=='helper' else helper,bad if which=='controller' else controller)
 except ValueError:negatives.append(dict(source=which,changed='remove actual ordinary delivery precondition'))
 else:raise AssertionError('new delivery guard removed')
try:bind.controller_source('regional-bft-four-cli-unserved-promotion-decision-allocated-20261006.json')
except ValueError as ex:assert str(ex)=='V20 remains unallocated; ordinary delivery unknown'
else:raise AssertionError('Native allocation derivative produced')
assert len(negatives)==24;assert "assert gate['new180_allocated']==1 and gate['new600_allocated']==0" in controller
x=json.loads((e/'regional-bft-unserved-promotion-final-identity-20261006.json').read_text());assert all(sha(r/p)==h for p,h in x['python_source_sha256'].items());assert all(sha(r/p)==h for p,h in x['native_source_sha256'].items());core=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text());assert len(core['files'])==171 and all(sha(r/v['path'])==v['sha256'] for v in core['files']);binary=b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate';assert sha(binary)==x['actual_cli_sha256'];check()
snapshot=b/'unserved-promotion-launch-precondition-source-only-private-20261006';assert not snapshot.exists();snapshot.mkdir(mode=0o700);paths=[b/'bft_unserved_delivery_precondition_v1_20261006.py',b/'bind_bft_four_cli_unserved_promotion_20261006.py',bind.NEW_HELPER,bind.NEW_CONTROLLER,bind.OLD_HELPER,bind.OLD_CONTROLLER,Path(__file__),Path(stage['controller_path'])];rows={}
for index,p in enumerate(paths):target=snapshot/(str(index).zfill(2)+'-'+p.name);target.write_bytes(p.read_bytes());rows[str(target)]={'source':str(p),'sha256':sha(target)}
manifest=snapshot/'source-manifest.json';manifest.write_text(json.dumps(dict(source_only=True,private_state_key_custody_ledger_binary_copies=0,files=rows),indent=2)+'\n');check()
print(json.dumps(dict(completed=True,duration_seconds=round(time.monotonic()-start,6),whole_V20_helper_controller_restores_V19_after_only_declared_bindings_and_guard=True,original17setup13import15mature_all8cold_envelopes_caller_owner_conservation_stop_preserved=True,actual_early_unqualified_delivery_refusals=refusals,full_future_helper_controller_main_refused_before_Native_import=True,original_guard_mutations_and_new_guard_removals_refused=negatives,allocated_variant_generation_refused=True,new_guard_does_not_grant_ledger_maturity_authority=True,current_source192_Native89_Core171_actual_binary_unchanged=True,new_native_root_allocation_and_decision_absent=True,ordinary_signed_delivery='unknown',no_delivery_scope_rerun=True,source_only_snapshot_files=8,source_only_snapshot_manifest_sha256=sha(manifest),future_fixture_helper_controller_main_refusal_dispatches=2,Native_Runtime_Node_socket_key_sign_fixture_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False),sort_keys=True))
