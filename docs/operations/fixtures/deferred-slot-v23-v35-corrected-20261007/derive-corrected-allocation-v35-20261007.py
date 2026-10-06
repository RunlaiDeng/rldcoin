from pathlib import Path
import ast,copy,datetime,hashlib,importlib.util,json,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
prior=e/'regional-bft-deferred-slot-v23-v34-source-binding-20261006-checks.json';q=json.loads(prior.read_text());assert q['completed']
for p,h in q['source_sha256'].items():assert sha(Path(p))==h
oldcontract=b/'first_service_diagnostic_entry_contract_v22_20261006.json';contract=b/'first_service_diagnostic_entry_contract_v23_20261006.json';c=json.loads(oldcontract.read_text());c['root']=c['root'].replace('diag-v34-','diag-v35-');assert not Path(c['root']).exists();assert not contract.exists();contract.write_text(json.dumps(c,sort_keys=True,indent=2)+'\n')
pairs=[('first_service_diagnostic_entry_contract_v22_20261006','first_service_diagnostic_entry_contract_v23_20261006'),('first_service_diagnostic_entry_v22_20261006','first_service_diagnostic_entry_v23_20261006'),('bft_four_cli_first_service_diagnostic_v19_20261006','bft_four_cli_first_service_diagnostic_v20_20261006'),('bft_deferred_slot_delivery_precondition_v15_20261006','bft_deferred_slot_delivery_precondition_v16_20261006'),('service-first-service-diag-v34','service-first-service-diag-v35'),('regional-bft-four-cli-deferred-slot-v34','regional-bft-four-cli-deferred-slot-v35'),('regional-bft-deferred-slot-entry-start-allocated-v34','regional-bft-deferred-slot-entry-start-allocated-v35'),('bind_bft_four_cli_deferred_slot_v34','bind_bft_four_cli_deferred_slot_v35'),('launch-owned-original-v34','launch-owned-original-v35'),('regional-bft-four-cli-v34-owned-controller','regional-bft-four-cli-v35-owned-controller'),(sha(oldcontract),sha(contract))]
def replace(t):
 for a,z in pairs:t=t.replace(a,z)
 return t
names=['first_service_diagnostic_entry_v22_20261006.py','bft_four_cli_first_service_diagnostic_v19_20261006.py','bft_deferred_slot_delivery_precondition_v15_20261006.py','observe-bft-four-cli-service-first-service-diag-v34-20261006.py','check-bft-four-cli-service-first-service-diag-v34-allocated-preview-20261006.py','bind_bft_four_cli_deferred_slot_v34_20261006.py','launch-owned-original-v34-20261007.py']
paths=[contract]
for name in names:
 old=b/name;new=b/replace(name);assert not new.exists();t=replace(old.read_text());compile(t,str(new),'exec');new.write_text(t);new.chmod(old.stat().st_mode & 0o777)
 reversed=t
 for a,z in pairs[::-1]:reversed=reversed.replace(z,a)
 assert ast.dump(ast.parse(reversed),include_attributes=False)==ast.dump(ast.parse(old.read_text()),include_attributes=False)
 paths.append(new)
oldallocation=e/'regional-bft-four-cli-deferred-slot-v34-decision-allocated-20261006.json';allocation=e/'regional-bft-four-cli-deferred-slot-v35-decision-allocated-20261006.json';z=json.loads(oldallocation.read_text());helper=b/'observe-bft-four-cli-service-first-service-diag-v35-20261006.py';controller=b/'check-bft-four-cli-service-first-service-diag-v35-allocated-preview-20261006.py'
z.update(root=c['root'],helper_sha256=sha(helper),controller_sha256=sha(controller),contract_sha256=sha(contract),recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),old_V34_refusal_before_Native_started=True,original_V34_budget_not_started_or_consumed=True)
# Carry every previous binding as an unchanged protected source, and add every new reviewed derivative.
z['protected_sha256'].update({str(p):sha(p) for p in paths});z['protected_sha256'][str(Path(__file__))]=sha(Path(__file__));z['protected_sha256'][str(oldallocation)]=sha(oldallocation)
z['protected_sha256'][str(e/'regional-bft-deferred-slot-v34-allocation-refusal-20261007-checks.json')]=sha(e/'regional-bft-deferred-slot-v34-allocation-refusal-20261007-checks.json')
assert not allocation.exists();allocation.write_text(json.dumps(z,indent=2)+'\n')
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
producer=load(b/'bind_bft_four_cli_deferred_slot_v35_20261006.py','producer35');assert producer.helper_source()==helper.read_text();assert producer.controller_source(decision=allocation.name)==controller.read_text()
guard=load(b/'bft_deferred_slot_delivery_precondition_v16_20261006.py','guard35');assert guard.require_ready_native_scope()[1]==z
entry=load(b/'first_service_diagnostic_entry_v23_20261006.py','entry35');assert entry.load_contract()==c
for key,p in [('helper_sha256',helper),('controller_sha256',controller),('contract_sha256',contract)]:assert z[key]==sha(p)
assert not Path(c['root']).exists();assert not (e/'regional-bft-deferred-slot-entry-start-allocated-v35-20261006.json').exists()
report=e/'regional-bft-deferred-slot-v23-v35-corrected-binding-20261007-checks.json';assert not report.exists();report.write_text(json.dumps(dict(completed=True,original_source60_cumulative_seconds=round(q['duration_seconds']+time.monotonic()-start,6),prior_source_binding_sha256=sha(prior),allocation_refusal_retained=True,actual_allocated_guard_accepts=True,controller_helper_contract_receipt_binding_exact=True,whole_driver_AST_exact_after_literal_reversal=True,Native_Runtime_Node_socket_key_sign_fixture_calls=0,source192_Native89_Core171_binary_unchanged_from_qualified_V23=True,original180_native_started=False,original_parameters_unchanged=True,source_sha256={str(p):sha(p) for p in paths+[allocation,Path(__file__)]}),indent=2)+'\n')
review=r/'docs/operations/fixtures/deferred-slot-v23-v35-corrected-20261007';assert not review.exists();review.mkdir()
for p in paths+[allocation,Path(__file__),report]:(review/p.name).write_bytes(p.read_bytes())
(review/'README.md').write_text('Corrects stale controller hash in allocation, preserving failed V34 rejection before any Native start. Every derivative matches reviewed V34 after literal reversal. Actual allocated guard validates helper/controller/contract/receipt and original limits before launch. Source/profile and all original acceptance unchanged. One original180 attempt remains not started; no failed Native fixture reused. Review copies only, no keys/state/binary.\n')
print(report.read_text())
