from pathlib import Path
import ast,hashlib,importlib.util,json,os,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();deadline=float(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();stage=json.loads((e/'regional-bft-unserved-promotion-entry-v8-source-binding-20261006-stage.json').read_text());pins=stage['protected_sha256']
def check():
 assert time.monotonic()<deadline,'original dependency60 remaining binding deadline'
 assert all(sha(Path(p))==v for p,v in pins.items())
check();x=json.loads((e/'regional-bft-unserved-promotion-final-identity-20261006.json').read_text());oldcontract=json.loads((b/'first_service_diagnostic_entry_contract_v7_20261006.json').read_text());path=b/'first_service_diagnostic_entry_v8_20261006.py';spec=importlib.util.spec_from_file_location('current_v8_unallocated_entry',path);entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry);contract=entry.load_contract();assert len(contract['source_sha256'])==453 and contract['python_source_commitment']==x['python_source_commitment'];delta=[p for p,h in contract['source_sha256'].items() if oldcontract['source_sha256'][p]!=h];assert delta==['tools/interstellar_mesh.py','tools/test_interstellar_mesh.py'];assert contract['original_parameters']==oldcontract['original_parameters'];root=Path(contract['root']);assert not root.exists() and not entry.ALLOCATED.exists()
text=path.read_text();old=b/'first_service_diagnostic_entry_v7_20261006.py';pairs=[('first_service_diagnostic_entry_contract_v7_20261006.json','first_service_diagnostic_entry_contract_v8_20261006.json'),(sha(b/'first_service_diagnostic_entry_contract_v7_20261006.json'),entry.CONTRACT_SHA256),('regional-bft-ordinary-newest-entry-start-allocated-v19-20261006.json','regional-bft-unserved-promotion-entry-start-allocated-v20-20261006.json'),('native-bft-four-cli-service-first-service-diag-v19-private-20261006','native-bft-four-cli-service-first-service-diag-v20-private-20261006')]
for before,after in reversed(pairs):assert after in text;text=text.replace(after,before)
assert text==old.read_text();adapter=b/'bft_four_cli_first_service_diagnostic_v5_20261006.py';assert adapter.read_text().replace('first_service_diagnostic_entry_v8_20261006.py','first_service_diagnostic_entry_v7_20261006.py')==(b/'bft_four_cli_first_service_diagnostic_v4_20261006.py').read_text()
# Four synthetic argv controls exercise the new root binding, not process launch.
slots=[]
for i in range(4):slots.append(dict(zip(entry.FLAGS,[contract['binary'],str(root/'proxima'/str(i)/'ledger'),'b'*64,'a'*64,'0.25',str(root/('component-mesh-config-'+str(i)+'.json')),str(root/('component-bft-config-'+str(i)+'.json')),'127.0.0.1:'+str(20000+i)])))
decision=dict(format='RLD-FIRST-SERVICE-ENTRY-ALLOCATED-V1',completed=True,root=str(root),budget_seconds=180,attempts=1,native_starts=4,entry_sha256=sha(path),contract_sha256=entry.CONTRACT_SHA256,original_parameters=contract['original_parameters'],slots=slots)
for i,slot in enumerate(slots):
 argv=tuple([contract['driver_argv']]+[item for flag in entry.FLAGS for item in (flag,slot[flag])]);assert entry.validate_invocation(argv,contract,decision)==(i,argv)
assert contract['driver_argv']==str(r/'tools/regional-ledger')+'/../../tools/regional_contact_node.py';assert Path(contract['driver_argv']).resolve(strict=True)==r/'tools/regional_contact_node.py'
# The previous38 actual negatives and seven pure aggregate negatives apply
# through exact whole-source literal reversal. They are not rerun or generalized.
oldchecks=json.loads((e/'regional-bft-ordinary-newest-final-binding-v1-20261006-checks.json').read_text());assert oldchecks['completed'];oldresult=oldchecks['result'];assert oldresult['pure_python_commitment_guard_and_prior7_negatives_reused'];assert len(oldresult['actual_Rust_argv_result']['entry_guard_negatives'])==38
oldsource=json.loads((e/'regional-bft-unserved-promotion-final-binding-v2-20261006-checks.json').read_text());assert oldsource['completed'] and oldsource['result']['old_V7_entry_refuses_changed_source'] and oldsource['result']['python_source_commitment']==x['python_source_commitment'];entry.check_python_commitment(contract)
prior_env=os.environ.get('RLD_GROUND_CONTACT_TRACE');os.environ['RLD_GROUND_CONTACT_TRACE']='1'
try:
 try:entry.main()
 except ValueError as ex:assert str(ex)=='new diagnostic Native scope not allocated'
 else:raise AssertionError('unallocated entry dispatched')
finally:
 if prior_env is None:os.environ.pop('RLD_GROUND_CONTACT_TRACE',None)
 else:os.environ['RLD_GROUND_CONTACT_TRACE']=prior_env
assert not {'interstellar_mesh','interstellar_tcp','regional_contact_node'} & set(sys.modules)
# Ordinary delivery is still unknown: no existing receipt can authorize this entry.
delivery=json.loads((e/'regional-bft-unserved-promotion-ordinary-delivery-v1-20261006-checks.json').read_text());assert not delivery['completed'] and delivery['stopped_files']==0
snapshot=b/'unserved-promotion-entry-v8-source-only-private-20261006';assert not snapshot.exists();snapshot.mkdir(mode=0o700);paths=[path,entry.CONTRACT_PATH,adapter,Path(__file__),Path(stage['controller_path']),old,b/'first_service_diagnostic_entry_contract_v7_20261006.json',b/'bft_four_cli_first_service_diagnostic_v4_20261006.py'];rows={}
for index,p in enumerate(paths):target=snapshot/(str(index).zfill(2)+'-'+p.name);target.write_bytes(p.read_bytes());rows[str(target)]={'source':str(p),'sha256':sha(target)}
manifest=snapshot/'source-manifest.json';manifest.write_text(json.dumps(dict(source_only=True,private_state_key_custody_ledger_binary_copies=0,files=rows),indent=2)+'\n');check();assert not root.exists() and not entry.ALLOCATED.exists()
print(json.dumps(dict(completed=True,duration_seconds=round(time.monotonic()-start,6),current_V8_source_contract_bindings=453,current_python_source_commitment=x['python_source_commitment'],source_delta=delta,whole_V7_entry_exact_after_only_four_literal_reversal=True,whole_adapter_exact_after_only_one_literal_reversal=True,all_original_parameters_equal=True,new_root_four_raw_Rust_argv_controls=4,previous38_entry_and7_aggregate_negatives_reused_through_exact_source=True,old_V7_source_refusal_reused_unchanged_source=True,unallocated_V8_main_refuses_before_Mesh_import=True,production_python_Native_Core_actual_binary_unchanged=True,new_Native_controller_integration_not_implemented=True,ordinary_signed_delivery='unknown',new_root_and_allocation_absent=True,source_only_snapshot_files=8,source_only_snapshot_manifest_sha256=sha(manifest),Native_Runtime_Node_socket_key_sign_driver_main_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False),sort_keys=True))
