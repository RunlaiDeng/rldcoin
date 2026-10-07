from pathlib import Path
import json,hashlib,ast,copy
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();started=__import__('time').monotonic()
rev=json.loads((b/'keyless-stopped-drain-source-reversal-v1-20261007.json').read_text())
for path,row in rev['files'].items():
 text=(r/path).read_text()
 if path.endswith('/regional_paged_fault_driver.py'):text=text.replace(rev['driver_added'],'').replace(rev['driver_run_after'],rev['driver_run_before'])
 else:text=text.replace(rev['new_test_class']+'\n','').replace(rev['model_adapter_added'],'').replace(rev['sequence_assertions_added'],'')
 assert text==Path(row['backup']).read_text() and hashlib.sha256(text.encode()).hexdigest()==row['old_sha256'] and sha(r/path)==row['new_sha256']
def methods(text):
 node=next(v for v in ast.parse(text).body if isinstance(v,ast.ClassDef) and v.name=='Driver');return {v.name:ast.dump(v,include_attributes=False) for v in node.body if isinstance(v,ast.FunctionDef)}
oldmethods=methods(Path(rev['files']['tools/regional_paged_fault_driver.py']['backup']).read_text());newmethods=methods((r/'tools/regional_paged_fault_driver.py').read_text());unchanged=[k for k in oldmethods if oldmethods[k]==newmethods[k]];assert set(oldmethods)-set(unchanged)=={'run'};assert set(newmethods)-set(oldmethods)=={'keyless_observations_ready','stopped_drain'}
x=copy.deepcopy(json.loads((e/'regional-keyless-directory-v1-identity-20261007.json').read_text()));x['prior_identity_sha256']=sha(e/'regional-keyless-directory-v1-identity-20261007.json')
for path,row in rev['files'].items():x['python_source_sha256'][path]=row['new_sha256']
x['python_source_commitment']=hashlib.sha256(json.dumps(x['python_source_sha256'],sort_keys=True,separators=(',',':')).encode()).hexdigest();x['keyless_drain_profile']='RLD-OWN-CLEAN-KEYLESS-FIXED-HEAD-DRAIN-V1';x['qualification_scope']='34 finite driver models plus explicit source bridge to historical V47. Full original600 still unqualified. All original drain conditions checked after own normal keyless stop, same active scope, then entire original cold/heads/conservation within600. No old failed reopen.';x['source_delta']=list(rev['files']);x['actual_current_profile_native_scope_started']=False;x['new180_allocated']=False;x['new600_allocated']=False
seal=b/'native-paged-full-fault-directory-v14-stopped-private-inventory-20261007.json';x['protected_private_inventory_sha256'][str(seal)]=sha(seal)
with (e/'regional-keyless-stopped-drain-v1-identity-20261007.json').open('x') as f:f.write(json.dumps(x,sort_keys=True,indent=2)+'\n')
g=copy.deepcopy(json.loads((e/'regional-keyless-directory-driver-source-gate-v1-20261007.json').read_text()));g.update(format='RLD-KEYLESS-FIXED-HEAD-DRAIN-SOURCE-GATE-V1',binding_source_sha256=sha(r/'tools/regional_paged_fault_driver.py'),tests_sha256=sha(r/'tools/test_regional_paged_fault_driver.py'),model_checks_sha256=sha(e/'regional-keyless-stopped-drain-model-v2-20261007.json'),old_source_gate_sha256=sha(e/'regional-keyless-directory-driver-source-gate-v1-20261007.json'),unchanged_method_AST=unchanged,tests=34,new_tests=17,old17_test_source_byte_identical=False,old17_test_source_assertions_preserved=True,old28_test_exact_reversal_with_declared_model_adapter=True,original_drain_predicate_and_full_cold_unchanged=True,normal_keyless_stop_required_before_same_predicate=True)
with (e/'regional-keyless-stopped-drain-driver-source-gate-v1-20261007.json').open('x') as f:f.write(json.dumps(g,indent=2)+'\n')
combined=copy.deepcopy(json.loads((b/'keyless-directory-source-reversal-v1-20261007.json').read_text()));combined['fixed_head_drain_reversal_sha256']=sha(b/'keyless-stopped-drain-source-reversal-v1-20261007.json');combined['original_run_cold_sign_calls_error_permission_guards_unchanged']=False;combined['run_changes_only_stop_then_same_drain_before_unchanged_fullcold']=True
for path,row in rev['files'].items():combined['files'][path]['new_sha256']=row['new_sha256']
with (b/'keyless-stopped-drain-combined-source-reversal-v1-20261007.json').open('x') as f:f.write(json.dumps(combined,indent=2)+'\n')
t=(b/'keyless_directory_source_bridge_v1.py').read_text().replace("keyless-directory-source-reversal-v1-20261007.json","keyless-stopped-drain-combined-source-reversal-v1-20261007.json").replace("regional-keyless-directory-model-v1-20261007.json","regional-keyless-stopped-drain-model-v2-20261007.json").replace("gate['tests_run']==28","gate['tests_run']==34")
insert="""
 delta=json.loads((b/'keyless-stopped-drain-source-reversal-v1-20261007.json').read_text())
 for path,row in delta['files'].items():
  text=(r/path).read_text()
  if path.endswith('/regional_paged_fault_driver.py'):text=text.replace(delta['driver_added'],'').replace(delta['driver_run_after'],delta['driver_run_before'])
  else:text=text.replace(delta['new_test_class']+'\\n','').replace(delta['model_adapter_added'],'').replace(delta['sequence_assertions_added'],'')
  assert text==Path(row['backup']).read_text() and hashlib.sha256(text.encode()).hexdigest()==row['old_sha256']
"""
t=t.replace(' latest=current\n',' latest=current\n'+insert);compile(t,'bridge','exec');(b/'keyless_stopped_drain_source_bridge_v1.py').write_text(t)
for old,new in [('observe-paged-fault-native-prepare-directory-v17-20261007.py','observe-paged-fault-native-prepare-stopped-v18-20261007.py'),('check-paged-fault-native-prepare-directory-v17-20261007.py','check-paged-fault-native-prepare-stopped-v18-20261007.py'),('observe-paged-fault-full-directory-v14-20261007.py','observe-paged-fault-full-stopped-v15-20261007.py'),('check-paged-fault-full-directory-v14-20261007.py','check-paged-fault-full-stopped-v15-20261007.py')]:
 text=(b/old).read_text().replace('prepare-directory-v17','prepare-stopped-v18').replace('preparation-directory-v17','preparation-stopped-v18').replace('full-fault-directory-v14','full-fault-stopped-v15').replace('full-directory-v14','full-stopped-v15').replace('controller-directory-v14','controller-stopped-v15').replace('keyless_directory_source_bridge_v1','keyless_stopped_drain_source_bridge_v1').replace('regional-keyless-directory-v1-identity','regional-keyless-stopped-drain-v1-identity').replace('regional-keyless-directory-driver-source-gate-v1','regional-keyless-stopped-drain-driver-source-gate-v1').replace("gate['tests']==28","gate['tests']==34").replace("gate['old17_test_source_byte_identical']","gate['old17_test_source_assertions_preserved']")
 if new.startswith('check-'):
  index=text.index('def pins(')
  protected='protected' if 'native-prepare' in new else 'protected'
  text=text[:index]+"for p in (e/'regional-keyless-stopped-drain-v1-identity-20261007.json',e/'regional-keyless-stopped-drain-driver-source-gate-v1-20261007.json',e/'regional-keyless-stopped-drain-model-v2-20261007.json',e/'regional-keyless-stopped-drain-counter-v1-20261007.json',e/'regional-keyless-stopped-drain-model-v1-20261007.json',e/'regional-keyless-stopped-drain-model-entry-error-20261007.json',e/'regional-paged-full-fault-directory-v14-20261007-checks.json',e/'regional-keyless-drain-directory-v14-readonly-20261007.json',b/'keyless-stopped-drain-source-reversal-v1-20261007.json',b/'keyless-stopped-drain-combined-source-reversal-v1-20261007.json',b/'keyless_stopped_drain_source_bridge_v1.py',b/'regional_paged_fault_driver-before-stopped-drain-v1-20261007.py',b/'test_regional_paged_fault_driver-before-stopped-drain-v1-20261007.py'):\n protected[str(p)]=sha(p)\n"+text[index:]
  if 'native-prepare' in new:
   text=text.replace("changed_source='", "changed_source='After directory-v14 FAIL600/603.233/7260, actual prefix read-lock counter .089326 and34 models PASS.241971; same-active normal keyless stop then identical original drain predicate before fullcold, no predicate/600/24/owner/key/Native change. ",1)
  else:
   text=text.replace("hypothesis='", "hypothesis='Exact actual keyless calls never reached other regions, repeated Earth prefix and busy later signer. Candidate requires original all12 current keyless observations then own normal exit0 and original full Native pending/head/group predicate, before unchanged all12 cold/conservation within600. First pending/group/nonconvergence/unclean/source/deadline fails and seals, no reopening. ",1)
 compile(text,new,'exec');assert not (b/new).exists();(b/new).write_text(text)
print(json.dumps(dict(new_source192=x['python_source_commitment'],unchanged_driver_methods=unchanged,changed_original_driver_methods=['run'],added_driver_methods=['keyless_observations_ready','stopped_drain'],helpers_syntax_checked=4,duration_seconds=round(__import__('time').monotonic()-started,6))))
