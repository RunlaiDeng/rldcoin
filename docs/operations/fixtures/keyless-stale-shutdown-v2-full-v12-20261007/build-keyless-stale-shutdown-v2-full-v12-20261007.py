from pathlib import Path
import ast,copy,hashlib,json
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
oldp=e/'regional-einval-origin-v1-identity-20261007.json';base=json.loads(oldp.read_text());revp=b/'keyless-stale-shutdown-source-reversal-v2-20261007.json';rev=json.loads(revp.read_text())
model=json.loads((e/'regional-keyless-stale-shutdown-model-v2-20261007.json').read_text());assert model['completed'] and model['tests_run']==25 and model['related60_after']<=60
x=copy.deepcopy(base)
for path,row in rev['files'].items():
 assert base['python_source_sha256'][path]==row['old_sha256']==sha(Path(row['backup']));assert sha(r/path)==row['new_sha256']
 x['python_source_sha256'][path]=row['new_sha256']
assert len(x['python_source_sha256'])==192
x['python_source_commitment']=hashlib.sha256(json.dumps(x['python_source_sha256'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
x.update(format='RLD-KEYLESS-STALE-DRIVER-IDENTITY-V1',prior_identity_sha256=sha(oldp),source_delta=list(rev['files']),source_only_snapshot_manifest_sha256=None,driver_startup_profile='RLD-OWN-CLEAN-PREDECESSOR-EXACT-BYTES-UNKNOWN-V1',qualification_scope='Ground fixture candidate; previous component retained only through explicit source bridge. Actual new full600 remains unqualified until complete original discriminators.',new180_allocated=False,new600_allocated=False,actual_current_profile_native_scope_started=False,full_fault_qualified=False,whole_goal_completed=False)
ip=e/'regional-keyless-stale-shutdown-v2-identity-20261007.json'
with ip.open('x') as f:json.dump(x,f,sort_keys=True,indent=2);f.write('\n')
# Compose, preserving historical bridge and every unchanged source hash.
text=(b/'einval_origin_source_bridge_v1.py').read_text()
needle=" b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()\n"
addition=""" latest=current
 current=json.loads((e/'regional-einval-origin-v1-identity-20261007.json').read_text())
 repair=json.loads((b/'keyless-stale-shutdown-source-reversal-v2-20261007.json').read_text())
 assert set(p for p in current['python_source_sha256'] if current['python_source_sha256'][p]!=latest['python_source_sha256'][p])==set(repair['files'])
 for p,row in repair['files'].items():
  assert sha(Path(row['backup']))==row['old_sha256']==current['python_source_sha256'][p]
  assert sha(r/p)==row['new_sha256']==latest['python_source_sha256'][p]
 assert latest['native_source_sha256']==current['native_source_sha256'] and latest['core_source_commitment']==current['core_source_commitment'] and latest['actual_cli_sha256']==current['actual_cli_sha256']
 gate=json.loads((e/'regional-keyless-stale-shutdown-model-v2-20261007.json').read_text())
 assert gate['completed'] and gate['tests_run']==25 and gate['driver_sha256']==sha(r/'tools/regional_paged_fault_driver.py') and gate['tests_sha256']==sha(r/'tools/test_regional_paged_fault_driver.py')
"""
assert text.count(needle)==1;text=text.replace(needle,needle+addition,1)
text=text.replace("all(sha(r/p)==h for p,h in current['python_source_sha256'].items())","all(sha(r/p)==h for p,h in latest['python_source_sha256'].items())")
bridge=b/'keyless_stale_shutdown_source_bridge_v2.py'
with bridge.open('x') as f:f.write(text)
# Actual call/query/proof/drain/fullcold/ownership/cleanup methods unchanged.
oldtree=ast.parse((b/'regional_paged_fault_driver-before-stale-v1-20261007.py').read_text());newtree=ast.parse((r/'tools/regional_paged_fault_driver.py').read_text())
methods=lambda tree:{n.name:ast.dump(n,include_attributes=False) for c in tree.body if isinstance(c,ast.ClassDef) and c.name=='Driver' for n in c.body if isinstance(n,ast.FunctionDef)}
a,z=methods(oldtree),methods(newtree);unchanged=[name for name in a if name not in ('__init__','stop_all','observations')];assert all(a[name]==z[name] for name in unchanged)
oldtests=(b/'test_regional_paged_fault_driver-before-stale-v1-20261007.py').read_text();newtests=(r/'tools/test_regional_paged_fault_driver.py').read_text();candidate=(b/'keyless-stale-observation-model-v1-20261007.py').read_text();cls=candidate[candidate.index('class StoppedObservationTests'):]
v2tests=(b/'keyless-stale-shutdown-model-v2-20261007.py').read_text();extra=v2tests[v2tests.index('    def test_exact_shutdown_marker'):]
assert newtests.replace('from types import SimpleNamespace\n','',1).replace(cls+'\n','',1).replace(extra+'\n','',1)==oldtests
original=json.loads((e/'regional-paged-fault-async-receipt-v4-20261005-checks.json').read_text());assert original['completed'] and original['binding_source_sha256']==rev['files']['tools/regional_paged_fault_driver.py']['old_sha256']
gate=dict(format='RLD-KEYLESS-STALE-DRIVER-SOURCE-GATE-V1',completed=True,helper_terminal=True,helper_exit_code=0,binding_source_sha256=sha(r/'tools/regional_paged_fault_driver.py'),tests_sha256=sha(r/'tools/test_regional_paged_fault_driver.py'),model_checks_sha256=sha(e/'regional-keyless-stale-shutdown-model-v2-20261007.json'),old_source_gate_sha256=sha(e/'regional-paged-fault-async-receipt-v4-20261005-checks.json'),unchanged_method_AST=unchanged,old17_test_source_byte_identical=True,tests=25,old_tests=17,new_tests=8,new_complete_native_query_without_global_telemetry_barrier=True,proof_domain_value_receipt_checks_unchanged=True,categorical_native_lock_vs_no_evidence_diagnostics_retained=True,original_600_60_24_maturity2_quorum3_cleanup5=True,full_fault_qualified=False)
with (e/'regional-keyless-stale-shutdown-driver-source-gate-v2-20261007.json').open('x') as f:json.dump(gate,f,indent=2);f.write('\n')
# New preparation is justified by same unchanged production/native + driver restart repair.
for old,new in [('observe-paged-fault-native-prepare-einval-v13-20261007.py','observe-paged-fault-native-prepare-shutdown-v15-20261007.py'),('check-paged-fault-native-prepare-einval-v13-v2-20261007.py','check-paged-fault-native-prepare-shutdown-v15-20261007.py'),('observe-paged-fault-full-einval-v10-20261007.py','observe-paged-fault-full-shutdown-v12-20261007.py'),('check-paged-fault-full-einval-v10-v2-20261007.py','check-paged-fault-full-shutdown-v12-20261007.py')]:
 text=(b/old).read_text().replace('einval-v13','shutdown-v15').replace('einval-v10','shutdown-v12').replace('regional-einval-origin-v1-identity-20261007.json','regional-keyless-stale-shutdown-v2-identity-20261007.json').replace('from einval_origin_source_bridge_v1 import verify','from keyless_stale_shutdown_source_bridge_v2 import verify')
 text=text.replace('check-paged-fault-native-prepare-shutdown-v15-v2-20261007.py','check-paged-fault-native-prepare-shutdown-v15-20261007.py').replace('check-paged-fault-full-shutdown-v12-v2-20261007.py','check-paged-fault-full-shutdown-v12-20261007.py')
 if new.startswith('observe-paged-fault-full'):
  begin=text.index(' for p,expected in ');end=text.index(" rows=subprocess.check_output",begin)
  replacement=""" gate=document(e/'regional-keyless-stale-shutdown-driver-source-gate-v2-20261007.json')
 require(gate['completed'] and gate['binding_source_sha256']==sha(r/'tools/regional_paged_fault_driver.py') and gate['tests_sha256']==sha(r/'tools/test_regional_paged_fault_driver.py') and gate['tests']==25 and gate['old17_test_source_byte_identical'],'new exact driver finite gate required')
 c=document(e/'regional-paged-fault-terminal-v1-20261005-checks.json')
 require(c['completed'] and c['helper_terminal'] and c['helper_exit_code']==0 and c['binding_source_sha256']==sha(r/'tools/regional_paged_fault_terminal.py'),'unchanged exact terminal finite gate required')
 require(gate['new_complete_native_query_without_global_telemetry_barrier'] and gate['proof_domain_value_receipt_checks_unchanged'] and gate['categorical_native_lock_vs_no_evidence_diagnostics_retained'],'unchanged strict receipt/cold semantics required')
"""
  text=text[:begin]+replacement+text[end:]
 if new.startswith('check-'):
  needle='def pins('
  idx=text.index(needle)
  pinline="for p in (b/'keyless_stale_shutdown_source_bridge_v2.py',b/'keyless-stale-shutdown-source-reversal-v2-20261007.json',b/'regional_paged_fault_driver-before-stale-v1-20261007.py',b/'test_regional_paged_fault_driver-before-stale-v1-20261007.py',e/'regional-keyless-stale-shutdown-v2-identity-20261007.json',e/'regional-keyless-stale-shutdown-driver-source-gate-v2-20261007.json',e/'regional-keyless-stale-shutdown-model-v2-20261007.json',e/'regional-keyless-stale-shutdown-counter-v2-20261007.json',e/'regional-paged-full-fault-einval-v10-20261007-checks.json',e/'regional-paged-full-fault-einval-v10-20261007-stage.json',e/'regional-paged-full-fault-einval-v10-keyless-stale-readonly-20261007.json'):protected[str(p)]=sha(p)\n"
  text=text[:idx]+pinline+text[idx:]
  # The fresh preparer also pins the immediately preceding failed6796 seal.
  if 'seals=dict(' in text:
   idx=text.index('def pins(');text=text[:idx]+"seals[str(b/'native-paged-full-fault-einval-v10-stopped-private-inventory-20261007.json')]=sha(b/'native-paged-full-fault-einval-v10-stopped-private-inventory-20261007.json')\n"+text[idx:]
  text=text.replace('Original exact full-fault driver744, terminal49f','New exact full-fault clean-predecessor driver, unchanged terminal49f')
  text=text.replace('same600/60round/24height/maturity2/3of4/3originalownerfirstsigns','same600/60round/24height/maturity2/3of4/3originalownerfirstsigns; previous einval-v10 FAIL384.478/6796sealed reached actual single recipient net9 maturity but rejected own stale predecessor PID at keyless startup, then keyless -15 cleanup failed. New exact-clean-own-predecessor byte-only unknown repair and eight strict model guards qualify necessary one new scope; no foreign PID waiver or deadline extension.')
  text=text.replace('Necessary fresh12 input for exactEINVAL origin observation after full apply-v9 FAIL243.853,5526sealed.','Necessary genuinely fresh12 input after einval-v10 FAIL384.478/6796sealed: exact own clean-predecessor status remains unknown at new process startup until valid current report. Driver only repair; original source/proof/error/keyless/cold/stop and all budgets unchanged.')
 for fn in ast.walk(ast.parse(text)):
  pass
 with (b/new).open('x') as f:f.write(text)
print(json.dumps(dict(identity_sha256=sha(ip),source192=x['python_source_commitment'],driver=sha(r/'tools/regional_paged_fault_driver.py'),methods_unchanged=len(unchanged),new_helpers=4)))
