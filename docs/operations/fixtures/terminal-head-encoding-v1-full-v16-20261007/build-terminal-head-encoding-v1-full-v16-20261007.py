from pathlib import Path
import json,copy,hashlib,ast,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();start=time.monotonic();rev=json.loads((b/'terminal-head-encoding-source-reversal-v1-20261007.json').read_text());x=copy.deepcopy(json.loads((e/'regional-keyless-stopped-drain-v1-identity-20261007.json').read_text()));prior=copy.deepcopy(x)
for path,row in rev['files'].items():
 text=(r/path).read_text();text=text.replace(rev['after'],rev['before']) if path.endswith('/regional_paged_fault_terminal.py') else text.replace(rev['new_test_class'],'')
 assert text==Path(row['backup']).read_text() and row['old_sha256']==prior['python_source_sha256'][path] and sha(r/path)==row['new_sha256'];x['python_source_sha256'][path]=row['new_sha256']
oldtree=ast.parse(Path(rev['files']['tools/regional_paged_fault_terminal.py']['backup']).read_text());newtree=ast.parse((r/'tools/regional_paged_fault_terminal.py').read_text())
for name in ('public_result','completed_body'):
 find=lambda t:ast.dump(next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name==name),include_attributes=False)
 assert find(oldtree)==find(newtree)
x['python_source_commitment']=hashlib.sha256(json.dumps(x['python_source_sha256'],sort_keys=True,separators=(',',':')).encode()).hexdigest();x['terminal_observation_profile']='RLD-TERMINAL-HEAD-SLOT-ENCODING-V1';x['prior_identity_sha256']=sha(e/'regional-keyless-stopped-drain-v1-identity-20261007.json');x['source_delta']=list(rev['files']);x['qualification_scope']='34 driver models source unchanged and7 actual execute/atomic terminal models. All old protocol/native/value/TLS/owner/cold/deadline/public privacy guards unchanged. Full original600 still FAIL/unknown, fresh full profile required, no old failed reopen.'
seal=b/'native-paged-full-fault-stopped-v15-stopped-private-inventory-20261007.json';assert sha(seal)=='c72b4cdd152783bbea76646b6e156949e22bfe0594bdc36c93cb1b7908722d96';x['protected_private_inventory_sha256'][str(seal)]=sha(seal)
with (e/'regional-terminal-head-encoding-v1-identity-20261007.json').open('x') as f:f.write(json.dumps(x,sort_keys=True,indent=2)+'\n')
combined=copy.deepcopy(json.loads((b/'keyless-stopped-drain-combined-source-reversal-v1-20261007.json').read_text()));combined['terminal_head_encoding_reversal_sha256']=sha(b/'terminal-head-encoding-source-reversal-v1-20261007.json');combined['files'].update(rev['files'])
with (b/'terminal-head-encoding-combined-source-reversal-v1-20261007.json').open('x') as f:f.write(json.dumps(combined,indent=2)+'\n')
t=(b/'keyless_stopped_drain_source_bridge_v1.py').read_text().replace('keyless-stopped-drain-combined-source-reversal-v1-20261007.json','terminal-head-encoding-combined-source-reversal-v1-20261007.json')
insert="""
 term=json.loads((b/'terminal-head-encoding-source-reversal-v1-20261007.json').read_text())
 for path,row in term['files'].items():
  text=(r/path).read_text()
  text=text.replace(term['after'],term['before']) if path.endswith('/regional_paged_fault_terminal.py') else text.replace(term['new_test_class'],'')
  assert text==Path(row['backup']).read_text() and hashlib.sha256(text.encode()).hexdigest()==row['old_sha256'] and sha(r/path)==row['new_sha256']
 tested=json.loads((e/'regional-terminal-head-encoding-model-v1-20261007.json').read_text())
 assert tested['completed'] and tested['tests_run']==7 and tested['terminal_source_sha256']==sha(r/'tools/regional_paged_fault_terminal.py') and tested['tests_sha256']==sha(r/'tools/test_regional_paged_fault_terminal.py')
"""
t=t.replace(' latest=current\n',' latest=current\n'+insert);compile(t,'bridge','exec');(b/'terminal_head_encoding_source_bridge_v1.py').write_text(t)
g=dict(format='RLD-TERMINAL-HEAD-ENCODING-SOURCE-GATE-V1',completed=True,helper_terminal=True,helper_exit_code=0,binding_source_sha256=sha(r/'tools/regional_paged_fault_terminal.py'),tests_sha256=sha(r/'tools/test_regional_paged_fault_terminal.py'),model_checks_sha256=sha(e/'regional-terminal-head-encoding-model-v1-20261007.json'),source_reversal_sha256=sha(b/'terminal-head-encoding-source-reversal-v1-20261007.json'),tests=7,old4_tests_byte_preserved=True,public_result_completed_body_cleanup_deadline_guards_unchanged=True,full_fault_qualified=False)
with (e/'regional-terminal-head-encoding-source-gate-v1-20261007.json').open('x') as f:f.write(json.dumps(g,indent=2)+'\n')
for old,new in [('observe-paged-fault-native-prepare-stopped-v18-20261007.py','observe-paged-fault-native-prepare-head-v19-20261007.py'),('check-paged-fault-native-prepare-stopped-v18-20261007.py','check-paged-fault-native-prepare-head-v19-20261007.py'),('observe-paged-fault-full-stopped-v15-20261007.py','observe-paged-fault-full-head-v16-20261007.py'),('check-paged-fault-full-stopped-v15-20261007.py','check-paged-fault-full-head-v16-20261007.py')]:
 text=(b/old).read_text().replace('prepare-stopped-v18','prepare-head-v19').replace('preparation-stopped-v18','preparation-head-v19').replace('full-fault-stopped-v15','full-fault-head-v16').replace('full-stopped-v15','full-head-v16').replace('controller-stopped-v15','controller-head-v16').replace('keyless_stopped_drain_source_bridge_v1','terminal_head_encoding_source_bridge_v1').replace('regional-keyless-stopped-drain-v1-identity','regional-terminal-head-encoding-v1-identity')
 if new.startswith('observe-paged-fault-full-'):text=text.replace("c=document(e/'regional-paged-fault-terminal-v1-20261005-checks.json')","c=document(e/'regional-terminal-head-encoding-source-gate-v1-20261007.json')")
 if new.startswith('check-'):
  # The previous scope's immutable preflight remains prior evidence; this new
  # scope receives a separately checked actual helper before launch.
  text=text.replace("regional-keyless-stopped-drain-full-v15-entry-preflight-20261007.json","regional-keyless-stopped-drain-full-v15-entry-preflight-20261007.json")
  idx=text.index('def pins(');text=text[:idx]+"for p in (e/'regional-terminal-head-encoding-v1-identity-20261007.json',e/'regional-terminal-head-encoding-model-v1-20261007.json',e/'regional-terminal-head-encoding-counter-v1-20261007.json',e/'regional-terminal-head-encoding-source-gate-v1-20261007.json',e/'regional-paged-full-fault-stopped-v15-20261007-checks.json',b/'terminal-head-encoding-source-reversal-v1-20261007.json',b/'terminal-head-encoding-combined-source-reversal-v1-20261007.json',b/'terminal_head_encoding_source_bridge_v1.py',b/'regional_paged_fault_terminal-before-head-encoding-v1-20261007.py',b/'test_regional_paged_fault_terminal-before-head-encoding-v1-20261007.py'):\n protected[str(p)]=sha(p)\n"+text[idx:]
  text=text.replace("hypothesis='", "hypothesis='Necessary fresh full scope after exact nonempty tuple-head JSON emission TypeError at prior589.344/6965: only private slot key encoding changes.7 execute/atomic models plus original guards unchanged, actual full cold/body outcome previously unknown; no retroactive PASS. ",1)
  if 'native-prepare' in new:text=text.replace("changed_source='", "changed_source='Exact private terminal slot-key encoding only, after stopped-v15 FAIL589.344/6965 with missing raw/public result; new source gate7, previous Driver34 unchanged and reused. ",1)
 compile(text,new,'exec');assert not (b/new).exists();(b/new).write_text(text)
print(json.dumps(dict(new_source192=x['python_source_commitment'],terminal_source_sha256=sha(r/'tools/regional_paged_fault_terminal.py'),unchanged_native_core_binary_driver_service_runtime_mesh_tcp_bft=True,helpers_syntax_checked=4,duration_seconds=round(time.monotonic()-start,6))))
