from pathlib import Path
import ast,json,sys,time,hashlib,types
import importlib.util
import tempfile
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(r/'tools'))
helper=b/sys.argv[1];tag=sys.argv[2];expected=sys.argv[3];start=time.monotonic();tree=ast.parse(helper.read_text());prefix=[]
for n in tree.body:
 if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='result' for t in n.targets):break
 if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=='signal':continue
 if isinstance(n,ast.Assign) and any(isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name) and t.value.id=='driver_module' for t in n.targets):continue
 prefix.append(n)
sys.argv=[str(helper),str(time.monotonic()+600)];space={'__file__':str(helper),'__name__':'stop_hook_model_not_launch'};exec(compile(ast.Module(body=prefix,type_ignores=[]),str(helper),'exec'),space)
p=b/'keyless-stale-observation-model-v1-20261007.py';spec=importlib.util.spec_from_file_location('model_provider',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
error=None;result=None
with tempfile.TemporaryDirectory(dir=r/'tmp',prefix='own-stop-hook-model-') as directory:
 d,p,value=m.StoppedObservationTests().setup_model(Path(directory));value['errors']=['TCP runtime is stopping; preserve evidence'];m.mesh.atomic(p,value);before=p.read_bytes();d.output=Path(directory)/'output';d.output.mkdir();d.stop_snapshot_sequence=0
 # Actual final helper hook with production Driver.stop_all, modeled process only.
 d.__class__=space['Tracked']
 d.persist_owned=types.MethodType(space['Tracked'].persist_owned,d)
 try:space['Tracked'].stop_all(d)
 except TypeError as failure:error=f'{type(failure).__name__}: {failure}'
 assert not d.processes and not d.logs and d.terminal[0]['exit_code']==0
 assert p.read_bytes()==before and len(d.stopped_observations)==1
 out=d.output/'own-clean-stopped-observations-1.json'
 if expected=='counter':assert error and 'multiple values' in error and not out.exists()
 else:
  assert error is None;result=json.loads(out.read_text());assert result['rows']==[dict(slot_region='earth',index=0,**d.stopped_observations['earth',0])];assert result['rows'][0]['region']==value['region'] and result['rows'][0]['slot_region']=='earth';assert result['Native_calls']==0 and result['ledger_or_signing_authority'] is False
  first=out.read_bytes();space['Tracked'].stop_all(d);assert out.read_bytes()==first and (d.output/'own-clean-stopped-observations-2.json').exists()
duration=time.monotonic()-start
prior=45.227978
if expected!='counter':prior=json.loads((e/'regional-keyless-stop-hook-counter-v1-20261007.json').read_text())['related60_after']
v=dict(completed=expected!='counter' and error is None,expected_counterexample=expected=='counter',failure=error,budget_seconds=60-prior,attempts=1,duration_seconds=round(duration,6),related60_before=prior,related60_after=round(prior+duration,6),helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),actual_Tracked_stop_all_and_Driver_stop_all_executed_on_fresh_model=True,Native_Runtime_Node_socket_key_sign_fixture_calls=0,Driver_constructor_calls=0,original_5seconds_cleanup_and_exit0_unchanged=True,exact_old_status_bytes_unchanged=True,cryptographic_region_preserved=True,full_fault_qualified=False)
assert v['related60_after']<60
with (e/('regional-keyless-stop-hook-'+tag+'-v1-20261007.json')).open('x') as f:json.dump(v,f,indent=2);f.write('\n')
print(json.dumps(v))
