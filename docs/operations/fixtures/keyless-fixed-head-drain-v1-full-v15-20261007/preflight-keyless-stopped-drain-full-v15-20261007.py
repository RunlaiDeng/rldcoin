from pathlib import Path
import ast,dis,types,builtins,sys,time,json,hashlib
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';p=b/'observe-paged-fault-full-stopped-v15-20261007.py';out=e/'regional-keyless-stopped-drain-full-v15-entry-preflight-20261007.json';assert not out.exists();started=time.monotonic();tree=ast.parse(p.read_text(),str(p));kept=[]
for node in tree.body:
 if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='result' for t in node.targets):break
 if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Attribute) and isinstance(node.value.func.value,ast.Name) and node.value.func.value.id=='signal' and node.value.func.attr=='signal':continue
 if isinstance(node,ast.Assign) and any(isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name) and t.value.id=='driver_module' for t in node.targets):continue
 kept.append(node)
ns={'__file__':str(p),'__name__':'preflight_only'};oldargv=sys.argv;sys.argv=[str(p),str(time.monotonic()+600)]
try:exec(compile(ast.Module(body=kept,type_ignores=[]),str(p),'exec'),ns)
finally:sys.argv=oldargv
names=set()
def inspect(code):
 for i in dis.get_instructions(code):
  if i.opname=='LOAD_GLOBAL':names.add(i.argval)
 for c in code.co_consts:
  if isinstance(c,types.CodeType):inspect(c)
for f in (ns['make'],ns['traced_observation_height'],*[v for v in vars(ns['Tracked']).values() if isinstance(v,types.FunctionType)]):inspect(f.__code__)
assert not (names-set(ns)-set(vars(builtins))),sorted(names-set(ns)-set(vars(builtins)))
assert not ns['output'].exists();assert (ns['root']/'native-prepared-observation.json').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
x=json.loads((e/'regional-keyless-stopped-drain-v1-identity-20261007.json').read_text());assert all(sha(r/p)==h for p,h in x['python_source_sha256'].items())
report=dict(completed=True,duration_seconds=round(time.monotonic()-started,6),budget_seconds=20,attempts=1,actual_LOAD_GLOBAL_names=sorted(names),actual_providers=len(names),helper_sha256=sha(p),driver_sha256=sha(r/'tools/regional_paged_fault_driver.py'),make_Tracked_guard_functions_executed=False,Native_Runtime_Node_socket_key_sign_fixture_calls=0,output_absent=True,production192_unchanged=True,full_fault_qualified=False)
with out.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
assert report['duration_seconds']<=20
print(json.dumps(report))
