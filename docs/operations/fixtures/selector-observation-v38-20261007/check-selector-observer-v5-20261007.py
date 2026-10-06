from pathlib import Path
import copy,hashlib,json,os,subprocess,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();prior=.558143;deadline=start+60-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sys.path.insert(0,str(b));sys.path.insert(0,str(r/'tools'))
import first_service_diagnostic_observer_v5_20261007 as diag
from first_service_diagnostic_collector_v3_20261007 import diag as collector_diag
import interstellar_mesh as mesh
assert collector_diag.FORMAT==diag.FORMAT=='RLD-FIRST-SERVICE-DIAGNOSTIC-V3'
for owner,names in [(diag.Observer,('install','restore')),(diag.Ring,('snapshot','append'))]:
 for name in names:assert callable(getattr(owner,name))
packet='1'*64;peer='2'*64;scope='3'*64;frame='4'*64
view=dict(hint_reads=[dict(scope=scope,frame_ids=[frame]),None],groups=[[[packet],[]]],transit_checks={packet:2},routes={packet:dict(attempts=2,path=[peer])});diag.check_selector(view)
with mesh._carriage_position_lock:before=copy.deepcopy(mesh._carriage_positions);size=mesh._carriage_position_bytes
cases=[]
def deny(value,name):
 try:diag.check_selector(value)
 except ValueError:cases.append(name)
 else:raise AssertionError('bad selector accepted '+name)
for field,value in [('extra',0),('hint_reads',[None]*3),('hint_reads',[dict(scope='z'*64,frame_ids=[frame])]),('hint_reads',[dict(scope=scope,frame_ids=[frame]*2)]),('groups',[[[packet],[packet]]]),('groups',[[]]),('groups',[[],[],[]]),('transit_checks',{packet:True}),('transit_checks',{packet:0}),('transit_checks',{packet:1025}),('routes',{'5'*64:dict(attempts=1,path=None)}),('routes',{packet:dict(attempts=True,path=None)}),('routes',{packet:dict(attempts=0,path=None)}),('routes',{packet:dict(attempts=1,path=[peer]*2)}),('routes',{packet:dict(attempts=1,path=['z'*64])}),('routes',{packet:dict(attempts=1,path=tuple([peer]))})]:
 v=copy.deepcopy(view);v[field]=value;deny(v,field)
with mesh._carriage_position_lock:assert mesh._carriage_positions==before and list(mesh._carriage_positions)==list(before) and mesh._carriage_position_bytes==size
root=b/'selector-observer-v5-ground-private-20261007';helper=b/'selector-observer-v5-ground-helper-20261007.py';assert not root.exists() and not helper.exists()
oldhelper=b/'competing-current-oldest-baseline-v24-helper-20261007.py';source=oldhelper.read_text().replace(str(b/'competing-current-oldest-baseline-v24-private-20261007'),str(root))
source=source.replace("import test_interstellar_mesh as tests\n","import test_interstellar_mesh as tests\nsys.path.insert(0,str(r/'tmp/default-relay-20260930'))\nimport interstellar_tcp as tcp\nimport first_service_diagnostic_observer_v5_20261007 as diag\n",1)
source=source.replace(" def setUp(self):self.f=tests.Fixture("," def setUp(self):\n  self.f=tests.Fixture(",1)
source=source.replace(" def tearDown(self):pass",'''  self.ring=diag.Ring(dict(process_id=999999,scope=str(self.f.root),slot=0,contract_sha256='a'*64))
  self.observer=diag.Observer(mesh,tcp,self.f.root/'earth',self.ring);self.observer.install()
 def tearDown(self):
  self.observer.restore();value=self.ring.snapshot()
  assert value['available'] and value['rejected']==0 and value['records']
  assert all('selector' in row for row in value['records'])
  consumed=[row for row in value['records'] if row['selector']['hint_reads'] and row['selector']['hint_reads'][0] is not None]
  assert consumed and any(row['selector']['groups'] and row['selector']['routes'] for row in consumed)
  print('selector-observation-result '+json.dumps(dict(completed=True,records=value['sequence'],available=value['available'],rejected=value['rejected'],actual_hint_reads=sum(len(z['selector']['hint_reads']) for z in value['records']),actual_groups=sum(len(z['selector']['groups']) for z in value['records']),actual_checked_ids=sum(len(z['selector']['transit_checks']) for z in value['records']),actual_route_ids=sum(len(z['selector']['routes']) for z in value['records']),original_signed_oldest_pair_and_ordinary_delivery_cold_assertions_passed=True)))''',1)
compile(source,str(helper),'exec');helper.write_text(source)
protected={str(p):sha(p) for p in (Path(__file__),helper,b/'first_service_diagnostic_observer_v5_20261007.py',b/'first_service_diagnostic_collector_v3_20261007.py',b/'selector-observer-v5-reversal-20261007.json',oldhelper,b/'competing-current-oldest-baseline-v24-stopped-inventory-20261007.json',r/'tools/interstellar_mesh.py',r/'tools/interstellar_tcp.py',r/'tools/regional_bft_node.py',r/'tools/test_interstellar_mesh.py',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',b/'native-bft-four-cli-service-first-service-diag-v37-stopped-private-inventory-20261006.json')}
stage=e/'regional-bft-selector-observer-v5-model-20261007-stage.json';out=e/'regional-bft-selector-observer-v5-model-20261007-checks.json';assert not stage.exists() and not out.exists();stage.write_text(json.dumps(dict(hypothesis='V37 records before planner cannot establish the hint actually consumed or actual recent/history ID order/route eligibility. Wrap original getters/groups/checks/routes once and retain only primitive original results; no extra LRU touch or protocol calls. V24 freshest signed multiple-frame counter passed, so no production ordering repair is supported.',budget_seconds=60,prior_seconds=prior,attempts=1,negative_cases=len(cases),original_Mesh_ground60_unreset=59.803250,protected_sha256=protected,exit='first original-function/schema/bound/byte guard or original60 deadline; never old Native/Runtime/socket/keys'),indent=2)+'\n')
log=b/'selector-observer-v5-ground-20261007.log';assert not log.exists()
with log.open('xb') as f:
 child=subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(helper)],cwd=r,stdout=f,stderr=f,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));code=child.wait(timeout=max(.001,deadline-time.monotonic()))
from regional_paged_fault_scope import inventory
seal=b/'selector-observer-v5-ground-stopped-inventory-20261007.json';assert not seal.exists();seal.write_text(json.dumps({str(root):inventory(root)},sort_keys=True)+'\n');assert all(sha(Path(p))==h for p,h in protected.items());results=[json.loads(z.split(' ',1)[1]) for z in log.read_text().splitlines() if z.startswith('selector-observation-result ')];duration=round(time.monotonic()-start,6);ok=code==0 and len(results)==1 and time.monotonic()<deadline
result=dict(completed=ok,helper_exit_code=code,budget_seconds=60,duration_seconds=duration,original60_cumulative_seconds=round(prior+duration,6),negative_cases=len(cases),readonly_schema_LRU_values_order_bytes_unchanged=True,original_functions_once_no_added_authentication_sign_getter_calls=True,original32events192KiB8MiB_unchanged=True,actual_ground_result=results,stage_sha256=sha(stage),log_sha256=sha(log),seal_sha256=sha(seal),retained_files=len(json.loads(seal.read_text())[str(root)]),production_sources_freeze_and_old_failed_inventory_unchanged=True,Native_Runtime_constructors_socket_oldfixture_calls=0,ground_role_analogy_only=True,new180=0,new600=0)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));print(log.read_text());raise SystemExit(0 if ok else 1)
