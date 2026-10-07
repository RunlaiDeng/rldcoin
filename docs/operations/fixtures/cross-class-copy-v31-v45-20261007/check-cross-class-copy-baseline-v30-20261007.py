from pathlib import Path
import ast,dis,hashlib,json,os,subprocess,sys,time,types,builtins
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();deadline=start+min(10,60-24.803208);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
method=b/'cross-class-copy-counter-method-v30-20261007.py';root=b/'cross-class-copy-baseline-v30-private-20261007';helper=b/'cross-class-copy-baseline-v30-helper-20261007.py';assert not root.exists() and not helper.exists()
sys.path.insert(0,str(r/'tools'));import test_interstellar_mesh as tests
text=method.read_text();compiled=compile(text,str(method),'exec');ns={k:getattr(tests,k) for k in ('mesh','evidence','json','copy','patch','NETWORK')};providers=set()
def bind(c):
 for z in dis.get_instructions(c):
  if z.opname=='LOAD_GLOBAL':
   providers.add(z.argval);assert z.argval in ns or hasattr(builtins,z.argval),(z.argval,'unbound global')
 for z in c.co_consts:
  if isinstance(z,types.CodeType):bind(z)
bind(compiled)
source="from pathlib import Path\nimport sys,unittest\nr=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))\nimport test_interstellar_mesh as tests\nfrom test_interstellar_mesh import mesh,evidence,json,copy,patch,NETWORK\n"+text+"\nclass Retained(tests.MeshTests):\n def setUp(self):self.f=tests.Fixture("+repr(str(root))+"+'/'+self._testMethodName)\n def tearDown(self):pass\nRetained.test_same_current_copy_survives_recent_to_history_transition=test_same_current_copy_survives_recent_to_history_transition\nresult=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite([Retained('test_same_current_copy_survives_recent_to_history_transition')]))\nraise SystemExit(0 if result.wasSuccessful() else 1)\n"
compile(source,str(helper),'exec');helper.write_text(source)
protected={str(p):sha(p) for p in (method,helper,Path(__file__),r/'tools/interstellar_mesh.py',r/'tools/interstellar_tcp.py',r/'tools/regional_bft_node.py',r/'tools/test_interstellar_mesh.py',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',b/'native-bft-four-cli-service-first-service-diag-v44-stopped-private-inventory-20261006.json')}
stage=e/'regional-bft-cross-class-copy-baseline-v30-20261007-stage.json';out=e/'regional-bft-cross-class-copy-baseline-v30-20261007-checks.json';assert not stage.exists() and not out.exists();stage.write_text(json.dumps(dict(hypothesis='V44 source2Proposalto0 waited58.298886s; actualsameframe sibling wasrecentlyprepared atoldest29 thenrepeated aftermove tohistory atnewest33 whileotherdestinationunprepared. Fresh real signedtwo-destination sameframe original32recent boundtransition tests missingnewkindcopyposition versus retainedsamepeer/scope/frame otherkind position. First2/floor/full4/auth/atomic/oldest/doublemiss/cold remain required. One10/remaining60, nooldNativecalls ortransportcounterreplay.',budget_seconds=10,attempts=1,prior_seconds=24.803208,prior_Mesh_ground60_unreset=59.803250,ground_role_analogy_only=True,protected_sha256=protected,actual_global_providers=sorted(providers),static_generate_calls=0,exit='first original guard or60seconds; semantic old-target failure retains FAIL and selects only ordering repair; old Native/Runtime/socket calls0'),indent=2)+'\n')
log=b/'cross-class-copy-baseline-v30-20261007.log';assert not log.exists()
with log.open('xb') as f:
 p=subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(helper)],cwd=r,stdout=f,stderr=f,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));code=p.wait(timeout=max(.001,deadline-time.monotonic()))
from regional_paged_fault_scope import inventory
seal=b/'cross-class-copy-baseline-v30-stopped-inventory-20261007.json';assert not seal.exists();seal.write_text(json.dumps({str(root):inventory(root)},sort_keys=True)+'\n');assert all(sha(Path(p))==h for p,h in protected.items());duration=round(time.monotonic()-start,6)
result=dict(completed=code==0 and time.monotonic()<deadline,helper_exit_code=code,duration_seconds=duration,original60_cumulative_seconds=round(24.803208+duration,6),stage_sha256=sha(stage),log_sha256=sha(log),seal_sha256=sha(seal),retained_files=len(json.loads(seal.read_text())[str(root)]),static_actual_provider_binding_passed=True,production_sources_freeze_and_old_inventory_unchanged=True,Native_Runtime_constructors_socket_oldfixture_calls=0,ground_role_analogy_not_native_maturity=True,new180=0,new600=0)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));print(log.read_text());raise SystemExit(code)
