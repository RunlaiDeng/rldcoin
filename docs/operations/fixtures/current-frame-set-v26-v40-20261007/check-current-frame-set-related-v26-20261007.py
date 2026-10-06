from pathlib import Path
import ast,dis,hashlib,json,os,subprocess,sys,time,types,builtins
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();prior=5.489205;deadline=start+min(10,60-prior);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();sys.path.insert(0,str(r/'tools'));import test_interstellar_mesh as tests
names=['test_stable_current_frame_set_survives_ordinary_ring_interference','test_same_current_frame_revisits_distinct_unreceipted_destinations','test_failed_current_prepare_oldest_pair_precedes_newer_current','test_new_arrival_uses_ordinary_class_slot_with_full_waiting_queue','test_other_ordinary_pair_keeps_original_recent_and_history_order','test_older_unserved_gets_alternate_priority_pair_without_displacing_offers','test_commit_hint_capacity_eviction_and_contact_scope_fall_back','test_current_frame_hint_survives_group_position_pressure_in_same_plan','test_current_frame_hint_pressure_ordinary_delivery']
positive=b/'competing-current-oldest-method-v24-20261007.py';method=compile(positive.read_text(),str(positive),'exec');ns={k:getattr(tests,k) for k in ('mesh','evidence','json','copy','patch','NETWORK')};providers=set()
def bound(c,scope):
 for z in dis.get_instructions(c):
  if z.opname=='LOAD_GLOBAL':
   providers.add(z.argval);assert z.argval in scope or hasattr(builtins,z.argval),(z.argval,'unbound')
 for z in c.co_consts:
  if isinstance(z,types.CodeType):bound(z,scope)
bound(method,ns);bound(getattr(tests.MeshTests,names[0]).__code__,tests.__dict__)
for name in names:
 if name!=names[2]:assert callable(getattr(tests.MeshTests,name))
root=b/'bft-current-frame-set-related-v26-private-20261007';helper=b/'observe-bft-current-frame-set-related-v26-20261007.py';assert not root.exists() and not helper.exists()
source="from pathlib import Path\nimport sys,unittest\nr=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))\nimport test_interstellar_mesh as tests\nfrom test_interstellar_mesh import mesh,evidence,json,copy,patch,NETWORK\n"+positive.read_text()+"\nclass Retained(tests.MeshTests):\n def setUp(self):self.f=tests.Fixture("+repr(str(root))+"+'/'+self._testMethodName)\nRetained.test_failed_current_prepare_oldest_pair_precedes_newer_current=test_failed_current_prepare_oldest_pair_precedes_newer_current\nresult=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite(Retained(n) for n in "+repr(names)+"))\nraise SystemExit(0 if result.wasSuccessful() else 1)\n"
compile(source,str(helper),'exec');helper.write_text(source)
protected={str(p):sha(p) for p in (r/'tools/interstellar_mesh.py',r/'tools/test_interstellar_mesh.py',r/'tools/interstellar_tcp.py',r/'tools/regional_bft_node.py',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',helper,Path(__file__),positive,b/'current-frame-set-v26-reversal-20261007.json',b/'current-frame-set-v26-reversal-20261007.json',b/'current-frame-set-baseline-v25-stopped-inventory-20261007.json',b/'native-bft-four-cli-service-first-service-diag-v38-stopped-private-inventory-20261006.json')}
stage=e/'regional-bft-current-frame-set-related-v26-20261007-stage.json';out=e/'regional-bft-current-frame-set-related-v26-20261007-checks.json';assert not stage.exists() and not out.exists();stage.write_text(json.dumps(dict(budget_seconds=10,original_related60_prior_seconds=prior,attempts=1,hypothesis='Stable exact current frame set rotates whole authenticated envelopes within each original class independently of ordinary ring; changed set/missing positions falls back to original frame order, same-frame copy rotation retained. Preserve first2/history floor/nonpriority/full4/auth/atomic/bytes/ordinary receipt/cold.',tests=names,actual_global_providers=sorted(providers),source_sha256=protected,exit='first guard or original10/remaining60; retain all failures, no old Native/Runtime/sign/key/socket fixture calls'),indent=2)+'\n')
log=b/'bft-current-frame-set-related-v26-20261007.log';code=None;failure=None;child=None
try:
 with log.open('xb') as f:
  child=subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(helper)],cwd=r,stdout=f,stderr=f,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));code=child.wait(timeout=max(.001,deadline-time.monotonic()))
except BaseException as error:
 failure=type(error).__name__+': '+str(error)
 if child is not None and child.poll() is None:child.kill();child.wait()
sys.path.insert(0,str(r/'tools'));from regional_paged_fault_scope import inventory
seal=b/'bft-current-frame-set-related-v26-stopped-private-inventory-20261007.json';assert not seal.exists();seal.write_text(json.dumps({str(root):inventory(root)},sort_keys=True)+'\n');pin=[p for p,h in protected.items() if sha(Path(p))!=h];duration=round(time.monotonic()-start,6);ok=code==0 and failure is None and not pin and duration<=10 and prior+duration<=60
result=dict(completed=ok,budget_seconds=10,attempts=1,duration_seconds=duration,combined_current_frame_set_related60_seconds=round(prior+duration,6),helper_exit_code=code,failure=failure,pin_error=pin,helper_stopped=child is not None and child.poll() is not None,tests=names,stage_sha256=sha(stage),helper_sha256=sha(helper),controller_sha256=sha(Path(__file__)),log=log.read_text(),log_sha256=sha(log),seal_sha256=sha(seal),retained_files=len(json.loads(seal.read_text()).get(str(root),{})),old_failed_fixtures_opened=False,Native_Runtime_constructors_socket_calls=0,model_Runtime_methods_called=True,once_final_ordinary_ground_method_executed=True,original_Mesh_ground60_unreset=59.803250,original_TCP_related60_unreset=3.451646,original_hint_related60_unreset=1.392620,new180=0,new600=0,full_fault_qualified=False)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));raise SystemExit(0 if ok else 1)
