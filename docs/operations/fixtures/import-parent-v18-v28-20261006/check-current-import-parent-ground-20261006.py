import ast,hashlib,json,os,subprocess,sys,time
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence'
label=sys.argv[1];prior=float(sys.argv[2]);names=sys.argv[3:];start=time.monotonic();deadline=start+10;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert prior<60 and names and label in ('baseline-v13','related-v14','delivery-v14','runtime-binding-v14','delivery-v14-v2','capacity-v14','delivery-final-v14','prepared-baseline-v14','prepared-related-v15','delivery-final-v15','prepare-baseline-v15','prepare-related-v16','prepare-delivery-v16','proposal-baseline-v16','proposal-related-v17','proposal-delivery-v17','import-parent-baseline-v17','import-parent-related-v18','import-parent-delivery-v18')
root=b/('bft-current-commit-'+label+'-private-20261006');assert not root.exists()
helper=b/('observe-bft-current-commit-'+label+'-20261006.py');assert not helper.exists()
source="from pathlib import Path\nimport sys,unittest\nr=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))\nimport test_interstellar_mesh as tests\nclass Retained(tests.MeshTests):\n    def setUp(self):self.f=tests.Fixture("+repr(str(root))+"+'/'+self._testMethodName)\nresult=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite(Retained(n) for n in "+repr(names)+"))\nraise SystemExit(0 if result.wasSuccessful() else 1)\n"
compile(source,str(helper),'exec');ast.parse((r/'tools/test_interstellar_mesh.py').read_text());helper.write_text(source)
protected={str(q):sha(q) for q in [r/'tools/interstellar_mesh.py',r/'tools/regional_bft_node.py',r/'tools/test_interstellar_mesh.py',r/'docs/WHITEPAPER_FREEZE_RECEIPT.json',helper,Path(__file__)]}
stage=e/('regional-bft-current-commit-'+label+'-20261006-stage.json');assert not stage.exists()
stage.write_text(json.dumps(dict(budget_seconds=10,attempts=1,original_ground60_prior_seconds=prior,tests=names,source_sha256=protected,exit='first guard failure or original10 deadline; retain failure; no duplicate same-source attempt; no old fixture constructors; no Native/runtime/socket calls'),indent=2)+'\n')
root.mkdir();log=b/('bft-current-commit-'+label+'-20261006.log');code=None;failure=None;child=None
try:
 with log.open('xb') as f:
  child=subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(helper)],cwd=r,stdout=f,stderr=subprocess.STDOUT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));code=child.wait(timeout=max(.001,min(deadline-time.monotonic(),60-prior)))
except BaseException as x:
 failure=type(x).__name__+': '+str(x)
 if child is not None and child.poll() is None:child.kill();child.wait()
duration=round(time.monotonic()-start,6);sys.path.insert(0,str(r/'tools'));from regional_paged_fault_scope import inventory
seal=b/('bft-current-commit-'+label+'-stopped-private-inventory-20261006.json');seal.write_text(json.dumps({str(root):inventory(root)},sort_keys=True,indent=2)+'\n');pin=[q for q,h in protected.items() if sha(Path(q))!=h]
report=dict(completed=code==0 and not failure and not pin and duration<=10 and prior+duration<=60,budget_seconds=10,attempts=1,duration_seconds=duration,helper_exit_code=code,helper_pid=child.pid,helper_stopped=child.poll() is not None,failure=failure,pin_error=pin,stage_sha256=sha(stage),helper_sha256=sha(helper),controller_sha256=sha(Path(__file__)),log=log.read_text(),log_sha256=sha(log),seal_sha256=sha(seal),retained_files=len(json.loads(seal.read_text())[str(root)]),combined_original_ground60_seconds=round(prior+duration,6),old_failed_fixtures_opened=False,Native_Runtime_constructors_socket_calls=0,model_Runtime_methods_called=label.startswith('delivery'),new180_allocated=0,new600_allocated=0,full_fault_qualified=False)
out=e/('regional-bft-current-commit-'+label+'-20261006-checks.json');out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,sort_keys=True));raise SystemExit(0 if report['completed'] else 1)
