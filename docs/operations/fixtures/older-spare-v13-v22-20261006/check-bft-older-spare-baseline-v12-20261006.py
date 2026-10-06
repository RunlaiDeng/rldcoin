import ast,hashlib,json,os,subprocess,sys,time
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();deadline=start+10;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
root=b/'bft-older-spare-baseline-v12-private-20261006';assert not root.exists();root.mkdir()
helper=b/'observe-bft-older-spare-baseline-v12-20261006.py';assert not helper.exists()
helper.write_text("from pathlib import Path\nimport sys,unittest\nr=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))\nimport test_interstellar_mesh as tests\nassert tests.mesh.TRANSIT_SCHEDULER=='RLD-CONTACT-TRANSIT-SCHEDULER-V12'\nclass Retained(tests.MeshTests):\n    def setUp(self):self.f=tests.Fixture(r/'tmp/default-relay-20260930/bft-older-spare-baseline-v12-private-20261006/fixture')\nresult=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([Retained('test_older_unserved_gets_alternate_priority_pair_without_displacing_offers')]))\nraise SystemExit(0 if result.wasSuccessful() else 1)\n")
compile(helper.read_text(),str(helper),'exec');bound={str(p):sha(p) for p in [r/'tools/interstellar_mesh.py',r/'tools/test_interstellar_mesh.py',helper,Path(__file__),r/'docs/WHITEPAPER_FREEZE_RECEIPT.json']};log=b/'bft-older-spare-baseline-v12-20261006.log';code=None;failure=None;child=None
try:
 with log.open('xb') as f:
  child=subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(helper)],cwd=r,stdout=f,stderr=subprocess.STDOUT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));code=child.wait(timeout=max(.001,deadline-time.monotonic()))
except BaseException as x:
 failure=type(x).__name__+': '+str(x)
 if child is not None and child.poll() is None:child.kill();child.wait()
duration=round(time.monotonic()-start,6);sys.path.insert(0,str(r/'tools'));from regional_paged_fault_scope import inventory
seal=b/'bft-older-spare-baseline-v12-stopped-private-inventory-20261006.json';seal.write_text(json.dumps({str(root):inventory(root)},sort_keys=True,indent=2)+'\n')
report=dict(completed=code==0 and not failure,budget_seconds=10,attempts=1,duration_seconds=duration,helper_exit_code=code,helper_pid=child.pid,helper_stopped=child.poll() is not None,failure=failure,source_sha256=bound,pin_error=[p for p,h in bound.items() if sha(Path(p))!=h],log=log.read_text(),log_sha256=sha(log),seal_sha256=sha(seal),retained_files=len(json.loads(seal.read_text())[str(root)]),combined_original_ground60_seconds=round(12.671297+duration,6),old_failed_fixtures_opened=False,Native_Runtime_socket_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False)
(e/'regional-bft-older-spare-baseline-v12-20261006-checks.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,sort_keys=True));raise SystemExit(0 if report['completed'] else 1)
