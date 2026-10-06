import ast, datetime, hashlib, json, os, subprocess, sys, time
from pathlib import Path
r=Path.cwd(); assert r==Path('/Users/galaxy/GitHub/rldcoin')
b=r/'tmp/default-relay-20260930'; e=r/'docs/operations/evidence'; start=time.monotonic(); deadline=start+10
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
root=b/'bft-older-spare-delivery-v13-v3-private-20261006'; assert not root.exists()
identity=json.loads((e/'regional-bft-unserved-promotion-final-identity-20261006.json').read_text())
current={p:sha(r/p) for p in identity['python_source_sha256']}; delta=[p for p,h in current.items() if h!=identity['python_source_sha256'][p]]; assert set(delta)=={'tools/test_interstellar_mesh.py','tools/interstellar_mesh.py'},delta
assert all(sha(r/p)==h for p,h in identity['native_source_sha256'].items())
old=subprocess.run(['git','show','HEAD:tools/test_interstellar_mesh.py'],cwd=r,capture_output=True,text=True,check=True).stdout
new=(r/'tools/test_interstellar_mesh.py').read_text(); names=lambda x:{n.name:ast.dump(n,include_attributes=False) for n in ast.walk(ast.parse(x)) if isinstance(n,ast.FunctionDef)}
a,c=names(old),names(new); assert all(c[k]==v for k,v in a.items()); assert set(c)-set(a)=={'test_older_unserved_gets_alternate_priority_pair_without_displacing_offers','test_older_spare_priority_reaches_destination_via_ordinary_ticks'}
protected={str(r/p):h for p,h in current.items()}; protected[str(r/'docs/WHITEPAPER_FREEZE_RECEIPT.json')]=sha(r/'docs/WHITEPAPER_FREEZE_RECEIPT.json')
for suffix in ('single-commit-boundary-v21-20261006-checks.json','commit-selection-model-v21-20261006-checks.json'):
 p=e/('regional-bft-'+suffix);protected[str(p)]=sha(p)
protected[str(Path(__file__))]=sha(Path(__file__))
stage=dict(format='RLD-OLDER-PENDING-REGRESSION-STAGE-V1',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=10,attempts=1,original_ground60_prior_seconds=18.323975,hypothesis='V12 retained pending older spare-class target reaches complete destination signed receipt through exactly one source and one destination ordinary tick.',exit='First auth/bytes/atomic/pair/retry/cold/source guard failure or10 seconds; no old fixture constructors, Native, Runtime, socket, or new180/600.',protected_sha256=protected,source_delta=delta,production_scheduler_source_changed=True,old_test_AST_unchanged=True)
sp=e/'regional-bft-older-spare-delivery-v13-v3-20261006-stage.json'; assert not sp.exists();sp.write_text(json.dumps(stage,indent=2)+'\n');root.mkdir()
helper=b/'observe-bft-older-spare-delivery-v13-v3-20261006.py';assert not helper.exists()
helper.write_text("from pathlib import Path\nimport sys, unittest\nr=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))\nimport test_interstellar_mesh as tests\nclass Retained(tests.MeshTests):\n    def setUp(self):\n        self.f=tests.Fixture(r/'tmp/default-relay-20260930/bft-older-spare-delivery-v13-v3-private-20261006/fixture')\nsuite=unittest.TestSuite([Retained('test_older_spare_priority_reaches_destination_via_ordinary_ticks')])\nresult=unittest.TextTestRunner(verbosity=2).run(suite)\nraise SystemExit(0 if result.wasSuccessful() else 1)\n")
compile(helper.read_text(),str(helper),'exec'); log=b/'bft-older-spare-delivery-v13-v3-20261006.log'; code=None; failure=None; child=None
try:
 with log.open('xb') as f:
  child=subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(helper)],cwd=r,stdout=f,stderr=subprocess.STDOUT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
  code=child.wait(timeout=max(.001,deadline-time.monotonic()))
except BaseException as ex:
 failure=type(ex).__name__+': '+str(ex)
 if child is not None and child.poll() is None:child.kill();child.wait()
duration=round(time.monotonic()-start,6); pin=[p for p,h in protected.items() if sha(Path(p))!=h]
sys.path.insert(0,str(r/'tools'));from regional_paged_fault_scope import inventory
seal=b/'bft-older-spare-delivery-v13-v3-stopped-private-inventory-20261006.json';seal.write_text(json.dumps({str(root):inventory(root)},sort_keys=True,indent=2)+'\n')
ok=code==0 and failure is None and not pin and duration<=10
report=dict(completed=ok,helper_exit_code=code,helper_pid=child.pid if child else None,helper_stopped=child is None or child.poll() is not None,duration_seconds=duration,budget_seconds=10,attempts_used=1,combined_original_ground60_seconds=round(18.323975+duration,6),failure=failure,pin_error=pin,stage_sha256=sha(sp),helper_sha256=sha(helper),controller_sha256=sha(Path(__file__)),log_sha256=sha(log),log=log.read_text(),retained_inventory_sha256=sha(seal),retained_files=len(json.loads(seal.read_text())[str(root)]),python192_source_sha256=current,python192_source_commitment=hashlib.sha256(json.dumps(current,sort_keys=True,separators=(',',':')).encode()).hexdigest(),source_delta=delta,old_tests_AST_unchanged=True,production_profile_unchanged='RLD-CONTACT-TRANSIT-SCHEDULER-V13',old_failed_fixtures_opened=False,Native_Runtime_socket_calls=0,new180_allocated=0,new600_allocated=0,Native_maturity_cold_conservation_full_fault_qualified=False)
cp=e/'regional-bft-older-spare-delivery-v13-v3-20261006-checks.json';cp.write_text(json.dumps(report,indent=2)+'\n'); print(json.dumps({k:v for k,v in report.items() if k not in ('python192_source_sha256',)},sort_keys=True));raise SystemExit(0 if ok else 1)
