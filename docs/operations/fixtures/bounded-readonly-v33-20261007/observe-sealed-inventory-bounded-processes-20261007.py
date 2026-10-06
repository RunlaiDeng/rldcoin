from pathlib import Path
import hashlib,json,sys,time,subprocess,os
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'));from regional_paged_fault_scope import inventory
b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
if len(sys.argv)>1:
 root,seal,expected=sys.argv[1:];root=Path(root);seal=Path(seal);assert sha(seal)==expected;original=json.loads(seal.read_text())[str(root)];assert inventory(root)==original;print(json.dumps(dict(completed=True,files=len(original))));raise SystemExit(0)
start=time.monotonic();prior=2.908759;deadline=start+20-prior;out=e/'regional-bft-sealed-inventory-bounded-processes-20261007-checks.json';assert not out.exists();cases=[]
for v in (28,29,30,31):
 checks=json.loads((e/('regional-bft-four-cli-service-first-service-diag-v'+str(v)+'-20261006-checks.json')).read_text());assert not checks['completed'] and checks['guardian']['owned_processes_stopped'];root=b/('native-bft-four-cli-service-first-service-diag-v'+str(v)+'-private-20261006');seal=b/('native-bft-four-cli-service-first-service-diag-v'+str(v)+'-stopped-private-inventory-20261006.json');assert sha(seal)==checks['stopped_inventory_sha256'];original=json.loads(seal.read_text())[str(root)];cases.append((root,seal,sha(seal),original))
a=time.monotonic()
for root,seal,expected,original in cases:assert time.monotonic()<deadline and inventory(root)==original and sha(seal)==expected
serial=time.monotonic()-a;children=[];parallel=None;failure=None
try:
 a=time.monotonic()
 for root,seal,expected,original in cases:
  children.append(subprocess.Popen([str(r/'tmp/rldcoin-goal-20261001-venv/bin/python'),'-B',str(Path(__file__)),str(root),str(seal),expected],cwd=r,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')))
 for child in children:
  stdout,stderr=child.communicate(timeout=max(.001,deadline-time.monotonic()));assert child.returncode==0 and not stderr;assert json.loads(stdout)['completed']
 parallel=time.monotonic()-a
except BaseException as error:failure=type(error).__name__+': '+str(error)
finally:
 for child in children:
  if child.poll() is None:child.terminate();child.wait(timeout=2)
result=dict(completed=failure is None and time.monotonic()<deadline,budget_seconds=20,shared_prior_seconds=prior,combined_seconds=round(prior+time.monotonic()-start,6),attempts=1,serial_seconds=round(serial,6),four_process_seconds=None if parallel is None else round(parallel,6),candidate_faster_in_this_representative_sample=parallel is not None and parallel<serial,roots=4,total_exact_files=sum(len(z[3]) for z in cases),all_original_inventory_checks_and_file_byte_schema_mode_uid_mtime_bounds_unchanged=True,all_child_return_codes=[c.returncode for c in children],all_children_stopped=all(c.poll() is not None for c in children),failure=failure,Native_Node_Runtime_key_sign_socket_fixture_calls=0,new180=0,new600=0,not_a_full_inventory_or_scope_benchmark=True,whole_goal_completed=False)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True));raise SystemExit(0 if result['completed'] else 1)
