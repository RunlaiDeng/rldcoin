from pathlib import Path
import sys,time,json,hashlib,signal,socket,subprocess,os
r=Path(__file__).resolve().parents[2];assert r==Path('/Users/galaxy/GitHub/rldcoin') and Path.cwd()==r;sys.path.insert(0,str(r/'tools'));sys.path.insert(0,str(r/'tmp/default-relay-20260930'))
b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';deadline=float(sys.argv[1]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();root=b/'native-paged-full-fault-native-preparation-einval-v13-private-20261007';output=b/'native-paged-full-fault-controller-einval-v10-private-20261007';python=r/'tmp/rldcoin-goal-20261001-venv/bin/python';binary=b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate'
from regional_paged_fault_prepared import Pins,bind
from regional_paged_fault_driver import Driver
from regional_paged_fault_terminal import execute
from regional_paged_fault_scope import document,require
from paged_return_value_accounting_v1 import observe as account
import interstellar_mesh as mesh
cp=e/'regional-paged-fault-native-prepare-einval-v13-20261007-checks.json';sp=e/'regional-paged-fault-native-prepare-einval-v13-20261007-stage.json';ip=b/'native-paged-full-fault-native-preparation-einval-v13-stopped-private-inventory-20261007.json';s=document(sp);o=document(root/'native-prepared-observation.json')
pins=Pins(sha(cp),sha(sp),sha(ip),s['source_commitment'],s['implementation'],s['cli_binary_sha256'],s['core_171_commitment'],o['currency'],sha(python.resolve(strict=True)))
def interrupted(signum,frame):raise TimeoutError('original600second full fault observation deadline')
signal.signal(signal.SIGTERM,interrupted)
class Tracked(Driver):
 def persist_owned(self):
  if self.output.exists():mesh.atomic(self.output/'owned-processes.json',dict(format='RLD-PAGED-FAULT-OWNED-PROCESSES-V1',processes=[dict(region=label,index=n,pid=p.pid,binary=str(binary),ledger=str(root/label/f'native-{n}')) for (label,n),p in self.processes.items() if p.poll() is None]))
 def record(self,*args,**kw):
  self.persist_owned();return super().record(*args,**kw)
 def call(self,label,n,command,*args):
  if command=='wallet-sign':
   self.attempted_owner_signs+=1
   require(self.attempted_owner_signs<=3,'three original owner first-sign attempts only')
   mesh.atomic(self.output/'owner-attempt-observation.json',dict(attempted=self.attempted_owner_signs,unknown_if_call_did_not_return=True))
  previous=len(self.calls)
  try:return super().call(label,n,command,*args)
  finally:
   if command=='wallet-receipt':
    row=self.calls[-1] if len(self.calls)>previous else dict(command=command,region=label,index=n,exit_code=None,observation_kind='NATIVE_RESULT_UNOBSERVED')
    print('paged-fault-receipt-read '+json.dumps(dict(row,phase=self.phase,remaining_seconds=round(max(0,self.deadline-time.monotonic()),3)),sort_keys=True),flush=True)
 def observations(self):
  rows=super().observations();now=time.monotonic()
  if now>=getattr(self,'next_live',0):
   self.next_live=now+10
   print('paged-fault-live '+json.dumps(dict(phase=self.phase,heights={label:[rows.get((label,n)) for n in range(4)] for label in ('earth','proxima','andromeda')},remaining_seconds=round(max(0,self.deadline-now),3),owned_nodes=len(self.processes)),sort_keys=True),flush=True)
  return rows
 def stop_all(self):
  try:return super().stop_all()
  finally:self.persist_owned()
# Capture the exact value already consumed by the original fatal guard.
# No extra Native/status sampling or changed acceptance predicate.
import regional_paged_fault_driver as driver_module
original_observation_height=driver_module.observation_height
def traced_observation_height(value,*args,**kwargs):
 try:return original_observation_height(value,*args,**kwargs)
 except ValueError:
  if '[Errno 22] Invalid argument' in value.get('errors',()):
   target=output/'exact-einval-guard-observation.json'
   if output.exists() and not target.exists():
    mesh.atomic(target,dict(format='RLD-EXACT-EINVAL-GUARD-OBSERVATION-V1',process_id=value.get('process_id'),currency=value.get('currency'),region=value.get('region'),current_error_list=value.get('errors',[])[:16],local_os_error_origins=value.get('local_os_errors',[])[:16],captured_exact_original_guard_argument=True,original_guard_rethrown_unchanged=True,Native_calls=0,ledger_or_signing_authority=False))
  raise
driver_module.observation_height=traced_observation_height
def make():
 c=document(e/'regional-bft-four-cli-service-first-service-diag-v47-20261006-checks.json');x=document(e/'regional-einval-origin-v1-identity-20261007.json');v=c['result'];from einval_origin_source_bridge_v1 import verify;old=verify(r,x)
 require(c['completed'] and c['helper_terminal'] and c['helper_exit_code']==0 and c['duration_seconds']<=180 and c['companion_source_commitment']==old['python_source_commitment'] and v['all_four_mature_height']==15 and v['full_fixed_head_native_cold']==8 and v['complete_retained_envelopes_native_checked']==413 and v['native_conservation'] and v['services_and_owned_threads_stopped'],'actual current-source original180 maturity/full8cold/completeenvelopes/heads/conservation gate required')
 require(all(sha(r/path)==expected for path,expected in s['python_source_sha256'].items()) and s['companion_source_commitment']==x['python_source_commitment'],'all192 current companion source bytes required')
 for p,expected in ((e/'regional-paged-fault-async-receipt-v4-20261005-checks.json',sha(r/'tools/regional_paged_fault_driver.py')),(e/'regional-paged-fault-terminal-v1-20261005-checks.json',sha(r/'tools/regional_paged_fault_terminal.py'))):
  c=document(p);require(c['completed'] is True and c['helper_terminal'] is True and c['helper_exit_code']==0 and c['binding_source_sha256']==expected,'current driver/terminal exact finite gate required')
 c=document(e/'regional-paged-fault-async-receipt-v4-20261005-checks.json');require(c['result']['tests']==17 and c['result']['new_complete_native_query_without_global_telemetry_barrier'] is True and c['result']['proof_domain_value_receipt_checks_unchanged'] is True and c['result']['categorical_native_lock_vs_no_evidence_diagnostics_retained'] is True,'source-bound complete Native receipt query without global telemetry barrier and retained outcomes required')
 rows=subprocess.check_output(['ps','-axo','pid=,args='],cwd=r).decode(errors='replace').splitlines()
 require(not any(str(binary)+' --dir '+str(root) in row or 'regional_contact_node.py --dir '+str(root) in row for row in rows),'eligible custody already running')
 held=[]
 try:
  for port in (*range(42000,42012),42100,42101):
   sock=socket.socket();held.append(sock);sock.bind(('127.0.0.1',port))
 finally:
  for sock in held:sock.close()
 bound=bind(project=r,root=root,output=output,checks_path=cp,stage_path=sp,retained_path=ip,binary=binary,python=python,pins=pins,ports=tuple(range(42000,42012)),relays=(42100,42101),deadline=deadline)
 driver=Tracked(r,bound,deadline,account);driver.attempted_owner_signs=0;return driver
result=execute(make,deadline,b/'regional-paged-full-fault-einval-v10-20261007-terminal-private.json')
mesh.atomic(b/'regional-paged-full-fault-einval-v10-20261007-terminal-public.json',result)
print('full-fault-result '+json.dumps(result,sort_keys=True),flush=True)
raise SystemExit(0 if result['completed'] else 1)
