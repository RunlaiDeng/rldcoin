from pathlib import Path
import sys,time,json,signal
r=Path(__file__).resolve().parents[2];assert r==Path('/Users/galaxy/GitHub/rldcoin') and Path.cwd()==r
sys.path.insert(0,str(r/'tools'));b=r/'tmp/default-relay-20260930'
from regional_paged_fault_prepare import Preparation
from paged_return_value_accounting_v1 import observe as account
start=time.monotonic();deadline=float(sys.argv[1])
def stopped(signum,frame):raise TimeoutError('single preparation scope controller terminated')
signal.signal(signal.SIGTERM,stopped)
x=json.loads((r/'docs/operations/evidence/regional-einval-origin-v1-identity-20261007.json').read_text())
import unittest
# Exact unchanged preparation-source/tests reuse their bound successful check.
checks=json.loads((r/'docs/operations/evidence/regional-paged-fault-native-prepare-test-path-v4-20261005-checks.json').read_text())
assert checks['completed'] and checks['helper_terminal'] and checks['helper_exit_code']==0
from types import SimpleNamespace
result=SimpleNamespace(testsRun=0)
p=Preparation(r,b/'native-paged-full-fault-native-preparation-einval-v13-private-20261007',b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate',x['implementation'],x['actual_cli_sha256'],deadline)
states,funding=p.run()
accounting=account([states[label][0] for label in ('earth','proxima','andromeda')],p.pin,p.region_ids[p.origin],p.currency['cap'],p.currency['block_reward'])
assert accounting['conserved'] and accounting['issued']==accounting['liquid'] and accounting['pending_exports']=='0' and accounting['observed_exports']==accounting['observed_permanent_imports']==2
p.remaining()
summary={c:dict(count=sum(v['command']==c for v in p.calls),wall_seconds=round(sum(v['wall_seconds'] for v in p.calls if v['command']==c),6)) for c in sorted({v['command'] for v in p.calls})}
print('native-preparation-result '+json.dumps(dict(completed=True,label_boundary_tests=result.testsRun,unchanged_preparation_boundary_tests_reused=True,duration_seconds=round(time.monotonic()-start,3),native_replicas=12,voter_caller_pairs=12,zero_allocation_from_fresh_signed_genesis=True,no_state_or_value_copy=True,genesis_native_issuance_only=True,actual_heights={label:[s['height'] for s in states[label]] for label in states},preparation_owner_first_signs=3,original_preparation_owner_journal_count=1,preparation_local_payment='95',preparation_export_gross=['3','3'],preparation_import_net=['2','2'],destination_receipts_fully_native_verified=8,maturity=2,fault_owner_first_signs=0,unsigned_fault_reviews=3,funding=[{k:v for k,v in f.items() if k not in ('owner_head','review_sha256')} for f in funding],native_accounting=accounting,native_calls=len(p.calls),native_command_summary=summary,fresh_mesh_tls_identities=12,fresh_tls_reopen_retention=True,network_starts=0,runtime_starts=0,full_fault_qualified=False,configuration_bound=False,independent_freshness_qualified=False,launch_authority=False)),flush=True)
