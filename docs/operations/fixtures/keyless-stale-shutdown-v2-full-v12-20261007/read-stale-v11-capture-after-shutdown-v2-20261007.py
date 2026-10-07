from pathlib import Path
import hashlib,json,time,sys
from types import SimpleNamespace
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sys.path.insert(0,str(r/'tools'))
from regional_paged_fault_scope import raw,document
from regional_paged_fault_driver import observation_height,Driver,CAPS
from regional_paged_fault_launch import SLOTS
start=time.monotonic();root=b/'native-paged-full-fault-native-preparation-stale-v14-private-20261007';output=b/'native-paged-full-fault-controller-stale-v11-private-20261007';ip=b/'native-paged-full-fault-stale-v11-stopped-private-inventory-20261007.json';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();seal=document(ip);sealsha=sha(ip);pins={}
def read(p):
 base=root if p.is_relative_to(root) else output;expected=seal[str(base)][p.relative_to(base).as_posix()][0];assert sha(p)==expected;pins[p]=expected;return document(p)
o=read(root/'native-prepared-observation.json');regions={label:o['heads'][i*4]['region'] for i,label in enumerate(('earth','proxima','andromeda'))};rows=[]
for i,(label,n) in enumerate(SLOTS):
 p=root/'mesh'/f'{label}-{n}'/'regional-contact-status.json';v=read(p);pin=o['transport_pins'][i];listener=dict(host='127.0.0.1',port=42000+i);phase='offline-catchup' if (label,n)==('earth',0) else 'isolated-missing-leader';log=output/phase/f'service-{label}-{n}.log';base=output;expected=seal[str(base)][log.relative_to(base).as_posix()][0];assert sha(log)==expected;pins[log]=expected;ownpids=set()
 for line in log.read_text().splitlines():
  if line.startswith('{'):
   z=json.loads(line)
   if z.get('format')=='RLD-REGIONAL-CONTACT-NODE-V1':ownpids.add(z['process_id'])
 error=None
 try:
  assert v['region']==regions[label];h=observation_height(v,v['process_id'],o['currency'],pin['tls_cert_sha256'],listener,CAPS[label])
 except BaseException as x:h=None;error=f'{type(x).__name__}: {x}'
 d=SimpleNamespace(root=root,phase='restored-maturity',regions=regions,currency=o['currency'],configs={('restored-maturity',label,n):SimpleNamespace(argv=('not-run','--mesh-listen',f'127.0.0.1:{42000+i}'))},observed=o,stopped_observations={})
 Driver.remember_stopped_observation(d,(label,n),v['process_id'])
 q=output/'keyless-drain'/f'service-{label}-{n}.log';expected=seal[str(output)][q.relative_to(output).as_posix()][0];assert sha(q)==expected;pins[q]=expected
 rows.append(dict(region=label,index=n,final_status_matches_previous_own_pid=v['process_id'] in ownpids,full_free_guard_height=h,full_free_guard_failure=error,exact_actual_capture_function_retains_status=bool(d.stopped_observations),keyless_log_bytes=q.stat().st_size))
assert sha(ip)==sealsha and all(sha(p)==h for p,h in pins.items());duration=time.monotonic()-start;assert duration<20
assert all(row['exact_actual_capture_function_retains_status'] for row in rows)
record=dict(completed=True,budget_seconds=20,attempts=1,duration_seconds=round(duration,6),read_files=len(pins),sealed_bytes_unchanged=True,seal_sha256=sealsha,rows=rows,Native_Runtime_Node_socket_sign_key_fixture_calls=0,Driver_constructor_calls=0,free_capture_function_only=True,driver_source_sha256=sha(r/'tools/regional_paged_fault_driver.py'),qualification='Read-only final stopped bytes cannot reconstruct intermediate stop-time bytes or prove exclusive original cause',full_fault_status='FAIL',whole_goal_completed=False)
with (e/'regional-keyless-stale-shutdown-v2-capture-readonly-20261007.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(record))
