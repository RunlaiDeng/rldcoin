#!/usr/bin/env python3
"""Actual Runtime same-round persistence checks in three fresh no-value fixtures.

Controller-carried setup votes only; no ordinary transport, full-cycle, process
interruption, power-loss or independent custody qualification.
"""
import argparse
from pathlib import Path
import hashlib,json,sys,time
from unittest.mock import patch
p=argparse.ArgumentParser(description=__doc__)
for name in ('source','manifest','binary','root','report'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();s=a.source.resolve();mp=a.manifest.resolve();binary=a.binary.resolve();root=a.root.resolve();report=a.report.resolve()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();m=json.loads(mp.read_text())
assert m['fixture_only'] and not m['live_rld'] and not root.exists() and not report.exists()
assert hashlib.sha256(json.dumps(m['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==m['source_set_sha256']
def guard():
 assert sum(p.is_file() for p in s.rglob('*'))==m['file_count']
 for row in m['files']:assert sha(s/row['path'])==row['sha256'],row['path']
guard();sys.path.insert(0,str(s/'tools'))
import interstellar_mesh as mesh
import regional_bft_node
from regional_bft_network_campaign import Campaign
from regional_bft_node import Runtime
from regional_contact_node import Native
from regional_contact_campaign import public
assert Path(regional_bft_node.__file__).resolve()==s/'tools/regional_bft_node.py'
root.mkdir(mode=0o700);rows=[];start=time.monotonic()
for boundary in ('normal','commit-pending-publication-failure','commit-outbox-publication-failure'):
 c=Campaign(binary,root/boundary);runtime=None;interrupted_records=None
 assert c.implementation==m['native_implementation']
 try:
  native=Native(binary,c.node('earth',1),public(1),c.currency)
  context=native.call('bft-context')['context'];candidate=c.cli('earth',1,'bft-candidate','--miner',public(10),'--commands',c.file('commands',[]));proposal=c.sign('earth',0,{'Propose':{'round':0,'snapshot':candidate,'timeout':None}})['message']['Proposal'];votes=[c.sign('earth',n,{'Prepare':proposal})['message'] for n in (0,2,3)]
  runtime=Runtime(native,mesh.load(c.root/'mesh-config-1.json',65536),c.root/'bft-config-1.json');before=runtime.signer_status()['records'];assert before==0
  for message in [{'Proposal':proposal},*votes]:runtime.retain(runtime.envelope({'Signed':message}),sync=False)
  if boundary=='normal':observed=runtime.tick()
  elif boundary=='commit-pending-publication-failure':
   atomic=mesh.atomic
   def fail_pending(path,value):
    if path==runtime.head_path and value.get('pending') is not None and 'Commit' in value['pending']:raise OSError('diagnostic failed commit pending publication')
    return atomic(path,value)
   with patch.object(mesh,'atomic',side_effect=fail_pending):
    try:runtime.tick();raise AssertionError('injected failure did not occur')
    except OSError:pass
   status=runtime.signer_status();interrupted_records=status['records'];assert status['records']==1 and status['state']['prepared'] is not None and status['state']['committed'] is None and runtime.head['pending'] is None
   runtime.close();runtime=Runtime(native,mesh.load(c.root/'mesh-config-1.json',65536),c.root/'bft-config-1.json');observed=runtime.tick()
  else:
   retain=runtime.retain
   def fail_outbox(envelope,*args,**kwargs):
    signed=envelope['body'].get('Signed',{});vote=signed.get('Vote',{})
    if vote.get('phase')=='Commit':raise OSError('diagnostic failed committed outbox retention')
    return retain(envelope,*args,**kwargs)
   with patch.object(runtime,'retain',side_effect=fail_outbox):
    try:runtime.tick();raise AssertionError('injected failure did not occur')
    except OSError:pass
   status=runtime.signer_status();interrupted_records=status['records'];assert status['records']==2 and status['state']['committed'] is not None and runtime.head['pending'] is None and runtime.head['outbox']['Vote']['phase']=='Commit'
   retained_head=runtime.head['head'];runtime.close();runtime=Runtime(native,mesh.load(c.root/'mesh-config-1.json',65536),c.root/'bft-config-1.json');assert runtime.head['head']==retained_head and runtime.head['outbox'] is None;observed=runtime.tick()
  status=runtime.signer_status();assert status['records']==2 and runtime.head['head']==status['head'] and runtime.head['pending'] is None and runtime.head['outbox'] is None
  own=[v['envelope']['body']['Signed']['Vote'] for v in runtime.state['messages'].values() if 'Signed' in v['envelope']['body'] and 'Vote' in v['envelope']['body']['Signed'] and v['envelope']['body']['Signed']['Vote']['approval']['key']==runtime.key]
  assert sorted(v['phase'] for v in own)==['Commit','Prepare'] and all(v['round']==0 for v in own);assert observed['round']==0 and native.call('status')['height']==0
  runtime.close();runtime=Runtime(native,mesh.load(c.root/'mesh-config-1.json',65536),c.root/'bft-config-1.json');assert runtime.signer_status()['records']==2 and runtime.head['pending'] is None and runtime.head['outbox'] is None
  rows.append(dict(boundary=boundary,passed=True,native_records_at_injected_failure=interrupted_records,reopen_did_not_repeat_retained_signature=True,native_own_records=2,own_retained_phases=['Prepare','Commit'],same_round=0,separate_caller_head_exact=True,pending_and_outbox_clear=True,cold_runtime_reopen_checked=True,native_height=0,controller_carried_setup_votes=True,ordinary_transport_delivery_qualified=False))
 finally:
  if runtime:runtime.close()
  c.cleanup()
guard()
result=dict(format='RLD-BOUNDED-PHASE-RUNTIME-CUSTODY-CHECK-V1',completed=True,source_set_sha256=m['source_set_sha256'],runtime_source_sha256=sha(s/'tools/regional_bft_node.py'),binary_sha256=sha(binary),producer_sha256=sha(Path(__file__)),source_unchanged=True,fresh_private_diagnostic_fixtures=3,cases=rows,duration_seconds=round(time.monotonic()-start,3),fixture_only=True,live_rld=False,same_host=True,full_cycle_completed=False,process_sigkill_or_power_loss_qualified=False,independent_custody_qualified=False)
report.parent.mkdir(parents=True,exist_ok=True);report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(completed=True,cases=3,duration_seconds=result['duration_seconds'])),flush=True)
