from pathlib import Path
import sys,os,json,time,signal,hashlib,fcntl
from contextlib import nullcontext
from types import SimpleNamespace
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'));b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence'
from regional_paged_fault_prepare import Preparation
from regional_paged_fault_scope import inventory
from regional_contact_node import Native,NativeRefusal,Service
import interstellar_mesh as mesh
import interstellar_transfer as wire
start=time.monotonic();deadline=float(sys.argv[1]);x=json.loads((e/'regional-contact-apply-defer-v1-identity-20261007.json').read_text());root=b/'native-contact-apply-lock-v1-private-20261007';binary=b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate'
def stop(*_):raise TimeoutError('one60 actual contact-apply discriminator deadline')
signal.signal(signal.SIGTERM,stop)
p=Preparation(r,root,binary,x['implementation'],x['actual_cli_sha256'],deadline)
p.region('earth');p.region('proxima')
for _ in range(3):p.certify('earth',[])
signed=p.sign_preparation('proxima');frame=p.call(p.regions['earth'][0]['ledger'],'contact-export','--export',signed['intent_id']);raw=wire.canonical(frame);header,_=wire.inspect_frame(raw);assert header['kind']=='finalized-import';p.file('complete-original-frame',frame)
configs={};ids={}
for label in ('earth','proxima'):
 path=root/('mesh-'+label);identity=mesh.initialize(path,p.pin,p.region_ids[p.origin if label=='earth' else label],label);ids[label]=identity['node_id'];configs[label]=dict(format=mesh.VERSION,state=str(path),network=p.pin,contacts=[])
for label,peer in (('earth','proxima'),('proxima','earth')):
 configs[label]['contacts']=[dict(peer=ids[peer],inbox=str(root/('inbox-'+label)),outbox=str(root/('inbox-'+peer)))]
with mesh.Node(configs['proxima']) as node:initial=node.exchange(ids['earth'])
with mesh.Node(configs['earth']) as node:
 node.receive(initial,ids['proxima']);packet=node.enqueue(raw,ids['proxima']);exchange=node.prepare_exchange(ids['proxima'])
with mesh.Node(configs['proxima']) as node:
 node.receive(exchange,ids['earth']);assert packet in node.receipts();_,retained,_=mesh.transit_check(node.transit(packet),p.pin);mesh.receipt_matches(node.receipts()[packet],node.transit(packet));assert retained==raw
row=p.regions['proxima'][0];native=Native(binary,row['ledger'],p.authority,p.pin);before=inventory(row['ledger']);head=native.call('history-head');owner_before=inventory(root/'preparation-owner');heads_before={str(item['caller']):item['caller'].read_bytes() for rows in p.regions.values() for item in rows}
service=Service.__new__(Service);service.native=native;service.region=p.region_ids['proxima'];service.root=root/'service-observation';service.root.mkdir(mode=0o700);service.path=service.root/'progress.json';service.progress=dict(cursor=0);service.contact_trace=None;service.bft=None;service.bft_seen=set();service.bft_individual_retry=False;service.receive_after=dict(novel=None,background=None);service.miner=None;service.carriage=None;service.tcp=SimpleNamespace(tick=lambda:dict(errors=[]));service.selection_node=lambda:mesh.Node(configs['proxima'])
# Fault injection owns this fresh OS lock only during the actual apply call.
# Native.call/apply and Service.tick remain the production implementation.
actual_apply=native.apply;actual_refusals=[];apply_frames=[]
def apply_with_first_lock(data,miner):
 apply_frames.append(hashlib.sha256(data).hexdigest())
 if len(apply_frames)==1:
  descriptor=os.open(row['ledger']/'LOCK',os.O_RDWR|os.O_NOFOLLOW)
  try:
   fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
   try:actual_apply(data,miner)
   except NativeRefusal as error:
    actual_refusals.append(dict(command=error.command,exit_code=error.exit_code,diagnostic=error.diagnostic));raise
   raise AssertionError('actual Native accepted held exclusive ledger lock')
  finally:os.close(descriptor)
 return actual_apply(data,miner)
native.apply=apply_with_first_lock
first=service.tick();assert len(actual_refusals)==1;failure=actual_refusals[0];assert failure['command']=='contact-apply' and type(failure['exit_code']) is int and failure['exit_code']==1
assert first['rejected']==[] and first['applied']==[] and len(first['deferred'])==1 and first['deferred'][0]['packet_id']==packet and first['deferred'][0]['ledger_acceptance_known'] is False and first['deferred'][0]['signing_authority'] is False and service.bft_seen==set()
assert inventory(row['ledger'])==before and native.call('history-head')==head;assert inventory(root/'preparation-owner')==owner_before;assert all(Path(path).read_bytes()==value for path,value in heads_before.items());p.file('first-tick-locked',first)
second=service.tick();assert second['rejected']==second['deferred']==[] and len(second['applied'])==1;answer=second['applied'][0]['native'];assert answer['evidence_verified'] is True and answer['import_accepted'] is False;assert len(apply_frames)==2 and apply_frames[0]==apply_frames[1]==hashlib.sha256(raw).hexdigest();assert service.bft_seen==set();p.file('second-tick-released',second)
status=native.call('status');assert status['height']==0 and not status['ledger']['coins'] and not status['ledger']['imports'];contact=native.call('contact-status');assert len(contact['contacts'])==1 and contact['contacts'][0]['evidence_verified'] is True and contact['contacts'][0]['import_accepted'] is False
before_cold=inventory(root);cold_count=0
for rows in p.regions.values():
 for item in rows:
  observed=p.call(item['ledger'],'history-head');checked=p.call(item['ledger'],'history-check','--expected-head',observed['history_head']);assert checked['history_head']==observed['history_head'];bound=p.call(item['ledger'],'bft-status','--signer-dir',item['signer']);caller=mesh.load(item['caller'],65536);assert bound['head']==caller['head'] and bound['binding']==caller['binding'];cold_count+=1
assert inventory(root)==before_cold;assert all(Path(path).read_bytes()==value for path,value in heads_before.items());assert inventory(root/'preparation-owner')==owner_before
mesh._verified_transits.clear()
with mesh.Node(configs['proxima']) as node:
 _,cold_raw,_=mesh.transit_check(node.transit(packet),p.pin);mesh.receipt_matches(node.receipts()[packet],node.transit(packet));assert cold_raw==raw
p.remaining()
print('contact-apply-native-result '+json.dumps(dict(completed=True,duration_seconds=round(time.monotonic()-start,6),actual_typed_refusal=failure,real_signed_finalized_import=True,full_frame_sha256=hashlib.sha256(raw).hexdigest(),packet_id=packet,actual_native_apply_calls=2,production_service_ticks=2,fresh_native_replicas=8,fixed_head_native_cold=cold_count,cold_bytes_unchanged=True,caller_owner_heads_unchanged=True,held_lock_mutations=0,release_same_complete_frame_evidence_verified=True,native_import_accepted=False,destination_height=0,destination_spendable_coins=0,mesh_complete_packet_receipt_and_cleared_witness_cold=True,TCP_socket_starts=0,TCP_tick_is_noop_model=True,Service_constructor_starts=0,controller_preparation_certificates=4,preparation_owner_signs=1,old_custody_reopened_or_copied=False,native_maturity_qualified=False,full_fault_qualified=False,whole_goal_completed=False),sort_keys=True),flush=True)
