from pathlib import Path
import sys,os,json,time,signal,threading,traceback,hashlib
from unittest.mock import patch
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'));b=r/'tmp/default-relay-20260930'
import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from test_interstellar_tcp import Fixture,NETWORK
from regional_carriage_worker import Worker
from regional_paged_fault_scope import inventory
start=time.monotonic();deadline=float(sys.argv[1]);root=b/'tcp-einval-six-peers-v1-private-20261007';assert not root.exists();root.mkdir(mode=0o700)
def stop(*_):raise TimeoutError('once50.466611 TCP diagnostic deadline')
signal.signal(signal.SIGTERM,stop)
guard=threading.Lock();found=threading.Event();counts={};einval=[];calls={};patches=[]
def wrapper(original,label):
 def observed(*args,**kw):
  with guard:calls[label]=min(1000000,calls.get(label,0)+1)
  try:return original(*args,**kw)
  except OSError as error:
   with guard:
    key=label+':'+str(error.errno);counts[key]=min(1000000,counts.get(key,0)+1)
    if error.errno==22:
     if len(einval)<8:einval.append(dict(stage=label,errno=error.errno,error_class=type(error).__name__,diagnostic=str(error)[:256],elapsed_seconds=round(time.monotonic()-start,6),trace=[dict(file=Path(frame.filename).name,function=frame.name,line=frame.lineno) for frame in traceback.extract_tb(error.__traceback__)[-8:]]))
     found.set()
   raise
 return observed
for owner,name,label in ((tcp,'client_connect','tcp.client_connect'),(tcp,'send','tcp.send'),(tcp,'receive','tcp.receive'),(tcp,'outgoing','tcp.outgoing'),(mesh,'atomic','mesh.atomic'),(mesh.Node,'__init__','Node.init'),(mesh.Node,'close','Node.close')):
 p=patch.object(owner,name,wrapper(getattr(owner,name),label));p.start();patches.append(p)
f=None;workers=[];frames={};complete=[];source_packet_bytes={};failure=None;body_end=min(deadline-15,start+30)
try:
 names=tuple(region+str(n) for region in ('earth','proxima','andromeda') for n in range(2));edges=list(zip(names,names[1:]+names[:1]));f=Fixture(root,names=names,edges=edges)
 for n,label in enumerate(names):
  target=names[(n+3)%len(names)];raw=wire.make_frame('source-finality',str(n+1)*64,str((n+3)%len(names)+1)*64,format(n+1,'064x'),wire.canonical(dict(ground_fixture=n,ledger_validation='required; no Native proof or authority',padding='0'*309000)))
  with f.node(label) as node:
   ident=node.enqueue(raw,f.ids[target]);source_packet_bytes[ident]=wire.canonical(node.transit(ident)['packet'])
  frames[ident]=dict(source=label,target=target,raw=raw)
 for server in f.servers.values():workers.append(Worker(server,interval=.25))
 turns=0
 while time.monotonic()<body_end and not found.is_set():
  for label in names:
   try:
    with f.node(label) as node:node.tick()
   except BlockingIOError:pass
  turns+=1;found.wait(.1)
finally:
 for worker in workers:worker.close()
 if f is not None:
  for server in list(f.servers.values()):server.close()
  f.servers.clear()
 for p in reversed(patches):p.stop()
assert all(not worker.thread.is_alive() for worker in workers)
if f is not None:
 mesh._verified_transits.clear()
 for ident,row in frames.items():
  with f.node(row['target']) as node:
   if ident in node.receipts():
    transit=node.transit(ident);_,raw,_=mesh.transit_check(transit,NETWORK);mesh.receipt_matches(node.receipts()[ident],transit);assert raw==row['raw'] and wire.canonical(transit['packet'])==source_packet_bytes[ident];complete.append(ident)
assert time.monotonic()<deadline
print('tcp-einval-result '+json.dumps(dict(completed=True,diagnostic_scope_completed=True,original_EINVAL_cause_known=bool(einval),actual_EINVAL_reproduced=bool(einval),einval=einval,ordinary_calls=calls,os_error_counts=counts,body_turns=turns,fresh_mesh_peers=6,real_tls_fixed_identity=True,ordinary_worker_count=len(workers),packet_size_model='309000 ground filler; real complete signed Mesh packet, no Native certificate',complete_exact_destination_receipts_cold=len(complete),transport_targets=6,all_workers_and_servers_stopped=True,Native_Runtime_ledger_key_owner_sign_calls=0,mesh_tls_ground_signatures=True,old_failed_custody_reopened_copied=False,original_TCP60_prior_seconds=9.533389,network_qualification=False,full_fault_qualified=False,scope_limit='No Native CPU/ledger locks or full 12 regional services. Missing EINVAL here leaves original origin unknown; ground receipt/cold is not ledger/maturity.',duration_seconds=round(time.monotonic()-start,6)),sort_keys=True),flush=True)
