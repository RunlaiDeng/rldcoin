from pathlib import Path
import hashlib,json,sys,time,cProfile,pstats
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v29-private-20261006';start=time.monotonic();deadline=start+20;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sp=e/'regional-bft-archive-cold-boundary-v29-20261006-stage.json';out=e/'regional-bft-archive-cold-boundary-v29-20261006-checks.json';assert not sp.exists() and not out.exists()
sp.write_text(json.dumps(dict(budget_seconds=20,attempts=1,hypothesis='V29 reached stopped Native receipt maturity but original180 expired in complete Mesh archive cold read. Measure one exact largest retained archive operation and its canonical serialization contribution, without Node/Native/Runtime constructors or reopening failed custody. Only a measured redundant exact serialization may select a repair.',exit='first source/sealed-byte/auth guard failure, one full read and exact serialization model or original20 deadline; no longscope/rerun/sign/transport/fixture',reader_sha256=sha(Path(__file__))),indent=2)+'\n')
prior=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v29-20261006-checks.json').read_text());assert not prior['completed'] and prior['helper_terminal'] and prior['guardian']['owned_processes_stopped'] and prior['pin_error'] is None
seal=b/'native-bft-four-cli-service-first-service-diag-v29-stopped-private-inventory-20261006.json';assert sha(seal)==prior['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];read={}
def raw(p):
 assert time.monotonic()<deadline
 h=sha(p);assert h==files[str(p.relative_to(root))][0];read[str(p)]=h;return p.read_bytes()
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;import interstellar_transfer as wire;import interstellar_frame_digest as fd
p=root/'mesh/0/mesh-state.json';packed=wire.decode_json(raw(p));state=mesh.load_state_storage(p,packed['network'],packed['node_id']);ident=max(state['archives'],key=lambda i:state['archives'][i]['body']['expanded_size_bytes'])
class ReadArchive:
 archive_entry=mesh.Node.archive_entry;archived=mesh.Node.archived
 def _archive_read(self,name):return raw(self.archive_root/name)
a=ReadArchive();a.id=state['node_id'];a.network=state['network'];a.state=state;a.archive_root=root/'mesh/0/archive'
with mesh._verified_transits_lock:mesh._verified_transits.clear()
prof=cProfile.Profile();t=time.monotonic();prof.enable();blob=a.archived(ident);prof.disable();seconds=time.monotonic()-t
stats=pstats.Stats(prof);canonical=[]
for (file,line,name),(cc,nc,tt,ct,callers) in stats.stats.items():
 if name in ('canonical','dumps','decode_json','inspect_frame','transit_check','encode_basestring_ascii','archived') or 'encode_basestring_ascii' in name:canonical.append(dict(file=Path(file).name,name=name,calls=nc,self_seconds=round(tt,6),inclusive_seconds=round(ct,6)))
# Exact existing segmented encoder on the same large frame, without persisting an object witness.
path=('transit','packet','body','frame');frame=blob['transit']['packet']['body']['frame'];assert frame.isascii() and len(frame)<=wire.MAX_FRAME*2 and not frame.encode().translate(None,fd.SAFE_ASCII)
left,right=fd._split(blob,path);t=time.monotonic();encoded=wire.canonical(blob);full_seconds=time.monotonic()-t;t=time.monotonic();h=hashlib.sha256();h.update(left);h.update(frame.encode('ascii'));h.update(right);digest=h.hexdigest();split_seconds=time.monotonic()-t
assert digest==hashlib.sha256(encoded).hexdigest() and len(left)+len(frame)+len(right)==len(encoded)
log=b/'regional-bft-four-cli-service-first-service-diag-v29-20261006.log';assert sha(log)==prior['log_sha256'];milestones=[]
for line in log.read_text().splitlines():
 if line.startswith('service-step '):
  v=json.loads(line[len('service-step '):])
  if v['kind']=='four-cli-cleanly-stopped-and-actual-maturity-confirmed' or v['kind']=='ordinary-progress' and v['heights']==[15]*4:milestones.append(v)
assert [v['kind'] for v in milestones][-1]=='four-cli-cleanly-stopped-and-actual-maturity-confirmed'
for p,h in read.items():assert sha(Path(p))==h
assert time.monotonic()<deadline
result=dict(completed=True,duration_seconds=round(time.monotonic()-start,6),budget_seconds=20,attempts=1,stage_sha256=sha(sp),stopped_inventory_sha256=sha(seal),V29_still_FAIL=True,maturity_milestones=milestones,archive_index_records_node0=len(state['archives']),selected_packet_id=ident,expanded_bytes=len(encoded),one_full_authenticated_archive_seconds=round(seconds,6),operation_profile=canonical,exact_segmented_blob_sha_size=True,canonical_full_seconds=round(full_seconds,6),segmented_blob_seconds=round(split_seconds,6),segment_result_not_authentication=True,consumed_sealed_files=len(read),consumed_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,full_all8_cold_or_conservation_qualified=False,new180=0,new600=0)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
