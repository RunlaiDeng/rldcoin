from pathlib import Path
import hashlib,json,sys,time,cProfile,pstats
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v32-private-20261006';start=time.monotonic();deadline=start+20;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out=e/'regional-bft-complete-mesh-cold-v32-20261006-checks.json';assert not out.exists()
checks=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v32-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v32-stopped-private-inventory-20261006.json';assert not checks['completed'] and checks['guardian']['owned_processes_stopped'] and sha(seal)==checks['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];p=root/'mesh/0/mesh-state.json';seen={}
def retained(path):
 assert time.monotonic()<deadline;rel=str(path.relative_to(root));assert sha(path)==files[rel][0];seen[rel]=files[rel][0]
retained(p);sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh
prof=cProfile.Profile();prof.enable();a=time.monotonic();packed=json.loads(p.read_text());state=mesh.load_state_storage(p,packed['network'],packed['node_id']);loaded=time.monotonic()-a
class ReadState:
 validate_state=mesh.Node.validate_state;archive_inventory=mesh.Node.archive_inventory;archive_entry=mesh.Node.archive_entry;archived=mesh.Node.archived
 def _archive_read(self,name):
  path=self.archive_root/name;raw=mesh.Node._archive_read(self,name);rel=str(path.relative_to(root));assert hashlib.sha256(raw).hexdigest()==files[rel][0];seen[rel]=files[rel][0];assert time.monotonic()<deadline;return raw
node=ReadState();node.state=state;node.network=state['network'];node.id=state['node_id'];node.root=p.parent;node.archive_root=p.parent/'archive'
with mesh._verified_transits_lock:mesh._verified_transits.clear()
with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
a=time.monotonic();node.validate_state();validated=time.monotonic()-a
a=time.monotonic()
for ident in state['archives']:node.archived(ident)
archived=time.monotonic()-a;prof.disable();stats=pstats.Stats(prof);rows=[]
for (file,line,name),(cc,nc,tt,ct,callers) in stats.stats.items():
 if name in ('load_state_storage','decode','_unpack','validate_state','archived','archive_entry','transit_check','_transit_check','_packet_frame_check','decode_json','canonical','verify','_commitment','packet_body_bytes','b64decode','_archive_read'):
  rows.append(dict(file=Path(file).name,name=name,calls=nc,self_seconds=round(tt,6),inclusive_seconds=round(ct,6)))
for rel,h in seen.items():assert sha(root/rel)==h
assert time.monotonic()<deadline
result=dict(completed=True,budget_seconds=20,attempts=1,duration_seconds=round(time.monotonic()-start,6),hypothesis='Measure one complete cold Mesh state plus every retained archive using exact failed V32 bytes and pure validators; no old Node/Native/Runtime constructors or ledger calls. Distinguish Mesh cost from unrecorded Native batch timing, without granting stopped ledger qualification.',exact_failed_scope_checks_sha256=sha(e/'regional-bft-four-cli-service-first-service-diag-v32-20261006-checks.json'),sealed_inventory_sha256=sha(seal),source_sha256={p:sha(r/p) for p in ('tools/interstellar_mesh.py','tools/interstellar_frame_digest.py','tools/interstellar_active_state.py')},loaded_seconds=round(loaded,6),complete_cold_state_seconds=round(validated,6),all_archives_seconds=round(archived,6),profile=rows,active_transits=len(state['messages']),complete_archive_entries=len(state['archives']),exact_read_files=len(seen),exact_read_bytes_unchanged=True,cold_native_maturity_conservation_qualified=False,Native_Node_Runtime_socket_key_sign_fixture_constructors=0,Native_calls=0,new180=0,new600=0,whole_goal_completed=False)
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='profile'},sort_keys=True))
