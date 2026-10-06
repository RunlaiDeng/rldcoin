from pathlib import Path
import json,hashlib,sys,time,cProfile,pstats
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v31-private-20261006';start=time.monotonic();deadline=start+20;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out=e/'regional-bft-warm-state-frame-decode-v31-20261006-checks.json';assert not out.exists();report=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v31-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v31-stopped-private-inventory-20261006.json';assert sha(seal)==report['stopped_inventory_sha256'] and report['guardian']['owned_processes_stopped'];files=json.loads(seal.read_text())[str(root)];p=root/'mesh/1/mesh-state.json';assert sha(p)==files[str(p.relative_to(root))][0];before=sha(p)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh
packed=json.loads(p.read_text());state=mesh.load_state_storage(p,packed['network'],packed['node_id'])
class ReadState:
 validate_state=mesh.Node.validate_state;archive_inventory=mesh.Node.archive_inventory;archive_entry=mesh.Node.archive_entry
node=ReadState();node.state=state;node.network=state['network'];node.id=state['node_id'];node.root=p.parent;node.archive_root=p.parent/'archive'
# Full ordinary checks first; second call observes only exact warm witnesses.
with mesh._verified_transits_lock:mesh._verified_transits.clear()
a=time.monotonic();node.validate_state();cold=time.monotonic()-a
prof=cProfile.Profile();a=time.monotonic();prof.enable();node.validate_state();prof.disable();warm=time.monotonic()-a;stats=pstats.Stats(prof);rows=[]
for (file,line,name),(cc,nc,tt,ct,callers) in stats.stats.items():
 if name in ('b64decode','a2b_base64','transit_check','validate_state','commitment') or 'a2b_base64' in name:rows.append(dict(file=Path(file).name,name=name,calls=nc,self_seconds=round(tt,6),inclusive_seconds=round(ct,6)))
assert sha(p)==before and time.monotonic()<deadline
result=dict(completed=True,budget_seconds=20,attempts=1,hypothesis='Measure exact warm Node state validation contribution from Base64 frame output that validate_state discards; original cold miss and exact-byte/hash/domain checks remain mandatory.',duration_seconds=round(time.monotonic()-start,6),cold_state_check_seconds=round(cold,6),warm_state_check_seconds=round(warm,6),profile=rows,active_transits=len(state['messages']),active_frame_text_bytes=sum(len(v['packet']['body']['frame']) for v in state['messages'].values()),archive_entries=len(state['archives']),exact_state_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_constructors=0,free_source_validator_calls=2,latest_Nativecold_maturity_conservation_qualified=False,fullfault_qualified=False,new180=0,new600=0);out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
