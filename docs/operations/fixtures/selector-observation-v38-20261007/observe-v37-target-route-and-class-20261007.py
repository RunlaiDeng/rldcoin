from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v37-private-20261006';start=time.monotonic();prior=1.940232;deadline=start+20-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
out=e/'regional-bft-target-route-and-class-v37-20261007-checks.json';stage=e/'regional-bft-target-route-and-class-v37-20261007-stage.json';assert not out.exists() and not stage.exists();stage.write_text(json.dumps(dict(hypothesis='Exact retained source2 Prepare has no later hop attempts. Test saved signed route/hop/receipt eligibility and final recent-history placement; compare actual selected current frames. Saved state cannot prove missing live ordering.',budget_seconds=20,prior_seconds=prior,attempts=1,exit='first sealed hash/signature/route guard or original20 deadline; no constructors/key/sign/socket/custody mutation'),indent=2)+'\n')
q=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v37-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v37-stopped-private-inventory-20261006.json';assert sha(seal)==q['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def load(p,lines=False):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return [json.loads(z) for z in raw.splitlines()] if lines else json.loads(raw)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as m
edge=json.loads((e/'regional-bft-exact-prepare-edge-v37-20261007-checks.json').read_text());pid=edge['packet_id'];peer=edge['actual_first_hop'];p=root/'mesh/2/mesh-state.json';raw=load(p);state=m.load_state_storage(p,raw['network'],raw['node_id']);config=load(root/'component-mesh-config-2.json')
# Ordinary free validation and pure original route method; no Node constructor.
class ReadRoute:
 route=m.Node.route
view=ReadRoute();view.state=state;view.id=state['node_id'];view.contacts={c['peer']:c for c in config['contacts']}
for advert in state['adverts'].values():m.advert_check(advert,state['network'])
transit=state['messages'][pid];packet,frame,visited=m.transit_check(transit,state['network']);route=view.route(packet['destination'],visited[:-1],first_hop=peer)
rows=[];records=load(root/'ordinary-process-controller/first-service-events.jsonl',True)
for v in records:
 z=v['record']
 if v['slot']!=2 or z['peer']!=peer or z['sequence'] not in (74,80,87,97,105,112):continue
 candidates=[]
 for ident in z['priority']['matching_packet_ids']:
  t=state['messages'].get(ident)
  if t is None:continue
  packet2,_,visited2=m.transit_check(t,state['network']);path=view.route(packet2['destination'],visited2[:-1],first_hop=peer)
  candidates.append(dict(packet_id=ident,destination=packet2['destination'],saved_route=path,saved_receipt=ident in state['receipts'],saved_recent=ident in state['recent_transits'],hop_count=len(t['hops']),hop_limit=packet2['hop_limit'],original_bytes=len(m.evidence.canonical(t))))
 rows.append(dict(sequence=z['sequence'],actual_selected=z['selected'],matching_current_retained=candidates))
assert time.monotonic()<deadline
for path,h in seen.items():assert sha(Path(path))==h
result=dict(completed=True,target_saved_route=route,target_saved_receipted=pid in state['receipts'],target_saved_recent=pid in state['recent_transits'],target_hops=len(transit['hops']),target_hop_limit=packet['hop_limit'],target_retained_bytes=len(m.evidence.canonical(transit)),original_wire_bound=m.MAX_BATCH,actual_rows=rows,historical_order_or_hint_at_selector_not_inferred=True,Node_Native_Runtime_key_sign_socket_fixture_calls=0,consumed_bytes_unchanged=True,stage_sha256=sha(stage),reader_sha256=sha(Path(__file__)),duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6))
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
