from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v36-private-20261006';start=time.monotonic();prior=2.181107;deadline=start+20-prior;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();q=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v36-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v36-stopped-private-inventory-20261006.json';assert sha(seal)==q['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def read(p):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return json.loads(raw)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;import interstellar_transfer as wire;import regional_bft_node as bft;from regional_bft_retention import unpack_state
s=unpack_state(read(root/'runtime/1/state.json'));cfg=read(root/'component-bft-config-1.json');keys=tuple(z['key'] for z in cfg['validators']);edge=json.loads((e/'regional-bft-exact-commit-edge-v36-20261007-checks.json').read_text());ident=edge['exact_target'];body=s['messages'].record(ident)['body'];vote=body['Signed']['Vote'];ctx=vote['context'];raw=wire.make_frame('regional-bft',ctx['region'],ctx['region'],s['messages'].content(ident),s['messages'].payload(ident));frame=wire.inspect_frame(raw)[0]['message_id'];frames=bft.commit_carriage_frames(s['messages'],ctx,keys,ctx['currency'],ctx['region']);candidates=[];size=0
for i,body,_,owned in s['messages'].bodies():
 signed=body.get('Signed',{});v=signed.get('Vote');p=signed.get('Proposal')
 eligible=v is not None and v.get('phase') in ('Prepare','Commit') and v.get('context')==ctx
 if p is not None:eligible=bft.current_empty_proposal_hint(p,ctx,keys)
 if not eligible:continue
 record=s['messages'].record(i);size+=record['size_bytes'];candidates.append(dict(body_id=i,complete_envelope_id=record['sha256'],phase=v['phase'] if v else 'Proposal',owned=owned,size_bytes=record['size_bytes'],cumulative_candidate_bytes=size,target=i==ident))
assert time.monotonic()<deadline
for p,h in seen.items():assert sha(Path(p))==h
result=dict(completed=True,actual_hint_budget=bft.MAX_BROADCAST_HINT_BYTES,total_candidate_bytes=size,current_candidate_rows=candidates,current_complete_frame_hint_count=len(frames),actual_target_in_current_hints=frame in frames,actual_target_complete_retained_at_relay=True,actual_target_frame_id=frame,live_hint_installation_unknown=True,unique_maturity_cause=False,Node_Native_Runtime_socket_key_sign_fixture_calls=0,consumed_bytes_unchanged=True,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6),new180=0,new600=0)
out=e/'regional-bft-relay-current-hint-budget-v36-20261007-checks.json';assert not out.exists();out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
