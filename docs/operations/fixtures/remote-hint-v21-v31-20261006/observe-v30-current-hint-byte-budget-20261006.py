from pathlib import Path
import hashlib,json,sys,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v30-private-20261006';start=time.monotonic();prior20=1.437255;deadline=start+20-prior20;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();out=e/'regional-bft-current-hint-byte-budget-v30-20261006-checks.json';assert not out.exists()
prior=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v30-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v30-stopped-private-inventory-20261006.json';assert sha(seal)==prior['stopped_inventory_sha256'] and prior['guardian']['owned_processes_stopped'];files=json.loads(seal.read_text())[str(root)];read={}
def load(p):
 assert time.monotonic()<deadline
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];read[str(p)]=h;return json.loads(raw)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;import interstellar_transfer as wire;import regional_bft_node as rt;from regional_bft_retention import unpack_state
matrix=json.loads((e/'regional-bft-parent14-v30-matrix-20261006-checks.json').read_text());target=next(v for v in matrix['rows'] if v['source']==0 and v['kind']=='Commit');rows=[]
for n in range(4):
 state=unpack_state(load(root/f'runtime/{n}/state.json'));config=load(root/f'component-bft-config-{n}.json');messages=state['messages'];body=next(v for i,v,_,_ in messages.bodies() if i==target['body_id']) if target['body_id'] in messages else next(v for i,v,_,_ in messages.bodies() if v.get('Signed',{}).get('Vote',{}).get('context',{}).get('parent_height')==14);context=body['Signed']['Vote']['context'];keys=tuple(v['key'] for v in config['validators']);full=rt.commit_carriage_frames(messages,context,keys,context['currency'],context['region']);single=[]
 # Inspect the classifier's finite typed predicates and exact original byte
 # bound, not Native authorization. Complete messages remain untouched.
 for ident,body,_,_ in messages.bodies():
  signed=body.get('Signed',{});vote=signed.get('Vote',{});proposal=signed.get('Proposal')
  if proposal is not None:
   eligible=rt.current_empty_proposal_hint(proposal,context,keys)
  else:eligible=vote.get('context')==context and vote.get('phase') in ('Prepare','Commit') and vote.get('approval',{}).get('key') in keys
  if eligible:single.append(dict(body_id=ident,size_bytes=messages.record(ident)['size_bytes'],kind='Proposal' if proposal is not None else vote['phase'],round=proposal['round'] if proposal is not None else vote['round']))
 rows.append(dict(slot=n,frame_hints_returned=len(full),eligible_complete_bytes=sum(v['size_bytes'] for v in single),original_bound=rt.MAX_BROADCAST_HINT_BYTES,qualified_shapes=single,target_companion_retained=target['body_id'] in messages))
for p,h in read.items():assert sha(Path(p))==h
assert time.monotonic()<deadline
report=dict(completed=True,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(time.monotonic()-start+prior20,6),hypothesis='Current exact-context Native-checked frame hint may be all-empty because complete qualified envelopes exceed original4MiB; compare actual returned hints and bounded typed complete bytes without changing capacity or reopening Native.',rows=rows,consumed_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_constructors=0,free_actual_signature_classifier_calls=4,Native_authority=False,unique_failure_cause=False,new180=0,new600=0);out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,sort_keys=True))
