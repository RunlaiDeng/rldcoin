import json,hashlib,sys,time,collections
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v25-private-20261006';start=time.monotonic();deadline=start+20-2.171249;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();edge=json.loads((e/'regional-bft-prepare-edge-v25-v2-20261006-checks.json').read_text());pid=edge['packet_id']
stage=e/'regional-bft-prepare-relay-v25-v2-20261006-stage.json';out=e/'regional-bft-prepare-relay-v25-v2-20261006-checks.json';assert not stage.exists() and not out.exists();stage.write_text(json.dumps(dict(budget_seconds=20,prior_seconds=2.171249,attempts=1,hypothesis='Same source3->destination1 Prepare full packet uses relay2: verify its complete retained route/hops and actual relay2 forwarding selection, distinguishing source refusal from relay admission/next hop. No generic scheduler repair without counterexample.',exit='exactonepacket/firsthash-authguard/original20 cumulative deadline, failedconstructors/signing/transport0'),indent=2)+'\n')
prior=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v25-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v25-stopped-private-inventory-20261006.json';assert sha(seal)==prior['stopped_inventory_sha256'];inv=json.loads(seal.read_text())[str(root)];read={}
def load(p,lines=False):
 data=p.read_bytes();rel=str(p.relative_to(root));h=hashlib.sha256(data).hexdigest();assert h==inv[rel][0];read[rel]=h;return [json.loads(x) for x in data.splitlines()] if lines else json.loads(data)
sys.path.insert(0,str(r/'tools'));import interstellar_mesh as mesh;import interstellar_transfer as wire
trace=load(root/'ordinary-process-controller/finite-trace-events.jsonl',True);first=load(root/'ordinary-process-controller/first-service-events.jsonl',True);copies=[];selection=[]
class ReadArchive:
 summaries=mesh.Node.summaries;archive_entry=mesh.Node.archive_entry;_archive_read=mesh.Node._archive_read;archived=mesh.Node.archived
for holder in range(4):
 p=root/f'mesh/{holder}/mesh-state.json';v=load(p);s=mesh.load_state_storage(p,v['network'],v['node_id']);tr=s['messages'].get(pid);receipt=s['receipts'].get(pid);storage='active'
 if pid in s['archives']:
  a=ReadArchive();a.id=s['node_id'];a.network=s['network'];a.archive_root=root/f'mesh/{holder}/archive';a.state=s;blob=a.archived(pid);tr=blob['transit'];receipt=blob['receipt'];storage='archive'
 if tr:
  body,raw,visited=mesh.transit_check(tr,s['network']);frame,payload=wire.inspect_frame(raw);assert frame['export_id']==next(z['envelope_id'] for z in json.loads((e/'regional-bft-parent13-v25-matrix-20261006-checks.json').read_text())['rows'] if z['body_id']==edge['exact_target']);assert mesh.digest(tr['packet'])==pid
  if receipt:mesh.receipt_check(receipt,s['network']);mesh.receipt_matches(receipt,tr)
  copies.append(dict(holder=holder,storage=storage,visited=visited,packet_routing=tr['routing'],complete_receipt=receipt is not None))
 selected=[z['record'] for z in first if z['slot']==holder and pid in z['record'].get('selected',[])];rows=[z for z in trace if z['slot']==holder and z.get('packet_id')==pid];selection.append(dict(holder=holder,stage_counts=dict(collections.Counter(z['stage'] for z in rows)),selected=[dict(peer=z['peer'],sequence=z['sequence'],position=z['selected'].index(pid),retry_count=len(z['retries'])) for z in selected],events=rows))
assert time.monotonic()<deadline
for rel,h in read.items():assert sha(root/rel)==h
q=dict(completed=True,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(time.monotonic()-start+2.171249,6),copies=copies,selection=selection,stage_sha256=sha(stage),consumed_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,new180=0,new600=0,unique_maturity_cause_proved=False);out.write_text(json.dumps(q,indent=2)+'\n');print(json.dumps({k:v for k,v in q.items() if k!='selection'}));print(json.dumps([dict(holder=z['holder'],stage_counts=z['stage_counts'],selected=z['selected']) for z in selection]))
