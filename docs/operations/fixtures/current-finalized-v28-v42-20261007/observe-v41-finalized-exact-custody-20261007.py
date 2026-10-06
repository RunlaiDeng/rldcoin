from pathlib import Path
import json,hashlib,time
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';root=b/'native-bft-four-cli-service-first-service-diag-v41-private-20261006';start=time.monotonic();prior=2.550175;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();term=json.loads((e/'regional-bft-four-cli-service-first-service-diag-v41-20261006-checks.json').read_text());seal=b/'native-bft-four-cli-service-first-service-diag-v41-stopped-private-inventory-20261006.json';assert sha(seal)==term['stopped_inventory_sha256'];files=json.loads(seal.read_text())[str(root)];seen={}
def load(p,lines=False):
 raw=p.read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==files[str(p.relative_to(root))][0];seen[str(p)]=h;return [json.loads(z) for z in raw.splitlines()] if lines else json.loads(raw)
q=json.loads((e/'regional-bft-current-finalized-frontier-v41-20261007-checks.json').read_text());trace=load(root/'ordinary-process-controller/finite-trace-events.jsonl',True);node0=load(root/'mesh/0/mesh-state.json')['node_id'];rows=[]
for entry in q['rows']:
 for target in entry['source_enqueued_targets']:
  if target['destination_peer']!=node0:continue
  pid=target['packet_id'];events=[z for z in trace if z.get('packet_id')==pid];prepared=[z for z in events if z['slot']==entry['source'] and z['stage']=='outgoing_prepared'];attempts=[]
  for p in prepared:
   same=[z for z in trace if z['slot']==entry['source'] and z.get('peer')==p['peer'] and z.get('attempt')==p['attempt']];attempts.append(dict(attempt=p['attempt'],peer=p['peer'],prepared_time=p['monotonic_seconds'],request_sent=any(z['stage']=='request_sent' for z in same),peer_custody=any(z['stage']=='peer_custody_authenticated' for z in same),local_reply_custody=any(z['stage']=='reply_local_custody' for z in same),failures=[dict(stage=z['failure_stage'],error=z['error_class']) for z in same if z['stage']=='contact_failed']))
  rows.append(dict(source=entry['source'],packet_id=pid,enqueued_time=target['time'],attempts=attempts,all_retained_packet_custody_events=[z for z in events if z['stage'] in ('local_transport_custody','deferred_input_queued','deferred_input_not_queued','deferred_local_custody','destination_receipt_retained')]))
assert time.monotonic()-start+prior<20
for p,h in seen.items():assert sha(Path(p))==h
out=e/'regional-bft-finalized-exact-custody-v41-20261007-checks.json';assert not out.exists();result=dict(completed=True,rows=rows,duration_seconds=round(time.monotonic()-start,6),combined_original20_seconds=round(prior+time.monotonic()-start,6),sealed_bytes_unchanged=True,Node_Native_Runtime_socket_key_sign_fixture_calls=0,unique_maturity_cause=False,reader_sha256=sha(Path(__file__)),new180=0,new600=0);out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
