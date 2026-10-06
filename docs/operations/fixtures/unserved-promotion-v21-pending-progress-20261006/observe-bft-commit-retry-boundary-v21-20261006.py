import hashlib,json,time
from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';start=time.monotonic();deadline=start+20
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
root=b/'native-bft-four-cli-service-first-service-diag-v21-private-20261006';p=root/'ordinary-process-controller/finite-trace-events.jsonl';s=root/'ordinary-process-controller/finite-trace-journal.json';j=json.loads(s.read_text());assert j['closed'] and j['failed'] and not j['authority'];assert sha(p)==j['journal_sha256']
first=root/'ordinary-process-controller/first-service-events.jsonl';snap=json.loads((root/'ordinary-process-controller/first-service-journal.json').read_text());assert sha(first)==snap['journal_sha256']
old=e/'regional-bft-single-commit-boundary-v21-20261006-checks.json';v=json.loads(old.read_text())['result'];target=v['current_source_pair'][0]['packet_id'];seqs={x['sequence'] for x in v['typed_prepare_prefix']['target_records']}
z=[json.loads(x) for x in first.read_bytes().splitlines()];z=[x['record'] for x in z if x['slot']==2 and x['record']['sequence'] in seqs];assert len(z)==34 and len({x['peer'] for x in z})==1;peer=z[0]['peer']
rows=[json.loads(x) for x in p.read_bytes().splitlines()];attempts={}
for x in rows:
 assert time.monotonic()<deadline
 if x['slot']==2 and x.get('peer')==peer and 'attempt' in x:attempts.setdefault(x['attempt'],[]).append(x)
# Exact selected packet-set and monotonic order association. No inter-thread
# timing or Native authority reconstructed from a cross-process timestamp.
results=[];last=0
for n,prep in enumerate(z):
 ids=set(prep['selected']);candidates=[]
 for attempt,events in sorted(attempts.items()):
  if attempt<=last:continue
  selected={x['packet_id'] for x in events if x['stage']=='outgoing_prepared' and 'packet_id' in x}
  if selected==ids:candidates.append((attempt,events))
 assert candidates,'typed selected packet set has no retained exact outgoing attempt'
 attempt,events=candidates[0];last=attempt
 failure=[x for x in events if x['stage']=='contact_failed'];assert len(failure)<=1
 result=dict(prepare_sequence=prep['sequence'],retry_count=len(prep['retries']),attempt=attempt,prepared_ids=sorted(ids),first_contact_time=min(x['monotonic_seconds'] for x in events),peer_custody_authenticated=any(x['stage']=='peer_custody_authenticated' for x in events),reply_local_custody=any(x['stage']=='reply_local_custody' for x in events),failure_stage=failure[0].get('failure_stage') if failure else None,error_class=failure[0].get('error_class') if failure else None)
 if prep['retries']:
  assert n>0 and set(z[n-1]['selected'])==set(prep['retries']) and not z[n-1]['retries'],'retry differs from immediate completed ordinary preparation'
 results.append(result)
assert len({x['attempt'] for x in results})==34
counts={}
for x in results:
 k=str(x['failure_stage'])+':'+str(x['error_class']);counts[k]=counts.get(k,0)+1
assert sha(p)==j['journal_sha256'] and sha(first)==snap['journal_sha256'] and time.monotonic()<deadline
print(json.dumps(dict(completed=True,budget_seconds=20,attempts=1,duration_seconds=round(time.monotonic()-start,6),first_journal_sha256=snap['journal_sha256'],trace_journal_sha256=j['journal_sha256'],prior_single_commit_checks_sha256=sha(old),target_packet_id=target,source=2,destination=1,joined_exact_selected_sets=results,source_attempt_failure_counts=counts,full4_retries_match_immediate_failed_ordinary_preparation=True,unique_historical_OS_CPU_Native_cause_proved=False,Node_Native_Runtime_socket_key_sign_fixture_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False),sort_keys=True))
