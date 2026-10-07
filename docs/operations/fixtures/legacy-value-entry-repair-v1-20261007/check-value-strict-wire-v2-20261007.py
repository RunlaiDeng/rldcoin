from pathlib import Path
import os,sys,json,time,hashlib,subprocess,signal,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();proposal=b/'value-strict-proposed-source-v2-20261007';plan=json.loads((proposal/'PLAN.json').read_text());stagep=e/'legacy-value-strict-wire-v2-20261007-stage.json';out=e/'legacy-value-strict-wire-v2-20261007-checks.json';log=b/'legacy-value-strict-wire-v2-20261007.log';manifestp=e/'legacy-value-strict-wire-v2-core-source-20261007.json';assert not any(p.exists() for p in (stagep,out,log,manifestp))
qualified=e/'regional-paged-full-fault-head-v16-20261007-checks.json';q=json.loads(qualified.read_text());assert q['completed'] and q['helper_terminal'] and q['helper_exit_code']==0 and q['duration_seconds']<=600
ps=subprocess.check_output(['ps','-axo','pid=,args='],cwd=r).decode();root=str(b/'native-paged-full-fault-native-preparation-head-v19-private-20261007');assert not any(root in row and ('regional_contact_node.py --dir' in row or 'rld-regional-ledger-candidate --dir' in row) for row in ps.splitlines())
for p,h in plan['source_sha256'].items():assert sha(r/p)==h and sha(proposal/p)==plan['candidate_source_sha256'][p]
anchor=json.loads((e/'regional-paged-full-fault-head-v16-qualified-profile-anchor-20261007.json').read_text());old=json.loads((b/'whitepaper-issuance-repaired-source-manifest-20261004.json').read_text());assert old['commitment']==anchor['core_source171']
for p in plan['source_sha256']:(r/p).write_bytes((proposal/p).read_bytes())
paths=[row['path'] for row in old['files']];digest=hashlib.sha256(b'RLD-EARTH-IMPLEMENTATION-SOURCE\0'+len(paths).to_bytes(4,'big'));entries=[]
for p in paths:
 data=(r/p).read_bytes();h=hashlib.sha256(data).digest();name=p.encode();digest.update(len(name).to_bytes(4,'big')+name+len(data).to_bytes(8,'big')+h);entries.append(dict(path=p,size_bytes=len(data),sha256=h.hex()))
new=dict(format=old['format'],commitment=digest.hexdigest(),file_count=len(entries),total_bytes=sum(v['size_bytes'] for v in entries),files=entries)
assert new['commitment']!=old['commitment'] and {p['path'] for p in old['files'] if next(z for z in entries if z['path']==p['path'])['sha256']!=p['sha256']}==set(plan['source_sha256'])
with manifestp.open('x') as f:f.write(json.dumps(new,indent=2)+'\n')
receipt=r/'docs/WHITEPAPER_FREEZE_RECEIPT.json';freeze=json.loads(receipt.read_text());protected={str(r/v['path']):v['sha256'] for v in entries};protected[str(qualified)]=sha(qualified);protected[str(receipt)]=sha(receipt);protected[str(Path(__file__))]=sha(Path(__file__));protected[str(proposal/'PLAN.json')]=sha(proposal/'PLAN.json');protected[str(manifestp)]=sha(manifestp);binary=b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate';protected[str(binary)]=anchor['actual_cli_sha256']
for field in ('canonical_markdown','pdf'):protected[str(r.parent/'rldcoin-website'/freeze[field]['path'])]=freeze[field]['sha256']
def pins():assert all(sha(Path(p))==h for p,h in protected.items()),'source/freeze/qualified-profile/binary changed'
pins();started=time.monotonic();deadline=started+300;env=dict(os.environ,RUSTUP_TOOLCHAIN='1.98.0');stage=dict(format='RLD-LEGACY-VALUE-STRICT-WIRE-STAGE-V2',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=300,attempts=1,repair='Box finality certificate reduces enum allocation; same bool predicate; complete original nonBox enum wire bytes, typed decode and original genuine finality/journal behavior mandatory',commands=plan['commands'],source_before=plan['source_sha256'],source_after=plan['candidate_source_sha256'],core_source171_before=old['commitment'],core_source171_after=new['commitment'],pinned_Rust='1.98.0',network_budget=0,source_bound_old_Native_profile_retained=anchor,protected_sha256=protected,old120_019_failed_record_remains=True,warning_exemptions=0,long_fault_retests=0,whole_goal_completed=False)
with stagep.open('x') as f:f.write(json.dumps(stage,indent=2)+'\n')
results=[];timed_out=False
with log.open('xb') as stream:
 for command in plan['commands']:
  at=time.monotonic();assert at<deadline
  p=subprocess.Popen(command,cwd=r,env=env,stdout=stream,stderr=stream,start_new_session=True)
  try:code=p.wait(timeout=max(.001,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:
   timed_out=True;os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
   code=p.returncode
  results.append(dict(command=command,exit_code=code,duration_seconds=round(time.monotonic()-at,6),terminal=p.poll() is not None))
  if code!=0 or timed_out:break
pin_error=None
try:pins()
except BaseException as ex:pin_error=str(ex)
duration=round(time.monotonic()-started,6);completed=not timed_out and pin_error is None and len(results)==2 and all(v['exit_code']==0 and v['terminal'] for v in results) and duration<=300
report=dict(format='RLD-LEGACY-VALUE-STRICT-WIRE-CHECKS-V2',completed=completed,duration_seconds=duration,budget_seconds=300,attempts=1,budget_exhausted=timed_out,pin_error=pin_error,results=results,source_before=stage['source_before'],source_after=stage['source_after'],core_source171_before=old['commitment'],core_source171_after=new['commitment'],stage_sha256=sha(stagep),controller_sha256=sha(Path(__file__)),log_sha256=sha(log),old120_019_failed_record_remains=True,warning_exemptions=0,long_fault_retests=0,old_qualified_Native_profile_binary_and_evidence_unmodified=pin_error is None,new_Core_or_rebuilt_Native_profile_qualification=False,legacy_library_strict_and_related_pow_only=completed,all_targets_or_entire_value_product_qualified=False,frozen_md_pdf_receipt_unchanged=pin_error is None,whole_goal_completed=False)
with out.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
print(json.dumps(report));raise SystemExit(0 if completed else 1)
