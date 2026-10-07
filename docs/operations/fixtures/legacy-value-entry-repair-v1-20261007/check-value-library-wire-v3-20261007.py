from pathlib import Path
import os,json,time,hashlib,subprocess,signal,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();stagep=e/'legacy-value-library-wire-v3-20261007-stage.json';out=e/'legacy-value-library-wire-v3-20261007-checks.json';log=b/'legacy-value-library-wire-v3-20261007.log';manifestp=e/'legacy-value-library-wire-v3-core-source-20261007.json';assert not any(p.exists() for p in (stagep,out,log,manifestp));old=json.loads((e/'legacy-value-strict-wire-v2-core-source-20261007.json').read_text());prior=json.loads((e/'legacy-value-strict-wire-v2-20261007-checks.json').read_text());assert not prior['completed'] and prior['results'][0]['exit_code']==101;entries=[];digest=hashlib.sha256(b'RLD-EARTH-IMPLEMENTATION-SOURCE\0'+len(old['files']).to_bytes(4,'big'))
for row in old['files']:
 p=row['path'];data=(r/p).read_bytes();h=hashlib.sha256(data).digest();name=p.encode();digest.update(len(name).to_bytes(4,'big')+name+len(data).to_bytes(8,'big')+h);entries.append(dict(path=p,size_bytes=len(data),sha256=h.hex()))
new=dict(format=old['format'],commitment=digest.hexdigest(),file_count=len(entries),total_bytes=sum(v['size_bytes'] for v in entries),files=entries);assert {a['path'] for a,z in zip(old['files'],entries) if a['sha256']!=z['sha256']}=={'crates/rld-value-successor/src/bin/rld-earth-finality.rs'}
with manifestp.open('x') as f:f.write(json.dumps(new,indent=2)+'\n')
commands=[['cargo','clippy','-p','rld-value-successor','--lib','--bins','--locked','--offline','--no-deps','--','-D','warnings'],['cargo','test','-p','rld-value-successor','--lib','--locked','--offline','destination::pow::tests::','--','--test-threads=1']]
protected={str(r/v['path']):v['sha256'] for v in entries};protected[str(Path(__file__))]=sha(Path(__file__));protected[str(manifestp)]=sha(manifestp)
receipt=r/'docs/WHITEPAPER_FREEZE_RECEIPT.json';x=json.loads(receipt.read_text());protected[str(receipt)]=sha(receipt)
for field in ('canonical_markdown','pdf'):protected[str(r.parent/'rldcoin-website'/x[field]['path'])]=x[field]['sha256']
for p in (e/'regional-paged-full-fault-head-v16-20261007-checks.json',e/'regional-paged-full-fault-head-v16-qualified-profile-anchor-20261007.json',e/'legacy-value-strict-wire-v2-20261007-checks.json',b/'legacy-value-finality-lock-reversal-20261007.json',b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate'):protected[str(p)]=sha(p)
def pins():assert all(sha(Path(p))==h for p,h in protected.items())
pins();started=time.monotonic();deadline=started+300;env=dict(os.environ,RUSTUP_TOOLCHAIN='1.98.0');stage=dict(format='RLD-LEGACY-VALUE-LIBRARY-WIRE-DIAGNOSTIC-V3',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=300,attempts=1,scope='Explicit partial library/current6bin strict diagnostic and actual related PoW behavior. Does NOT replace full --lib --tests FAIL or missing5candidateCLI integration obligations.',source_change='Finality lock explicitly truncate(false), same original nontruncating default; reviewed Box and same bool predicate preserved',commands=commands,core_source171_before=old['commitment'],core_source171_after=new['commitment'],protected_sha256=protected,full_strict_runtime_compile_still_failed=True,missing_candidate_cli_count=5,missing_candidate_cli_compile_errors=9,warning_exemptions=0,long_fault_retests=0,old120_and_v2_failures_retained=True,whole_goal_completed=False)
with stagep.open('x') as f:f.write(json.dumps(stage,indent=2)+'\n')
results=[];timed_out=False
with log.open('xb') as stream:
 for command in commands:
  at=time.monotonic();assert at<deadline;p=subprocess.Popen(command,cwd=r,env=env,stdout=stream,stderr=stream,start_new_session=True)
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
report=dict(format=stage['format'],completed=completed,duration_seconds=duration,budget_seconds=300,attempts=1,results=results,budget_exhausted=timed_out,pin_error=pin_error,stage_sha256=sha(stagep),controller_sha256=sha(Path(__file__)),log_sha256=sha(log),core_source171_before=old['commitment'],core_source171_after=new['commitment'],partial_library_and_current_bins_only=True,full_strict_runtime_compile_still_failed=True,full_value_acceptance_completed=False,missing_candidate_cli_count=5,warning_exemptions=0,long_fault_retests=0,old120_and_v2_failures_retained=True,new_Core_or_rebuilt_Native_profile_qualification=False,old_pinned_Native_binary_and_evidence_unchanged=pin_error is None,frozen_md_pdf_receipt_unchanged=pin_error is None,whole_goal_completed=False)
with out.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
print(json.dumps(report));raise SystemExit(0 if completed else 1)
