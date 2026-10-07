from pathlib import Path
import os,json,time,hashlib,subprocess,signal,datetime
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';e=r/'docs/operations/evidence';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
name='core-hybrid-renewal-archive-related-v18-20261007';stagep=e/(name+'-stage.json');out=e/(name+'-checks.json');log=b/(name+'.log');manifestp=e/(name+'-core-source.json');assert not any(p.exists() for p in (stagep,out,log,manifestp))
def capture():
 paths=[]
 def walk(p):
  assert not p.is_symlink()
  if p.is_dir():
   for child in p.iterdir():
    n=child.name
    if not(n.startswith('.') or n in ('target','node_modules','__pycache__') or n.endswith('.pyc')):walk(child)
  else:assert p.is_file();paths.append(p)
 for n in ('Cargo.toml','Cargo.lock','rust-toolchain.toml','crates','vectors','spec','docs/spec'):walk(r/n)
 paths.sort(key=lambda p:p.relative_to(r).as_posix());assert len(paths)<=8192
 d=hashlib.sha256(b'RLD-EARTH-IMPLEMENTATION-SOURCE\0'+len(paths).to_bytes(4,'big'));entries=[]
 for p in paths:
  v=p.read_bytes();assert len(v)<=128*1024*1024;n=p.relative_to(r).as_posix();raw=n.encode();h=hashlib.sha256(v).digest();d.update(len(raw).to_bytes(4,'big')+raw+len(v).to_bytes(8,'big')+h);entries.append(dict(path=n,size_bytes=len(v),sha256=h.hex()))
 assert sum(v['size_bytes'] for v in entries)<=512*1024*1024
 return dict(format='RLD-EARTH-IMPLEMENTATION-SOURCE',commitment=d.hexdigest(),file_count=len(entries),total_bytes=sum(v['size_bytes'] for v in entries),files=entries)
manifest=capture();manifestp.write_text(json.dumps(manifest,indent=2)+'\n');protected={str(r/v['path']):v['sha256'] for v in manifest['files']};protected[str(Path(__file__))]=sha(Path(__file__));receipt=r/'docs/WHITEPAPER_FREEZE_RECEIPT.json';x=json.loads(receipt.read_text());protected[str(receipt)]=sha(receipt)
for f in ('canonical_markdown','pdf'):protected[str(r.parent/'rldcoin-website'/x[f]['path'])]=x[f]['sha256']
for p in (e/'regional-paged-full-fault-head-v16-20261007-checks.json',e/'regional-paged-full-fault-head-v16-qualified-profile-anchor-20261007.json',e/'legacy-value-strict-wire-v2-20261007-checks.json',e/'legacy-value-library-wire-v3-20261007-checks.json',b/'native-loop-observation-build-v2-private-20261006/rld-regional-ledger-candidate'):protected[str(p)]=sha(p)
protected[str(b/'legacy-value-runtime-v7-failed-private-inventory-20261007.json')]=sha(b/'legacy-value-runtime-v7-failed-private-inventory-20261007.json')
protected[str(e/'legacy-value-candidate-entries-v7-20261007-checks.json')]=sha(e/'legacy-value-candidate-entries-v7-20261007-checks.json')
protected[str(b/'legacy-value-full-v12-budget-failed-private-inventory-20261007.json')]=sha(b/'legacy-value-full-v12-budget-failed-private-inventory-20261007.json')
protected[str(e/'legacy-value-candidate-full-value-v12-20261007-checks.json')]=sha(e/'legacy-value-candidate-full-value-v12-20261007-checks.json')
protected[str(e/'core-era-authority-baseline-v6-20261007-checks.json')]=sha(e/'core-era-authority-baseline-v6-20261007-checks.json')
protected[str(e/'core-era-authority-related-v7-20261007-checks.json')]=sha(e/'core-era-authority-related-v7-20261007-checks.json')
protected[str(e/'core-era-integrated-v8-20261007-checks.json')]=sha(e/'core-era-integrated-v8-20261007-checks.json')
protected[str(e/'core-era-checkpoint-baseline-v10-20261007-checks.json')]=sha(e/'core-era-checkpoint-baseline-v10-20261007-checks.json')
for suffix in ('checks.json','stage.json','core-source.json'):
 for version in ('v6','v7'):protected[str(e/('core-hybrid-related-'+version+'-20261007-'+suffix))]=sha(e/('core-hybrid-related-'+version+'-20261007-'+suffix))
for p in (e/'core-hybrid-integrated-v8-20261007-checks.json',e/'core-hybrid-reference-v1-qualified-profile-20261007.json',b/'core-hybrid-integrated-v8-20261007-qualified-test-binary'):protected[str(p)]=sha(p)
for p in (e/'core-hybrid-quorum-related-v10-20261007-checks.json', e/'core-hybrid-integrated-v9-20261007-checks.json', e/'pq-hybrid-tls-composition-v4-20261007-checks.json', b/'core-hybrid-integrated-v9-20261007-qualified-test-binary'):
 protected[str(p)]=sha(p)
def pins():assert capture()==manifest and all(sha(Path(p))==h for p,h in protected.items())
commands=[['cargo', 'fmt', '--all', '--check'], ['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--offline', '--no-deps', '--', '-D', 'warnings'], ['cargo', 'test', '-p', 'rld-core', '--lib', '--locked', '--offline', '--target-dir', 'target/value-tests-rust198-opt1', '--config', 'profile.test.opt-level=1', '--config', 'profile.test.debug-assertions=true', '--config', 'profile.test.overflow-checks=true', 'joint_renewal_archive', '--', '--test-threads=1', '--nocapture']]
stage=dict(format='RLD-CORE-HYBRID-RENEWAL-ARCHIVE-RELATED-V18',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),budget_seconds=120,attempts=1,hypothesis='Finite verification-only ordered complete renewal archive from independent initial caller anchor and per-step observations to separately retained exact latest transition. Allentries checked<=64/each32768/total2097152 before crypto, no Native/transport/ledger cap increase. Two actual real RAM-only consecutive4signature renewals; valid standalone prefix remains valid but refused as latest when expectedhead is final2. Missing tail/prefix/reordered/repeated/stale expectedhead/bad innerPQ/unknown broken revoked oldpolicy and empty/mismatched/resource oversized inputs refuse, no initialanchor mutation or durable state installation. Once120 relevant3 behavioraltests+wholeworkspace alltarget strict; all old historic FAIL/PASS origins kept, no long Native/value/TLS repeats.',exit='First static/compile/test/pin failure or original120 deadline stops and retains FAIL; no changed threshold, warning exemption, old fixture reuse or unchanged retry.',commands=commands,core_source=manifest['commitment'],core_file_count=manifest['file_count'],protected_sha256=protected,old_failures_retained=True,whole_goal_completed=False)
pins();stagep.write_text(json.dumps(stage,indent=2)+'\n');started=time.monotonic();deadline=started+120;results=[];timedout=False
with log.open('xb') as stream:
 for command in commands:
  at=time.monotonic();p=subprocess.Popen(command,cwd=r,env=dict(os.environ,RUSTUP_TOOLCHAIN='1.98.0'),stdout=stream,stderr=stream,start_new_session=True)
  try:code=p.wait(timeout=max(.001,deadline-time.monotonic()))
  except subprocess.TimeoutExpired:
   timedout=True;os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
   code=p.returncode
  results.append(dict(command=command,exit_code=code,duration_seconds=round(time.monotonic()-at,6),terminal=p.poll() is not None))
  if code!=0 or timedout:break
error=None
try:pins()
except BaseException as ex:error=repr(ex)
duration=round(time.monotonic()-started,6);completed=not timedout and error is None and duration<=120 and all(v['exit_code']==0 for v in results)
report=dict(format=stage['format'],completed=completed,duration_seconds=duration,budget_seconds=120,attempts=1,results=results,budget_exhausted=timedout,pin_error=error,source_manifest_sha256=sha(manifestp),stage_sha256=sha(stagep),controller_sha256=sha(Path(__file__)),log_sha256=sha(log),core_source=manifest['commitment'],core_file_count=manifest['file_count'],full_core_suite_passed=False,related_three_tests_passed=completed,expected_baseline_regression_failure=False,whole_era_qualification=False,warning_exemptions=0,long_fault_retests=0,new_Native_profile_qualification=False,old_failures_retained=True,whole_goal_completed=False)
out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));raise SystemExit(0 if completed else 1)
